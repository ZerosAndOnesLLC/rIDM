//! Token introspection (RFC 7662): `POST /t/{slug}/introspect`.
//! Requires an authenticated (confidential) client. Inactive, unknown, or
//! foreign tokens all yield `{"active": false}`.

use std::net::{IpAddr, SocketAddr};

use axum::Router;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::error::{OAuthError, OAuthErrorCode};
use crate::middleware::{TenantCtx, client_ip_addr};
use crate::oidc::authorize::RawParams;
use crate::oidc::client_auth;
use crate::services::tokens::{self, VerifyOptions};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/t/{slug}/introspect", post(introspect))
}

async fn introspect(
    State(state): State<AppState>,
    tenant: TenantCtx,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let ip = client_ip_addr(&state, &headers, Some(peer));
    let params = RawParams::parse(&body);
    let mut res = match handle(&state, &tenant, &headers, &params, ip).await {
        Ok(v) => axum::Json(v).into_response(),
        Err(e) => e.into_response(),
    };
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

async fn handle(
    state: &AppState,
    tenant: &TenantCtx,
    headers: &HeaderMap,
    params: &RawParams,
    ip: Option<IpAddr>,
) -> Result<Value, OAuthError> {
    let token_endpoint = format!("{}/token", tenant.issuer(state));
    let (client, method) =
        client_auth::authenticate(state, tenant, headers, params, &token_endpoint, ip).await?;
    if method == crate::models::TokenEndpointAuthMethod::None {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidClient,
            "introspection requires a confidential client",
        ));
    }
    let token = params
        .one("token")
        .map_err(OAuthError::invalid_request)?
        .ok_or_else(|| OAuthError::invalid_request("token is required"))?;
    let inactive = json!({"active": false});

    if token.starts_with("rt_") {
        let hash = Sha256::digest(token.as_bytes()).to_vec();
        let mut tx = crate::db::tenant_tx(&state.db, tenant.id()).await?;
        let rec =
            crate::repos::refresh_tokens::find_by_hash_for_update(&mut *tx, tenant.id(), &hash)
                .await?;
        tx.commit().await?;
        let Some(rec) = rec else { return Ok(inactive) };
        if rec.client_id != client.client_id || !rec.is_usable(Utc::now()) {
            return Ok(inactive);
        }
        let mut out = json!({
            "active": true,
            "token_type": "refresh_token",
            "client_id": rec.client_id,
            "scope": rec.scopes.join(" "),
            "iat": rec.created_at.timestamp(),
            "exp": rec.expires_at.timestamp(),
            "iss": tenant.issuer(state),
        });
        if let Some(u) = rec.user_id {
            out["sub"] = json!(u);
        }
        return Ok(out);
    }

    if crate::services::personal_access_tokens::looks_like_pat(token) {
        let rec = crate::services::personal_access_tokens::find(state, tenant.id(), token).await?;
        let Some(rec) = rec else { return Ok(inactive) };
        if !rec.is_usable(Utc::now()) {
            return Ok(inactive);
        }
        let user = match crate::services::users::get(state, tenant.id(), rec.user_id).await {
            Ok(u) if u.status == crate::models::UserStatus::Active && !u.is_locked_now() => u,
            _ => return Ok(inactive),
        };
        let mut out = json!({
            "active": true,
            "token_type": "personal_access_token",
            "sub": rec.user_id,
            "username": user.username,
            "scope": rec.scopes.join(" "),
            "iat": rec.created_at.timestamp(),
            "iss": tenant.issuer(state),
        });
        if let Some(e) = rec.expires_at {
            out["exp"] = json!(e.timestamp());
        }
        return Ok(out);
    }

    // JWT access token: signature must verify; expiry decides `active`.
    let claims = match tokens::verify(
        state,
        &tenant.tenant,
        token,
        &VerifyOptions {
            allow_expired: true,
            leeway_secs: 0,
            ..Default::default()
        },
    )
    .await
    {
        Ok(c) => c,
        Err(_) => return Ok(inactive),
    };
    let exp = claims["exp"].as_i64().unwrap_or_default();
    if exp <= Utc::now().timestamp() {
        return Ok(inactive);
    }
    // Only the client the token was issued to, or an audience of it, may learn its details.
    let azp = claims["azp"].as_str().unwrap_or_default();
    let aud_matches = match &claims["aud"] {
        Value::String(a) => a == &client.client_id || client.allowed_audiences.contains(a),
        Value::Array(list) => list.iter().any(|a| {
            a == &client.client_id
                || a.as_str()
                    .is_some_and(|s| client.allowed_audiences.contains(&s.to_string()))
        }),
        _ => false,
    };
    if azp != client.client_id && !aud_matches {
        return Ok(inactive);
    }
    let mut out = json!({
        "active": true,
        "token_type": "Bearer",
        "typ": "at+jwt",
    });
    for k in [
        "scope",
        "client_id",
        "sub",
        "aud",
        "iss",
        "exp",
        "iat",
        "nbf",
        "jti",
        "sid",
        "tid",
        "roles",
        "permissions",
    ] {
        if let Some(v) = claims.get(k) {
            out[k] = v.clone();
        }
    }
    if let Some(sub) = claims["sub"].as_str()
        && let Ok(uid) = uuid::Uuid::parse_str(sub)
        && let Ok(user) = crate::services::users::get(state, tenant.id(), uid).await
    {
        out["username"] = json!(user.username);
    }
    Ok(out)
}
