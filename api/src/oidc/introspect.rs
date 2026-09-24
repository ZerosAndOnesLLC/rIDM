//! Token introspection (RFC 7662): `POST /t/{slug}/introspect`.
//! Requires an authenticated (confidential) client. Inactive, unknown, or
//! foreign tokens all yield `{"active": false}`. Access tokens may be JWTs
//! or opaque `at_` tokens; for the latter this is the only way a resource
//! server learns what they stand for.

use std::net::{IpAddr, SocketAddr};

use axum::Router;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use chrono::Utc;
use serde_json::{Value, json};

use crate::error::{OAuthError, OAuthErrorCode};
use crate::middleware::{TenantCtx, client_ip_addr};
use crate::oidc::authorize::RawParams;
use crate::oidc::client_auth;
use crate::oidc::form::FormParams;
use crate::oidc::mtls::{ClientCert, ClientCertificate};
use crate::services::tokens::{self, VerifyOptions};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/t/{slug}/introspect", post(introspect))
}

async fn introspect(
    State(state): State<AppState>,
    tenant: TenantCtx,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    cert: ClientCertificate,
    headers: HeaderMap,
    FormParams(params): FormParams,
) -> Response {
    let ip = client_ip_addr(&state, &headers, Some(peer));
    let mut res = match handle(&state, &tenant, &headers, &params, ip, cert.get()).await {
        Ok(v) => axum::Json(v).into_response(),
        Err(e) => e.into_response(),
    };
    crate::middleware::security_headers::set_no_store(res.headers_mut());
    res
}

async fn handle(
    state: &AppState,
    tenant: &TenantCtx,
    headers: &HeaderMap,
    params: &RawParams,
    ip: Option<IpAddr>,
    cert: Option<&ClientCert>,
) -> Result<Value, OAuthError> {
    let token_endpoint = tenant.token_endpoint(state);
    let (client, method) =
        client_auth::authenticate(state, tenant, headers, params, &token_endpoint, ip, cert)
            .await?;
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
        let rec = crate::services::refresh_tokens::find(state, tenant.id(), token).await?;
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

    // Access token, JWT or opaque: a JWT's signature must verify, an opaque
    // token must still have its entry; expiry decides `active`.
    let claims = match tokens::verify_access(
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
        // A certificate-bound token is still a bearer token by scheme (RFC 8705 §3).
        "token_type": if claims.get("cnf").and_then(|c| c.get("jkt")).is_some() { "DPoP" } else { "Bearer" },
    });
    // RFC 9068 names JWT access tokens; an opaque one has no JOSE type.
    if !crate::services::opaque_tokens::looks_like(token) {
        out["typ"] = json!("at+jwt");
    }
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
        "org_id",
        "roles",
        "permissions",
        "cnf",
        "act",
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
