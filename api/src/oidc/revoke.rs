//! Token revocation (RFC 7009): `POST /t/{slug}/revoke`. Refresh tokens are
//! revoked with their family; JWT access tokens are denylisted by `jti` until
//! they expire. Unknown tokens still return 200.

use std::net::{IpAddr, SocketAddr};

use axum::Router;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use chrono::{DateTime, Utc};

use crate::error::OAuthError;
use crate::middleware::{TenantCtx, client_ip_addr};
use crate::oidc::authorize::RawParams;
use crate::oidc::client_auth;
use crate::services::tokens::{self, VerifyOptions};
use crate::services::{denylist, refresh_tokens};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/t/{slug}/revoke", post(revoke))
}

async fn revoke(
    State(state): State<AppState>,
    tenant: TenantCtx,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let ip = client_ip_addr(&state, &headers, Some(peer));
    let params = RawParams::parse(&body);
    let mut res = match handle(&state, &tenant, &headers, &params, ip).await {
        Ok(()) => StatusCode::OK.into_response(),
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
) -> Result<(), OAuthError> {
    let token_endpoint = format!("{}/token", tenant.issuer(state));
    let (client, _) =
        client_auth::authenticate(state, tenant, headers, params, &token_endpoint, ip).await?;
    let token = params
        .one("token")
        .map_err(OAuthError::invalid_request)?
        .ok_or_else(|| OAuthError::invalid_request("token is required"))?;

    if token.starts_with("rt_") {
        refresh_tokens::revoke(state, tenant.id(), &client.client_id, token).await?;
        return Ok(());
    }
    // Access token: only the client it was issued to may revoke it.
    if let Ok(claims) = tokens::verify(
        state,
        &tenant.tenant,
        token,
        &VerifyOptions {
            allow_expired: true,
            check_denylist: false,
            ..Default::default()
        },
    )
    .await
        && claims["azp"].as_str() == Some(client.client_id.as_str())
        && let (Some(jti), Some(exp)) = (claims["jti"].as_str(), claims["exp"].as_i64())
        && let Some(exp) = DateTime::<Utc>::from_timestamp(exp, 0)
    {
        denylist::deny(state, tenant.id(), jti, exp).await?;
    }
    Ok(())
}
