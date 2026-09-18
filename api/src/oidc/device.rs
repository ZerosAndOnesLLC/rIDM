//! Device authorization endpoint (RFC 8628 §3.1): `POST /t/{slug}/device_authorization`.
//! The device polls `/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`
//! (see `token.rs`) while the user approves on the `/device/` page.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};

use crate::error::{OAuthError, OAuthErrorCode};
use crate::middleware::{TenantCtx, client_ip_addr};
use crate::models::grants;
use crate::oidc::authorize::RawParams;
use crate::oidc::client_auth;
use crate::services::device_codes::{self, DeviceAuthorization};
use crate::services::scopes;
use crate::state::AppState;

pub fn router() -> axum::Router<AppState> {
    axum::Router::new().route(
        "/t/{slug}/device_authorization",
        axum::routing::post(device_authorization),
    )
}

pub async fn device_authorization(
    State(state): State<AppState>,
    tenant: TenantCtx,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let ip = client_ip_addr(&state, &headers, Some(peer));
    let mut res = match handle(&state, &tenant, &headers, &body, ip).await {
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
    body: &str,
    ip: Option<IpAddr>,
) -> Result<DeviceAuthorization, OAuthError> {
    let params = RawParams::parse(body);
    let one = |n: &str| params.one(n).map_err(OAuthError::invalid_request);
    let endpoint = format!("{}/device_authorization", tenant.issuer(state));
    let (client, _) =
        client_auth::authenticate(state, tenant, headers, &params, &endpoint, ip).await?;
    if !client.allows_grant(grants::DEVICE_CODE) {
        return Err(OAuthError::new(
            OAuthErrorCode::UnauthorizedClient,
            "client may not use the device authorization grant",
        ));
    }
    let checked = scopes::validate_request(
        state,
        tenant.id(),
        &client,
        scopes::parse_scope_param(one("scope")?.unwrap_or_default()),
        &[],
        true,
    )
    .await?;
    let mut audiences: Vec<String> = vec![];
    for r in params.many("resource") {
        let r = r.trim();
        if r.is_empty()
            || url::Url::parse(r)
                .map(|u| u.fragment().is_some())
                .unwrap_or(true)
        {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidTarget,
                format!("invalid resource `{r}`"),
            ));
        }
        let mut tx = crate::db::tenant_tx(&state.db, tenant.id()).await?;
        let known =
            crate::repos::resource_servers::find_by_identifier(&mut *tx, tenant.id(), r).await?;
        tx.commit().await?;
        if known.is_none() {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidTarget,
                format!("unknown resource `{r}`"),
            ));
        }
        if !client.allowed_audiences.is_empty() && !client.allowed_audiences.iter().any(|a| a == r)
        {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidTarget,
                format!("resource `{r}` is not allowed for this client"),
            ));
        }
        if !audiences.iter().any(|a| a == r) {
            audiences.push(r.to_string());
        }
    }
    // A scope bound to a resource server targets it too.
    let audiences = scopes::with_bound_audiences(
        audiences,
        &client.allowed_audiences,
        checked.bound_audiences,
    );
    Ok(device_codes::issue(state, tenant, &client, checked.scopes, audiences).await?)
}
