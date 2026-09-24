//! Pushed authorization requests (RFC 9126): `POST /t/{slug}/par`.
//! The client authenticates, pushes the full authorization request, and
//! receives a one-time `request_uri` for `/authorize`.

use std::sync::Arc;

use std::net::{IpAddr, SocketAddr};

use axum::Router;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use redis::AsyncCommands as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cache::keys;
use crate::error::{AppError, OAuthError, OAuthErrorCode};
use crate::middleware::{TenantCtx, client_ip_addr};
use crate::models::Client;
use crate::oidc::authorize::{self, Failure, RawParams};
use crate::oidc::form::FormParams;
use crate::oidc::mtls::{ClientCert, ClientCertificate};
use crate::oidc::{client_auth, jar};
use crate::services::login_flows::AuthRequest;
use crate::state::AppState;

pub const URN_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";
pub const PAR_TTL_SECS: u64 = 60;

pub fn router() -> Router<AppState> {
    Router::new().route("/t/{slug}/par", post(par))
}

#[derive(Debug, Serialize, Deserialize)]
struct Stored {
    client_id: Uuid,
    request: AuthRequest,
}

async fn par(
    State(state): State<AppState>,
    tenant: TenantCtx,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    cert: ClientCertificate,
    headers: HeaderMap,
    FormParams(params): FormParams,
) -> Response {
    let ip = client_ip_addr(&state, &headers, Some(peer));
    let mut res = match handle(&state, &tenant, &headers, &params, ip, cert.get()).await {
        Ok((request_uri, expires_in)) => (
            StatusCode::CREATED,
            axum::Json(serde_json::json!({"request_uri": request_uri, "expires_in": expires_in})),
        )
            .into_response(),
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
) -> Result<(String, u64), OAuthError> {
    let token_endpoint = tenant.token_endpoint(state);
    let (client, _) =
        client_auth::authenticate(state, tenant, headers, params, &token_endpoint, ip, cert)
            .await?;
    if params.one("request_uri").ok().flatten().is_some() {
        return Err(OAuthError::invalid_request(
            "request_uri is not allowed in a pushed request",
        ));
    }
    let merged = match params.one("request").map_err(OAuthError::invalid_request)? {
        Some(jwt) => jar::merge(state, tenant, &client, params, jwt)
            .await
            .map_err(|f| jar::as_oauth(&f))?,
        None => RawParams(params.0.clone()),
    };
    let (redirect, mode, state_param) =
        authorize::resolve_redirect(&client, &merged).map_err(|f| match f {
            Failure::Page(_, d) => OAuthError::invalid_request(d),
            Failure::Redirect(e) => e,
            Failure::Internal(_) => OAuthError::server_error(),
        })?;
    let validated = authorize::validate(
        state,
        tenant,
        &client,
        &merged,
        &redirect,
        mode,
        state_param,
    )
    .await
    .map_err(|f| match f {
        Failure::Page(_, d) => OAuthError::invalid_request(d),
        Failure::Redirect(e) => e,
        Failure::Internal(_) => OAuthError::server_error(),
    })?;

    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let id = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes);
    let stored = Stored {
        client_id: client.id,
        request: validated.request,
    };
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(
            keys::par_request(tenant.id(), &id),
            serde_json::to_string(&stored).map_err(AppError::from)?,
            PAR_TTL_SECS,
        )
        .await
        .map_err(AppError::from)?;
    Ok((format!("{URN_PREFIX}{id}"), PAR_TTL_SECS))
}

/// Consume a pushed request for `/authorize`. The `client_id` parameter must
/// match the client that pushed it.
pub async fn take(
    state: &AppState,
    tenant: &TenantCtx,
    params: &RawParams,
    request_uri: &str,
) -> Result<(Arc<Client>, AuthRequest), Failure> {
    let page = |d: &str| Failure::Page("invalid_request", d.to_string());
    let client_id = params
        .one("client_id")
        .map_err(|d| Failure::Page("invalid_request", d))?
        .ok_or_else(|| page("client_id is required"))?;
    let id = request_uri.strip_prefix(URN_PREFIX).unwrap_or_default();
    if id.is_empty() || id.len() > 64 {
        return Err(page("invalid request_uri"));
    }
    let mut conn = state.redis.get().await.map_err(Failure::Internal)?;
    let raw: Option<String> = redis::cmd("GETDEL")
        .arg(keys::par_request(tenant.id(), id))
        .query_async(&mut conn)
        .await
        .map_err(|e| Failure::Internal(AppError::from(e)))?;
    let stored: Stored = raw
        .and_then(|r| serde_json::from_str(&r).ok())
        .ok_or_else(|| {
            Failure::Redirect(OAuthError::new(
                OAuthErrorCode::InvalidRequestUri,
                "request_uri is unknown, expired, or already used",
            ))
        })?;
    let client = crate::services::clients::find_by_client_id(state, tenant.id(), client_id)
        .await?
        .filter(|c| c.id == stored.client_id)
        .ok_or_else(|| {
            Failure::Page(
                "invalid_request",
                "client_id does not match the pushed request".into(),
            )
        })?;
    if !client.is_active() {
        return Err(Failure::Page(
            "unauthorized_client",
            "client is disabled".into(),
        ));
    }
    Ok((client, stored.request))
}
