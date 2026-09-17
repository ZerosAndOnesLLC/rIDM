//! Custom domains: a request whose host is a tenant's `custom_domain` is
//! served as if it had come in under `/t/{slug}`.
//!
//! The router's fallback does the work, because a `Router::layer` runs after
//! routing: a path no route matched on the primary host is looked up by host,
//! rewritten to `/t/{slug}{path}` and dispatched through the routed
//! application again (layers included), so every tenant endpoint — discovery,
//! JWKS, `/authorize`, `/token`, the flow API — answers on the tenant's own
//! host with its issuer set to that host. Other hosts fall through to the
//! ordinary 404. The host is `X-Forwarded-Host` from a trusted proxy, else
//! `Host`, else the request target's authority (HTTP/2), lower-cased.

use std::net::SocketAddr;

use axum::Router;
use axum::extract::{ConnectInfo, Request};
use axum::http::{HeaderMap, Uri, header};
use axum::response::{IntoResponse, Response};
use tower::ServiceExt as _;

use crate::middleware::tenant::resolve_tenant_by_host;
use crate::state::AppState;

/// The host the client asked for, lower-cased, without surrounding whitespace.
pub fn request_host(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    peer: Option<SocketAddr>,
) -> Option<String> {
    let trusted = peer.is_some_and(|p| {
        state
            .config
            .trusted_proxies
            .iter()
            .any(|net| net.contains(&p.ip()))
    });
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_ascii_lowercase)
    };
    if trusted && let Some(h) = header("x-forwarded-host") {
        return Some(h);
    }
    header(header::HOST.as_str())
        .or_else(|| uri.authority().map(|a| a.as_str().to_ascii_lowercase()))
}

/// Fallback handler: serve a custom-domain request through `routed`.
pub async fn dispatch(state: AppState, routed: Router, req: Request) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let Some(host) = request_host(&state, req.headers(), req.uri(), peer) else {
        return routed.oneshot(req).await.into_response();
    };
    // The primary hosts never map to a tenant; skip the lookup.
    if state.config.primary_hosts().contains(&host) {
        return routed.oneshot(req).await.into_response();
    }
    let tenant = match resolve_tenant_by_host(&state, &host).await {
        Ok(Some(t)) => t,
        Ok(None) => return routed.oneshot(req).await.into_response(),
        Err(err) => return err.into_response(),
    };
    let (mut parts, body) = req.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let rewritten = format!("/t/{}{path_and_query}", tenant.slug);
    match rewritten.parse::<Uri>() {
        Ok(uri) => parts.uri = uri,
        Err(_) => {
            return routed
                .oneshot(Request::from_parts(parts, body))
                .await
                .into_response();
        }
    }
    routed
        .oneshot(Request::from_parts(parts, body))
        .await
        .into_response()
}
