//! Custom domains: a request whose host is a tenant's `custom_domain` is
//! served as if it had come in under `/t/{slug}`, and a custom domain serves
//! that tenant only.
//!
//! [`dispatch`] sees every request before routing. On the primary hosts (and
//! any host no tenant claims) it passes the request on untouched. On a
//! tenant's custom domain it rewrites the path to `/t/{slug}{path}` and
//! dispatches it through the routed application (layers included), so every
//! tenant endpoint — discovery, JWKS, `/authorize`, `/token`, the flow and
//! account APIs, branding — answers on the tenant's own host with its issuer
//! set to that host. Only a few paths go through unchanged:
//!
//! * the health probes (`/healthz`, `/readyz`), which a load balancer asks
//!   whatever host it uses;
//! * the host-wide `/.well-known/webfinger` and `/.well-known/security.txt`;
//! * the tenant's own `/t/{slug}/…` and `/scim/v2/{slug}/…` paths, for a UI
//!   or provisioning client that names the tenant explicitly.
//!
//! Everything else lands under the prefix and so reaches nothing but the
//! tenant's routes: another tenant's `/t/{other}/…` or `/scim/v2/{other}/…`,
//! the admin API, `/metrics`, `/docs` and `/openapi.json` all answer 404 on a
//! custom domain. The host is `X-Forwarded-Host` from a trusted proxy, else
//! `Host`, else the request target's authority (HTTP/2), lower-cased.

use std::net::SocketAddr;

use axum::Router;
use axum::extract::{ConnectInfo, Request};
use axum::http::{HeaderMap, StatusCode, Uri, header};
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

/// Paths a custom domain serves as they are, without the tenant prefix.
const HOST_WIDE: &[&str] = &[
    "/healthz",
    "/readyz",
    "/.well-known/webfinger",
    "/.well-known/security.txt",
];

/// Does `path` stay as it is on the custom domain of the tenant `slug`?
fn passes_unprefixed(path: &str, slug: &str) -> bool {
    if HOST_WIDE.contains(&path) {
        return true;
    }
    let own = |prefix: &str| {
        path.strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix(slug))
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    };
    own("/t/") || own("/scim/v2/")
}

/// Serve a request: as it is on the primary hosts, mapped onto the tenant on
/// a custom domain.
pub async fn dispatch(state: AppState, routed: Router, req: Request) -> Response {
    // Probes never depend on the host (and never pay for a tenant lookup).
    if HOST_WIDE[..2].contains(&req.uri().path()) {
        return routed.oneshot(req).await.into_response();
    }
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
    if passes_unprefixed(req.uri().path(), &tenant.slug) {
        return routed.oneshot(req).await.into_response();
    }
    let (mut parts, body) = req.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let rewritten = format!("/t/{}{path_and_query}", tenant.slug);
    match rewritten.parse::<Uri>() {
        Ok(uri) => parts.uri = uri,
        // Never serve an unmapped request on a custom domain.
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    }
    routed
        .oneshot(Request::from_parts(parts, body))
        .await
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_host_wide_and_own_tenant_paths_skip_the_prefix() {
        for p in [
            "/healthz",
            "/readyz",
            "/.well-known/webfinger",
            "/t/acme",
            "/t/acme/token",
            "/scim/v2/acme/Users",
        ] {
            assert!(passes_unprefixed(p, "acme"), "{p}");
        }
        for p in [
            "/t/other/token",
            "/t/acme-2/token",
            "/t/acmeX",
            "/scim/v2/other/Users",
            "/admin/tenants",
            "/metrics",
            "/docs/",
            "/openapi.json",
            "/token",
            "/.well-known/openid-configuration",
        ] {
            assert!(!passes_unprefixed(p, "acme"), "{p}");
        }
    }
}
