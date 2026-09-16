//! Cross-origin policy.
//!
//! One `CorsLayer` wraps the whole router and decides per request:
//!
//! * the UI's and the API's own origins may call everything (the consoles and
//!   the sign-in pages run there, with cookies);
//! * public documents (discovery, JWKS, WebFinger, branding) answer any origin;
//! * under `/t/{slug}/` an origin registered as a `cors_origins` entry of one
//!   of the tenant's active clients is admitted (the union is cached per
//!   tenant and evicted on every client change);
//! * everything else gets no CORS headers, so browsers refuse the response.
//!
//! The layer cannot know which client a `/token` request is for (the
//! preflight has no body), so client-authenticated endpoints check again
//! once the client is known: an `Origin` that is not the UI's, the API's or
//! one of that client's is refused even though the tenant admits it
//! ([`origin_allowed_for_client`]).

use std::collections::BTreeSet;
use std::time::Duration;

use axum::http::request::Parts;
use axum::http::{HeaderName, HeaderValue, Method, header};
use tower_http::cors::{AllowOrigin, CorsLayer};
use url::Url;

use crate::cache::keys;
use crate::error::AppResult;
use crate::middleware::tenant::resolve_tenant;
use crate::models::Client;
use crate::repos;
use crate::state::AppState;

/// Cached union of client origins; evicted eagerly on client writes anyway.
const ORIGINS_TTL: Duration = Duration::from_secs(300);

pub fn layer(state: AppState) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::async_predicate(
            move |origin: HeaderValue, parts: &Parts| {
                let state = state.clone();
                let path = parts.uri.path().to_string();
                async move { origin_allowed(&state, &origin, &path).await }
            },
        ))
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::ACCEPT_LANGUAGE,
            header::IF_NONE_MATCH,
            HeaderName::from_static("dpop"),
            HeaderName::from_static("x-requested-with"),
        ])
        .expose_headers([
            header::RETRY_AFTER,
            header::WWW_AUTHENTICATE,
            header::LOCATION,
            header::ETAG,
            HeaderName::from_static("ratelimit-limit"),
            HeaderName::from_static("ratelimit-remaining"),
            HeaderName::from_static("ratelimit-reset"),
            HeaderName::from_static("dpop-nonce"),
        ])
        .max_age(Duration::from_secs(600))
}

/// `scheme://host[:port]` in canonical form, or `None` for opaque origins.
pub fn normalize_origin(raw: &str) -> Option<String> {
    let url = Url::parse(raw.trim()).ok()?;
    let origin = url.origin();
    if !origin.is_tuple() {
        return None;
    }
    Some(origin.ascii_serialization())
}

/// Documents any relying party may fetch from a browser.
fn is_public_document(path: &str) -> bool {
    if path == "/.well-known/webfinger" || path == "/.well-known/security.txt" {
        return true;
    }
    let Some(rest) = path.strip_prefix("/t/") else {
        return false;
    };
    let Some((_slug, tail)) = rest.split_once('/') else {
        return false;
    };
    matches!(
        tail,
        ".well-known/openid-configuration" | ".well-known/jwks.json" | "branding"
    )
}

fn tenant_slug(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/t/")?;
    let slug = rest.split('/').next()?;
    (!slug.is_empty()).then_some(slug)
}

async fn origin_allowed(state: &AppState, origin: &HeaderValue, path: &str) -> bool {
    let Some(origin) = origin.to_str().ok().and_then(normalize_origin) else {
        return false;
    };
    if state.config.own_origins().contains(&origin) || is_public_document(path) {
        return true;
    }
    let Some(slug) = tenant_slug(path) else {
        return false;
    };
    let tenant = match resolve_tenant(state, slug).await {
        Ok(Some(t)) => t,
        Ok(None) => return false,
        Err(err) => {
            tracing::warn!(error = %err, "cors: tenant lookup failed");
            return false;
        }
    };
    match client_origins(state, tenant.id).await {
        Ok(set) => set.contains(&origin),
        Err(err) => {
            tracing::warn!(error = %err, "cors: client origins lookup failed");
            false
        }
    }
}

/// Union of the `cors_origins` of a tenant's active clients.
pub async fn client_origins(
    state: &AppState,
    tenant_id: uuid::Uuid,
) -> AppResult<BTreeSet<String>> {
    let db = state.db.clone();
    let loaded = state
        .cache
        .get_or_load(
            &keys::client_origins(tenant_id),
            ORIGINS_TTL,
            || async move {
                let mut tx = crate::db::tenant_tx(&db, tenant_id).await?;
                let raw = repos::clients::active_cors_origins(&mut *tx, tenant_id).await?;
                tx.commit().await?;
                let set: BTreeSet<String> =
                    raw.iter().filter_map(|o| normalize_origin(o)).collect();
                Ok(Some(set))
            },
        )
        .await?;
    Ok(loaded.map(|s| (*s).clone()).unwrap_or_default())
}

/// Second, per-client check for endpoints that authenticate the client:
/// a browser origin must be the UI's, the API's or registered on this client.
pub fn origin_allowed_for_client(state: &AppState, client: &Client, origin: &HeaderValue) -> bool {
    let Some(origin) = origin.to_str().ok().and_then(normalize_origin) else {
        return false;
    };
    state.config.own_origins().contains(&origin)
        || client
            .cors_origins
            .iter()
            .filter_map(|o| normalize_origin(o))
            .any(|o| o == origin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_normalize() {
        assert_eq!(
            normalize_origin("HTTPS://App.Example.com:443/"),
            Some("https://app.example.com".into())
        );
        assert_eq!(
            normalize_origin("http://localhost:3110"),
            Some("http://localhost:3110".into())
        );
        assert_eq!(normalize_origin("null"), None);
        assert_eq!(normalize_origin("file:///x"), None);
    }

    #[test]
    fn public_documents() {
        assert!(is_public_document(
            "/t/acme/.well-known/openid-configuration"
        ));
        assert!(is_public_document("/t/acme/.well-known/jwks.json"));
        assert!(is_public_document("/t/acme/branding"));
        assert!(is_public_document("/.well-known/webfinger"));
        assert!(!is_public_document("/t/acme/token"));
        assert!(!is_public_document("/admin/tenants"));
    }
}
