//! Per-route rate limiting (`services::rate_limit`) as an axum layer.
//!
//! Applied to a router with `Router::layer` so the path parameters are known:
//! the tenant is resolved (cached) and its policy consulted. Every response
//! passing through carries `RateLimit-Limit`, `RateLimit-Remaining` and
//! `RateLimit-Reset` for the tightest bucket; a refused request gets `429`
//! with `Retry-After` in the endpoint family's own error format.

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::{AppError, OAuthError};
use crate::middleware::client_ip;
use crate::middleware::tenant::resolve_tenant;
use crate::services::rate_limit::{self, Category, Decision};
use crate::state::AppState;

/// How a refusal is rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// RFC 6749 JSON (`{"error": "slow_down"}`).
    OAuth,
    /// RFC 9457 `application/problem+json`.
    Problem,
    /// A plain HTML page for browser navigations (`/authorize`, brokering).
    Html,
}

#[derive(Clone)]
pub struct Limiter {
    state: AppState,
    category: Category,
    style: Style,
}

/// Build the middleware for one endpoint family:
/// `router.layer(axum::middleware::from_fn_with_state(Limiter::new(..), limit))`.
impl Limiter {
    pub fn new(state: AppState, category: Category, style: Style) -> Self {
        Self {
            state,
            category,
            style,
        }
    }
}

pub async fn limit(State(l): State<Limiter>, req: Request, next: Next) -> Response {
    if !l.state.config.rate_limits.enabled {
        return next.run(req).await;
    }
    let slug = tenant_slug(req.uri().path());
    let tenant = match slug {
        Some(slug) => match resolve_tenant(&l.state, slug).await {
            Ok(t) => t,
            Err(err) => {
                tracing::warn!(error = %err, "rate limiter could not resolve tenant");
                None
            }
        },
        None => None,
    };
    let peer = req
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0);
    let ip = client_ip(&l.state, req.headers(), peer);
    let decision = rate_limit::hit(&l.state, tenant.as_deref(), l.category, ip.as_deref()).await;
    if let Some(retry_after) = decision.retry_after_secs {
        tracing::info!(
            category = l.category.as_str(),
            tenant = slug.unwrap_or(""),
            ip = ip.as_deref().unwrap_or(""),
            retry_after,
            "rate limit exceeded"
        );
        return with_headers(refusal(l.style, retry_after), &decision);
    }
    with_headers(next.run(req).await, &decision)
}

/// `/t/{slug}/...` → `slug`.
fn tenant_slug(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/t/")?;
    let slug = rest.split('/').next()?;
    (!slug.is_empty()).then_some(slug)
}

fn refusal(style: Style, retry_after_secs: u64) -> Response {
    let err = AppError::RateLimited { retry_after_secs };
    match style {
        Style::Problem => err.into_response(),
        Style::OAuth => OAuthError::from(err).into_response(),
        Style::Html => {
            let mut res = crate::oidc::authorize::error_page(
                StatusCode::TOO_MANY_REQUESTS,
                "slow_down",
                &format!("Too many requests; try again in {retry_after_secs} seconds."),
            );
            if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                res.headers_mut().insert(header::RETRY_AFTER, v);
            }
            res
        }
    }
}

/// Add the draft-ietf-httpapi-ratelimit-headers fields for the tightest bucket.
pub fn with_headers(mut res: Response<Body>, decision: &Decision) -> Response<Body> {
    if let Some(b) = decision.tightest {
        let h = res.headers_mut();
        let set = |h: &mut axum::http::HeaderMap, name: &'static str, v: u64| {
            if let Ok(v) = HeaderValue::from_str(&v.to_string()) {
                h.insert(name, v);
            }
        };
        set(h, "ratelimit-limit", u64::from(b.limit));
        set(h, "ratelimit-remaining", u64::from(b.remaining));
        set(h, "ratelimit-reset", b.reset_secs);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::tenant_slug;

    #[test]
    fn slug_from_path() {
        assert_eq!(tenant_slug("/t/acme/token"), Some("acme"));
        assert_eq!(tenant_slug("/t/acme"), Some("acme"));
        assert_eq!(tenant_slug("/t//token"), None);
        assert_eq!(tenant_slug("/admin/tenants"), None);
    }
}
