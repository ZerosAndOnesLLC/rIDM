//! The request guard on the authorization, token and flow endpoint families:
//! tenant-wide IP rules (`services::ip_rules`), then rate limits
//! (`services::rate_limit`), as one axum layer per family.
//!
//! Applied to a router with `Router::layer` so the path parameters are known:
//! the tenant is resolved (cached) and its rules and policy consulted. A
//! refused address gets `403`, an exhausted bucket `429` with `Retry-After`,
//! both in the family's own error format; every other response carries
//! `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset` for the
//! tightest bucket. Client-scoped IP rules are checked by the handlers once
//! the client is known.

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::{AppError, OAuthError};
use crate::middleware::client_ip_addr;
use crate::middleware::tenant::{is_valid_slug, resolve_tenant};
use crate::services::ip_rules;
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
pub struct Guard {
    state: AppState,
    category: Category,
    style: Style,
}

/// Build the middleware for one endpoint family:
/// `router.layer(axum::middleware::from_fn_with_state(Guard::new(..), guard))`.
impl Guard {
    pub fn new(state: AppState, category: Category, style: Style) -> Self {
        Self {
            state,
            category,
            style,
        }
    }
}

pub async fn guard(State(l): State<Guard>, req: Request, next: Next) -> Response {
    let slug = tenant_slug(req.uri().path());
    // The guard reads the raw path, the handlers read axum's percent-decoded
    // path parameter. A slug carrying an escape (`/t/%61cme/token`) would be
    // invisible here and still reach the tenant, taking its IP rules and
    // rate-limit buckets with it. A valid slug is `[a-z0-9-]` and so never
    // needs escaping, which makes the two views equal exactly when the raw
    // segment is already valid: anything else cannot name a tenant and is
    // refused rather than passed on.
    if let Some(raw) = slug
        && !is_valid_slug(raw)
    {
        return refusal(l.style, AppError::NotFound("tenant"));
    }
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
    let ip = client_ip_addr(&l.state, req.headers(), peer);
    if let Some(t) = &tenant {
        match ip_rules::tenant_allows(&l.state, t.id, ip).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::info!(tenant = %t.slug, ip = ?ip, "tenant ip rule refused request");
                metrics::counter!("ridm_ip_rule_rejections_total", "scope" => "tenant")
                    .increment(1);
                return refusal(
                    l.style,
                    AppError::Forbidden("this address may not sign in here".into()),
                );
            }
            // Unreadable rules must not open the door.
            Err(err) => {
                tracing::warn!(error = %err, "ip rules unavailable; refusing");
                return refusal(
                    l.style,
                    AppError::Unavailable("ip rules unavailable".into()),
                );
            }
        }
    }
    if !l.state.config.rate_limits.enabled {
        return next.run(req).await;
    }
    let ip = ip.map(|ip| ip.to_string());
    let decision = rate_limit::hit(&l.state, tenant.as_deref(), l.category, ip.as_deref()).await;
    if let Some(retry_after) = decision.retry_after_secs {
        tracing::info!(
            category = l.category.as_str(),
            tenant = slug.unwrap_or(""),
            ip = ip.as_deref().unwrap_or(""),
            retry_after,
            "rate limit exceeded"
        );
        return with_headers(
            refusal(
                l.style,
                AppError::RateLimited {
                    retry_after_secs: retry_after,
                },
            ),
            &decision,
        );
    }
    with_headers(next.run(req).await, &decision)
}

/// `/t/{slug}/...` → `slug`.
fn tenant_slug(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/t/")?;
    let slug = rest.split('/').next()?;
    (!slug.is_empty()).then_some(slug)
}

/// Render a refusal in the family's format (the HTML page keeps the problem
/// status and, for a rate limit, `Retry-After`).
fn refusal(style: Style, err: AppError) -> Response {
    match style {
        Style::Problem => err.into_response(),
        Style::OAuth => OAuthError::from(err).into_response(),
        Style::Html => {
            let status = err.status();
            let (code, text) = match &err {
                AppError::RateLimited { retry_after_secs } => (
                    "slow_down",
                    format!("Too many requests; try again in {retry_after_secs} seconds."),
                ),
                AppError::Forbidden(m) => ("access_denied", m.clone()),
                other => ("temporarily_unavailable", other.to_string()),
            };
            let mut res = crate::oidc::authorize::error_page(status, code, &text);
            if let AppError::RateLimited { retry_after_secs } = err
                && let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string())
            {
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
