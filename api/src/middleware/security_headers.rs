//! Browser hardening headers on every response.
//!
//! Handlers that set a header keep theirs (the authorization error page has
//! its own content security policy); the rest get the API defaults: nothing
//! may be loaded from or framed by an API response, content types are not
//! sniffed, and referrers are not sent. `Strict-Transport-Security` is added
//! when `PUBLIC_URL` is https (`HSTS_MAX_AGE`, 0 = off). Swagger UI under
//! `/docs` needs scripts and styles, so it keeps only the framing rule.

use axum::extract::{Request, State};
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

use crate::state::AppState;

/// Content security policy for the HTML pages the API renders itself
/// (inline styles only; no scripts, no framing, no navigation targets).
pub const HTML_PAGE_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

const API_CSP: &str = "default-src 'none'; frame-ancestors 'none'";
const DOCS_CSP: &str = "frame-ancestors 'none'";

pub async fn security_headers(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let docs = req.uri().path().starts_with("/docs");
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    let set_default = |h: &mut axum::http::HeaderMap, name: header::HeaderName, v: &'static str| {
        if !h.contains_key(&name) {
            h.insert(name, HeaderValue::from_static(v));
        }
    };
    set_default(h, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set_default(h, header::X_FRAME_OPTIONS, "DENY");
    set_default(h, header::REFERRER_POLICY, "no-referrer");
    set_default(
        h,
        header::CONTENT_SECURITY_POLICY,
        if docs { DOCS_CSP } else { API_CSP },
    );
    if state.config.public_url.scheme() == "https"
        && state.config.hsts_max_age > 0
        && !h.contains_key(header::STRICT_TRANSPORT_SECURITY)
        && let Ok(v) = HeaderValue::from_str(&format!(
            "max-age={}; includeSubDomains",
            state.config.hsts_max_age
        ))
    {
        h.insert(header::STRICT_TRANSPORT_SECURITY, v);
    }
    res
}
