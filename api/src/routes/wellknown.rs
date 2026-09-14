//! Global well-known documents (not tenant scoped).

use axum::Router;
use axum::http::{HeaderValue, header};
use axum::response::IntoResponse;
use axum::routing::get;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/.well-known/security.txt", get(security_txt))
}

/// RFC 9116 security.txt. Kept in sync with SECURITY.md.
const SECURITY_TXT: &str = "\
Contact: https://github.com/mack42/rIDM/security/advisories/new
Expires: 2027-09-14T00:00:00.000Z
Preferred-Languages: en
Policy: https://github.com/mack42/rIDM/blob/main/SECURITY.md
Canonical: https://github.com/mack42/rIDM/blob/main/api/src/routes/wellknown.rs
";

async fn security_txt() -> impl IntoResponse {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=86400"),
            ),
        ],
        SECURITY_TXT,
    )
}
