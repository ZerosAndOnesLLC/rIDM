//! Global well-known documents (not tenant scoped).

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/.well-known/security.txt", get(security_txt))
}

/// RFC 9116 security.txt, as the operator configured it (see
/// [`crate::util::security_txt`]); 404 when they have not.
async fn security_txt(State(state): State<AppState>) -> Response {
    let Some(txt) = &state.config.security_txt else {
        return StatusCode::NOT_FOUND.into_response();
    };
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
        txt.render(chrono::Utc::now()),
    )
        .into_response()
}
