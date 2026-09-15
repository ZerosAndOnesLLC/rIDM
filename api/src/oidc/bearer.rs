//! Bearer token extraction and RFC 6750 error responses.

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// `Authorization: Bearer <token>` or a `access_token` form/query parameter.
pub fn extract(headers: &HeaderMap, body_token: Option<&str>) -> Option<String> {
    let from_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let (scheme, rest) = v.split_once(' ')?;
            scheme
                .eq_ignore_ascii_case("bearer")
                .then(|| rest.trim().to_string())
        })
        .filter(|t| !t.is_empty());
    from_header.or_else(|| body_token.map(str::to_string).filter(|t| !t.is_empty()))
}

/// 401/403 with `WWW-Authenticate` per RFC 6750 §3.
pub fn error(status: StatusCode, code: &str, description: &str) -> Response {
    let value = format!(
        "Bearer error=\"{code}\", error_description=\"{}\"",
        description.replace('"', "'")
    );
    let mut res = (
        status,
        axum::Json(serde_json::json!({"error": code, "error_description": description})),
    )
        .into_response();
    if let Ok(v) = HeaderValue::from_str(&value) {
        res.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

pub fn invalid_token(description: &str) -> Response {
    error(StatusCode::UNAUTHORIZED, "invalid_token", description)
}

pub fn insufficient_scope(description: &str) -> Response {
    error(StatusCode::FORBIDDEN, "insufficient_scope", description)
}
