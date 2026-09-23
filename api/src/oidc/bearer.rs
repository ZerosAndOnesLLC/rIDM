//! Bearer token extraction and RFC 6750 error responses.

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// How the access token was presented (RFC 6750 `Bearer`, RFC 9449 `DPoP`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Bearer,
    Dpop,
}

/// `Authorization: Bearer|DPoP <token>` or an `access_token` form/query
/// parameter (which counts as `Bearer`).
pub fn extract_with_scheme(
    headers: &HeaderMap,
    body_token: Option<&str>,
) -> Option<(Scheme, String)> {
    let from_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let (scheme, rest) = v.split_once(' ')?;
            let scheme = if scheme.eq_ignore_ascii_case("bearer") {
                Scheme::Bearer
            } else if scheme.eq_ignore_ascii_case("dpop") {
                Scheme::Dpop
            } else {
                return None;
            };
            let token = rest.trim();
            (!token.is_empty()).then(|| (scheme, token.to_string()))
        });
    from_header.or_else(|| {
        body_token
            .map(str::to_string)
            .filter(|t| !t.is_empty())
            .map(|t| (Scheme::Bearer, t))
    })
}

/// `Authorization: Bearer <token>` or a `access_token` form/query parameter.
pub fn extract(headers: &HeaderMap, body_token: Option<&str>) -> Option<String> {
    extract_with_scheme(headers, body_token)
        .and_then(|(scheme, t)| (scheme == Scheme::Bearer).then_some(t))
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
    crate::middleware::security_headers::set_no_store(res.headers_mut());
    res
}

pub fn invalid_token(description: &str) -> Response {
    error(StatusCode::UNAUTHORIZED, "invalid_token", description)
}

/// 401 for a sender-constrained token presented wrongly: the challenge names
/// both schemes and the proof algorithms (RFC 9449 §7.1).
pub fn dpop_invalid_token(description: &str) -> Response {
    let mut res = error(StatusCode::UNAUTHORIZED, "invalid_token", description);
    let value = format!(
        "DPoP error=\"invalid_token\", error_description=\"{}\", algs=\"{}\", Bearer error=\"invalid_token\"",
        description.replace('"', "'"),
        crate::oidc::dpop::ALGS.join(" ")
    );
    if let Ok(v) = HeaderValue::from_str(&value) {
        res.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    res
}

pub fn insufficient_scope(description: &str) -> Response {
    error(StatusCode::FORBIDDEN, "insufficient_scope", description)
}
