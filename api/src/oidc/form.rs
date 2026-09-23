//! Bodies of the OAuth endpoints that take `application/x-www-form-urlencoded`
//! (token, introspection, revocation, PAR, CIBA): another content type is an
//! `invalid_request`, as RFC 6749 §3.2 and its extensions require.

use axum::extract::{FromRequest, Request};
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};

use crate::error::OAuthError;
use crate::middleware::security_headers::no_store;
use crate::oidc::authorize::RawParams;

const NOT_A_FORM: &str = "content type must be application/x-www-form-urlencoded";

pub fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            ct.to_ascii_lowercase()
                .starts_with("application/x-www-form-urlencoded")
        })
}

pub fn not_a_form() -> OAuthError {
    OAuthError::invalid_request(NOT_A_FORM)
}

/// The parameters of a form post; the extractor refuses any other body.
pub struct FormParams(pub RawParams);

impl<S: Send + Sync> FromRequest<S> for FormParams {
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        if !is_form(req.headers()) {
            return Err(no_store(not_a_form().into_response()));
        }
        let body = String::from_request(req, state)
            .await
            .map_err(|e| no_store(OAuthError::invalid_request(e.body_text()).into_response()))?;
        Ok(Self(RawParams::parse(&body)))
    }
}
