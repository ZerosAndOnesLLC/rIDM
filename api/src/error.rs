//! Application error type.
//!
//! * Admin / account / flow endpoints render errors as RFC 9457 `application/problem+json`.
//! * OAuth 2.0 / OIDC endpoints render errors as RFC 6749 §5.2 JSON (`{"error": ..}`)
//!   via [`OAuthError`].

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("validation failed: {}", format_fields(.0))]
    Validation(Vec<FieldError>),
    #[error("authentication required")]
    Unauthorized,
    #[error("{0}")]
    Forbidden(String),
    #[error("{0} not found")]
    NotFound(&'static str),
    #[error("{0}")]
    Conflict(String),
    #[error("rate limit exceeded")]
    RateLimited { retry_after_secs: u64 },
    #[error("service unavailable: {0}")]
    Unavailable(String),
    #[error("database error")]
    Database(#[from] sqlx::Error),
    #[error("cache error")]
    Cache(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldError {
    pub field: String,
    pub message: String,
}

fn format_fields(fields: &[FieldError]) -> String {
    fields
        .iter()
        .map(|f| format!("{} {}", f.field, f.message))
        .collect::<Vec<_>>()
        .join("; ")
}

/// RFC 9457 problem details body.
#[derive(Debug, Serialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub title: &'static str,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<FieldError>>,
}

impl AppError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) | Self::Validation(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Database(_) | Self::Cache(_) | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn problem_type(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "urn:ridm:error:bad-request",
            Self::Validation(_) => "urn:ridm:error:validation",
            Self::Unauthorized => "urn:ridm:error:unauthorized",
            Self::Forbidden(_) => "urn:ridm:error:forbidden",
            Self::NotFound(_) => "urn:ridm:error:not-found",
            Self::Conflict(_) => "urn:ridm:error:conflict",
            Self::RateLimited { .. } => "urn:ridm:error:rate-limited",
            Self::Unavailable(_) => "urn:ridm:error:unavailable",
            Self::Database(_) | Self::Cache(_) | Self::Internal(_) => "urn:ridm:error:internal",
        }
    }

    pub fn problem(&self) -> Problem {
        let status = self.status();
        let internal = status.is_server_error();
        // Never leak internal details to the client; they are logged instead.
        let detail = if internal {
            None
        } else {
            Some(self.to_string())
        };
        let errors = match self {
            Self::Validation(errors) => Some(errors.clone()),
            _ => None,
        };
        Problem {
            kind: self.problem_type(),
            title: status.canonical_reason().unwrap_or("Error"),
            status: status.as_u16(),
            detail,
            errors,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        if status.is_server_error() {
            tracing::error!(error = ?self, "request failed");
        } else {
            tracing::debug!(error = %self, "request rejected");
        }
        let body = serde_json::to_vec(&self.problem()).unwrap_or_default();
        let mut response = (status, body).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        if let Self::RateLimited { retry_after_secs } = self
            && let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, v);
        }
        response
    }
}

impl AppError {
    /// Translate constraint violations into client errors instead of 500s.
    pub fn from_db(err: sqlx::Error) -> Self {
        if let sqlx::Error::Database(db) = &err {
            if db.is_unique_violation() {
                return Self::Conflict("already exists".into());
            }
            if db.is_foreign_key_violation() {
                return Self::BadRequest("referenced object does not exist".into());
            }
            if db.is_check_violation() {
                return Self::BadRequest(format!(
                    "constraint violated: {}",
                    db.constraint().unwrap_or("unknown")
                ));
            }
            // 42501: insufficient_privilege, raised by row level security.
            if db.code().as_deref() == Some("42501") {
                return Self::Forbidden("row level security denied the operation".into());
            }
        }
        Self::Database(err)
    }
}

impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        Self::Cache(err.to_string())
    }
}

impl From<deadpool_redis::PoolError> for AppError {
    fn from(err: deadpool_redis::PoolError) -> Self {
        Self::Cache(err.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        Self::Internal(err.to_string())
    }
}

/// OAuth 2.0 / OIDC error codes (RFC 6749 §5.2, §4.1.2.1; OIDC Core §3.1.2.6; RFC 8628).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    AccessDenied,
    UnsupportedResponseType,
    ServerError,
    TemporarilyUnavailable,
    InvalidToken,
    InsufficientScope,
    InteractionRequired,
    LoginRequired,
    ConsentRequired,
    AccountSelectionRequired,
    InvalidRequestUri,
    InvalidRequestObject,
    RequestNotSupported,
    RequestUriNotSupported,
    RegistrationNotSupported,
    AuthorizationPending,
    SlowDown,
    ExpiredToken,
    InvalidRedirectUri,
    InvalidClientMetadata,
    InvalidDpopProof,
    UseDpopNonce,
}

impl OAuthErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::AccessDenied => "access_denied",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InvalidToken => "invalid_token",
            Self::InsufficientScope => "insufficient_scope",
            Self::InteractionRequired => "interaction_required",
            Self::LoginRequired => "login_required",
            Self::ConsentRequired => "consent_required",
            Self::AccountSelectionRequired => "account_selection_required",
            Self::InvalidRequestUri => "invalid_request_uri",
            Self::InvalidRequestObject => "invalid_request_object",
            Self::RequestNotSupported => "request_not_supported",
            Self::RequestUriNotSupported => "request_uri_not_supported",
            Self::RegistrationNotSupported => "registration_not_supported",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::ExpiredToken => "expired_token",
            Self::InvalidRedirectUri => "invalid_redirect_uri",
            Self::InvalidClientMetadata => "invalid_client_metadata",
            Self::InvalidDpopProof => "invalid_dpop_proof",
            Self::UseDpopNonce => "use_dpop_nonce",
        }
    }

    pub fn status(self) -> StatusCode {
        match self {
            Self::InvalidClient | Self::InvalidToken => StatusCode::UNAUTHORIZED,
            Self::InsufficientScope => StatusCode::FORBIDDEN,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::TemporarilyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

/// An OAuth error rendered as `{"error": "...", "error_description": "..."}`.
#[derive(Debug, Clone, Serialize)]
pub struct OAuthError {
    pub error: OAuthErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

impl OAuthError {
    pub fn new(error: OAuthErrorCode, description: impl Into<String>) -> Self {
        Self {
            error,
            error_description: Some(description.into()),
            error_uri: None,
            state: None,
        }
    }

    pub fn code(error: OAuthErrorCode) -> Self {
        Self {
            error,
            error_description: None,
            error_uri: None,
            state: None,
        }
    }

    pub fn with_state(mut self, state: Option<String>) -> Self {
        self.state = state;
        self
    }

    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidRequest, description)
    }

    pub fn server_error() -> Self {
        Self::code(OAuthErrorCode::ServerError)
    }
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.error_description {
            Some(d) => write!(f, "{}: {d}", self.error.as_str()),
            None => f.write_str(self.error.as_str()),
        }
    }
}

impl std::error::Error for OAuthError {}

impl From<AppError> for OAuthError {
    fn from(err: AppError) -> Self {
        match err {
            AppError::BadRequest(m) => Self::invalid_request(m),
            AppError::Validation(_) => Self::invalid_request("validation failed"),
            AppError::Unauthorized => Self::code(OAuthErrorCode::InvalidToken),
            AppError::Forbidden(m) => Self::new(OAuthErrorCode::AccessDenied, m),
            AppError::NotFound(what) => Self::invalid_request(format!("{what} not found")),
            AppError::Conflict(m) => Self::invalid_request(m),
            AppError::RateLimited { .. } => Self::code(OAuthErrorCode::SlowDown),
            AppError::Unavailable(_) => Self::code(OAuthErrorCode::TemporarilyUnavailable),
            AppError::Database(_) | AppError::Cache(_) | AppError::Internal(_) => {
                tracing::error!(error = ?err, "oauth request failed");
                Self::server_error()
            }
        }
    }
}

impl From<sqlx::Error> for OAuthError {
    fn from(err: sqlx::Error) -> Self {
        Self::from(AppError::from_db(err))
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let status = self.error.status();
        let mut response = (status, axum::Json(&self)).into_response();
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        if self.error == OAuthErrorCode::InvalidClient {
            headers.insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"ridm\""),
            );
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_errors_do_not_leak_detail() {
        let p = AppError::Internal("db password wrong".into()).problem();
        assert_eq!(p.status, 500);
        assert!(p.detail.is_none());
    }

    #[test]
    fn oauth_error_serializes_snake_case() {
        let e = OAuthError::code(OAuthErrorCode::UnsupportedGrantType);
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(json["error"], "unsupported_grant_type");
        assert!(json.get("error_description").is_none());
    }
}
