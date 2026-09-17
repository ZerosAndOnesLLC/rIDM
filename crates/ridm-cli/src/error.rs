//! Errors the CLI reports, and the exit codes they produce.
//!
//! Exit codes follow the convention of the tools an operator already has in a
//! script: `0` success, `1` the command ran and failed, `2` the command line
//! (or the configuration behind it) was wrong. `ridm tenant diff --exit-code`
//! adds `3` for "there are changes", so a pipeline can branch on it.

use std::fmt;

pub type Result<T> = std::result::Result<T, CliError>;

/// Exit code for "the plan is not empty" (`tenant diff --exit-code`).
pub const EXIT_CHANGES: i32 = 3;

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Wrong flags, no profile, nothing to authenticate with: nothing ran.
    #[error("{0}")]
    Usage(String),
    /// The command ran and did not get what it asked for.
    #[error("{0}")]
    Failed(String),
    /// Boxed: a problem document is the largest thing a command can fail
    /// with, and every `Result` in the CLI would otherwise carry its size.
    #[error("{0}")]
    Api(Box<ApiError>),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Http(#[from] reqwest::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    /// `tenant diff --exit-code` with a non-empty plan. Not a failure: the
    /// plan has already been printed.
    #[error("")]
    Changes,
}

impl CliError {
    pub fn usage(msg: impl Into<String>) -> Self {
        Self::Usage(msg.into())
    }

    pub fn failed(msg: impl Into<String>) -> Self {
        Self::Failed(msg.into())
    }

    pub fn code(&self) -> i32 {
        match self {
            Self::Usage(_) => 2,
            Self::Changes => EXIT_CHANGES,
            _ => 1,
        }
    }
}

impl From<ApiError> for CliError {
    fn from(err: ApiError) -> Self {
        Self::Api(Box::new(err))
    }
}

/// A response the admin API refused, rendered from its RFC 9457 problem
/// document when it sent one.
#[derive(Debug)]
pub struct ApiError {
    pub method: String,
    pub url: String,
    pub status: u16,
    pub title: String,
    pub detail: Option<String>,
    /// Per-field validation messages (`errors[]` of the problem document).
    pub fields: Vec<(String, String)>,
}

impl std::error::Error for ApiError {}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} → {} {}",
            self.method, self.url, self.status, self.title
        )?;
        if let Some(d) = &self.detail {
            write!(f, ": {d}")?;
        }
        for (field, message) in &self.fields {
            write!(f, "\n  {field}: {message}")?;
        }
        Ok(())
    }
}

/// An OAuth error response (RFC 6749 §5.2) from the token or device endpoint.
#[derive(Debug)]
pub struct OAuthError {
    pub code: String,
    pub description: Option<String>,
}

impl std::error::Error for OAuthError {}

impl fmt::Display for OAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.description {
            Some(d) => write!(f, "{}: {d}", self.code),
            None => write!(f, "{}", self.code),
        }
    }
}
