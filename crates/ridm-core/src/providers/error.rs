use std::fmt;

/// Error returned by every provider. The variant tells the caller whether a
/// retry can help.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The provider is misconfigured (bad credentials, missing key). Not retryable.
    #[error("provider configuration error: {0}")]
    Configuration(String),
    /// The backend is temporarily unreachable or throttling. Retryable.
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    /// The backend refused the request permanently (invalid recipient, bad
    /// ciphertext, unknown key version). Not retryable.
    #[error("provider rejected request: {0}")]
    Rejected(String),
}

impl ProviderError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }

    pub fn unavailable(err: impl fmt::Display) -> Self {
        Self::Unavailable(err.to_string())
    }

    pub fn rejected(err: impl fmt::Display) -> Self {
        Self::Rejected(err.to_string())
    }

    pub fn configuration(err: impl fmt::Display) -> Self {
        Self::Configuration(err.to_string())
    }
}
