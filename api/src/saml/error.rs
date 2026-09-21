/// Why a SAML message was refused. The text names the rule broken, never
/// the message's content, so it can be logged and shown to an operator.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SamlError {
    /// Not well-formed, too large, or not the SAML the endpoint expects.
    #[error("malformed SAML message: {0}")]
    Malformed(String),
    /// A signature is missing, broken, or does not verify.
    #[error("SAML signature rejected: {0}")]
    Signature(String),
    /// Well-formed, but asks for something rIDM does not do.
    #[error("unsupported SAML feature: {0}")]
    Unsupported(String),
    /// A key, certificate or cipher operation failed.
    #[error("SAML crypto failure: {0}")]
    Crypto(String),
}

impl SamlError {
    pub fn malformed(s: impl Into<String>) -> Self {
        Self::Malformed(s.into())
    }

    pub fn signature(s: impl Into<String>) -> Self {
        Self::Signature(s.into())
    }
}

pub type SamlResult<T> = Result<T, SamlError>;
