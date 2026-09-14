use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailAddress {
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl EmailAddress {
    pub fn new(email: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            name: None,
        }
    }

    pub fn with_name(email: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            name: Some(name.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailMessage {
    pub to: Vec<EmailAddress>,
    /// `None` means the sender's configured default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<EmailAddress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<EmailAddress>,
    pub subject: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    /// Extra headers (e.g. `List-Unsubscribe`, `X-Entity-Ref-ID`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
}

/// Delivers email. Implementations: SMTP (lettre), generic HTTP webhook, and
/// the in-memory mock used by tests.
#[async_trait]
pub trait EmailSender: Send + Sync {
    /// Human-readable backend name for diagnostics (`smtp`, `http`, `mock`).
    fn name(&self) -> &'static str;

    async fn send(&self, message: &EmailMessage) -> Result<(), super::ProviderError>;
}
