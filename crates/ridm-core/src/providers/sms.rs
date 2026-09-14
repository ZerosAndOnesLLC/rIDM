use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmsMessage {
    /// Recipient in E.164 form (`+15551234567`).
    pub to: String,
    pub body: String,
}

/// Delivers SMS. Implementations: generic HTTP webhook (so any gateway can be
/// used without a provider-specific SDK) and the in-memory mock used by tests.
#[async_trait]
pub trait SmsSender: Send + Sync {
    fn name(&self) -> &'static str;

    async fn send(&self, message: &SmsMessage) -> Result<(), super::ProviderError>;
}
