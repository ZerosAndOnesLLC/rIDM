use std::net::IpAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Which widget the UI must render. Sent to the browser as part of the flow state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptchaKind {
    Turnstile,
    HCaptcha,
    /// No challenge is ever required.
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptchaOutcome {
    pub success: bool,
    /// Error codes reported by the backend, for logging.
    pub error_codes: Vec<String>,
}

/// Verifies a CAPTCHA response token. Implementations: Cloudflare Turnstile,
/// hCaptcha, disabled, and the configurable mock used by tests.
#[async_trait]
pub trait Captcha: Send + Sync {
    fn kind(&self) -> CaptchaKind;

    /// Public site key the browser widget needs, if any.
    fn site_key(&self) -> Option<&str>;

    async fn verify(
        &self,
        token: &str,
        remote_ip: Option<IpAddr>,
    ) -> Result<CaptchaOutcome, super::ProviderError>;
}
