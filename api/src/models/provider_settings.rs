use serde::{Deserialize, Serialize};

/// Kinds of per-tenant provider configuration held encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Captcha,
    Smtp,
    Sms,
}

impl ProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Captcha => "captcha",
            Self::Smtp => "smtp",
            Self::Sms => "sms",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptchaProvider {
    Turnstile,
    HCaptcha,
}

/// CAPTCHA provider configuration. `secret` is only ever handled decrypted
/// inside the process; the admin API returns it redacted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaptchaConfig {
    pub provider: CaptchaProvider,
    pub site_key: String,
    pub secret: String,
    /// Override the verification endpoint (tests, self-hosted proxies).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_url: Option<String>,
}
