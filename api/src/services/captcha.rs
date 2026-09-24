//! CAPTCHA providers: Cloudflare Turnstile and hCaptcha (same siteverify
//! shape), selected per tenant from encrypted provider settings.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ridm_core::providers::{Captcha, CaptchaKind, CaptchaOutcome, ProviderError};
use uuid::Uuid;

use crate::error::AppResult;
use crate::models::{CaptchaConfig, CaptchaProvider, ProviderKind};
use crate::services::provider_settings;
use crate::state::AppState;

pub const TURNSTILE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
pub const HCAPTCHA_VERIFY_URL: &str = "https://api.hcaptcha.com/siteverify";

pub struct SiteverifyCaptcha {
    kind: CaptchaKind,
    site_key: String,
    secret: String,
    verify_url: String,
    http: reqwest::Client,
}

/// Siteverify answers quickly or not at all.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);

impl SiteverifyCaptcha {
    pub fn from_config(cfg: &CaptchaConfig, http: reqwest::Client) -> Self {
        let (kind, default_url) = match cfg.provider {
            CaptchaProvider::Turnstile => (CaptchaKind::Turnstile, TURNSTILE_VERIFY_URL),
            CaptchaProvider::HCaptcha => (CaptchaKind::HCaptcha, HCAPTCHA_VERIFY_URL),
        };
        Self {
            kind,
            site_key: cfg.site_key.clone(),
            secret: cfg.secret.clone(),
            verify_url: cfg
                .verify_url
                .clone()
                .unwrap_or_else(|| default_url.to_string()),
            http,
        }
    }
}

#[async_trait]
impl Captcha for SiteverifyCaptcha {
    fn kind(&self) -> CaptchaKind {
        self.kind.clone()
    }

    fn site_key(&self) -> Option<&str> {
        Some(&self.site_key)
    }

    async fn verify(
        &self,
        token: &str,
        remote_ip: Option<IpAddr>,
    ) -> Result<CaptchaOutcome, ProviderError> {
        if token.is_empty() || token.len() > 4096 {
            return Ok(CaptchaOutcome {
                success: false,
                error_codes: vec!["invalid-input-response".into()],
            });
        }
        let mut form = vec![
            ("secret", self.secret.clone()),
            ("response", token.to_string()),
        ];
        if let Some(ip) = remote_ip {
            form.push(("remoteip", ip.to_string()));
        }
        // `verify_url` is a tenant's choice: the shared outbound client
        // reaches public addresses only (SSRF).
        crate::util::outbound::check_url(&self.verify_url).map_err(ProviderError::Rejected)?;
        let res = self
            .http
            .post(&self.verify_url)
            .timeout(VERIFY_TIMEOUT)
            .form(&form)
            .send()
            .await
            .map_err(ProviderError::unavailable)?;
        if !res.status().is_success() {
            return Err(ProviderError::Unavailable(format!(
                "siteverify returned {}",
                res.status()
            )));
        }
        let body: serde_json::Value = res.json().await.map_err(ProviderError::unavailable)?;
        Ok(CaptchaOutcome {
            success: body["success"].as_bool().unwrap_or(false),
            error_codes: body["error-codes"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}

/// No challenge configured.
pub struct DisabledCaptcha;

#[async_trait]
impl Captcha for DisabledCaptcha {
    fn kind(&self) -> CaptchaKind {
        CaptchaKind::Disabled
    }

    fn site_key(&self) -> Option<&str> {
        None
    }

    async fn verify(
        &self,
        _token: &str,
        _remote_ip: Option<IpAddr>,
    ) -> Result<CaptchaOutcome, ProviderError> {
        Ok(CaptchaOutcome {
            success: true,
            error_codes: vec![],
        })
    }
}

/// Provider for a tenant, from its encrypted configuration.
pub async fn provider_for(state: &AppState, tenant_id: Uuid) -> AppResult<Arc<dyn Captcha>> {
    match provider_settings::get::<CaptchaConfig>(state, tenant_id, ProviderKind::Captcha).await? {
        Some(cfg) => Ok(Arc::new(SiteverifyCaptcha::from_config(
            &cfg,
            state.outbound.clone(),
        ))),
        None => Ok(Arc::new(DisabledCaptcha)),
    }
}

pub async fn configure(state: &AppState, tenant_id: Uuid, cfg: &CaptchaConfig) -> AppResult<()> {
    provider_settings::set(state, tenant_id, ProviderKind::Captcha, cfg).await
}

pub async fn disable(state: &AppState, tenant_id: Uuid) -> AppResult<()> {
    provider_settings::clear(state, tenant_id, ProviderKind::Captcha)
        .await
        .map(|_| ())
}
