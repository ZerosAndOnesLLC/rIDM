use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;

use crate::providers::{Captcha, CaptchaKind, CaptchaOutcome, ProviderError};

/// Records every verification and returns a configurable outcome.
/// Tokens equal to `"valid"` pass and anything else fails unless
/// [`MockCaptcha::accept_all`] is set.
#[derive(Debug)]
pub struct MockCaptcha {
    kind: CaptchaKind,
    accept_all: AtomicBool,
    calls: Mutex<Vec<(String, Option<IpAddr>)>>,
}

impl Default for MockCaptcha {
    fn default() -> Self {
        Self::new(CaptchaKind::Turnstile)
    }
}

impl MockCaptcha {
    pub fn new(kind: CaptchaKind) -> Self {
        Self {
            kind,
            accept_all: AtomicBool::new(false),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn accept_all(&self, accept: bool) {
        self.accept_all.store(accept, Ordering::SeqCst);
    }

    pub fn calls(&self) -> Vec<(String, Option<IpAddr>)> {
        self.calls.lock().expect("mock poisoned").clone()
    }
}

#[async_trait]
impl Captcha for MockCaptcha {
    fn kind(&self) -> CaptchaKind {
        self.kind.clone()
    }

    fn site_key(&self) -> Option<&str> {
        match self.kind {
            CaptchaKind::Disabled => None,
            _ => Some("mock-site-key"),
        }
    }

    async fn verify(
        &self,
        token: &str,
        remote_ip: Option<IpAddr>,
    ) -> Result<CaptchaOutcome, ProviderError> {
        self.calls
            .lock()
            .expect("mock poisoned")
            .push((token.to_string(), remote_ip));
        let success = self.accept_all.load(Ordering::SeqCst) || token == "valid";
        Ok(CaptchaOutcome {
            success,
            error_codes: if success {
                vec![]
            } else {
                vec!["invalid-input-response".into()]
            },
        })
    }
}
