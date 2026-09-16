use std::collections::HashSet;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::providers::{BreachChecker, ProviderError, password_sha1_hex};

/// Knows the passwords it was told are breached; records every lookup and
/// can fail the next `n` of them.
#[derive(Debug, Default)]
pub struct MockBreachChecker {
    breached: Mutex<HashSet<String>>,
    calls: Mutex<Vec<String>>,
    fail_next: Mutex<u32>,
}

impl MockBreachChecker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a plaintext password as breached (reported as seen once).
    pub fn add(&self, password: &str) {
        self.breached
            .lock()
            .expect("mock poisoned")
            .insert(password_sha1_hex(password));
    }

    /// The SHA-1 hex values looked up so far.
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("mock poisoned").clone()
    }

    pub fn fail_next(&self, n: u32) {
        *self.fail_next.lock().expect("mock poisoned") = n;
    }
}

#[async_trait]
impl BreachChecker for MockBreachChecker {
    async fn count(&self, sha1_hex: &str) -> Result<u64, ProviderError> {
        self.calls
            .lock()
            .expect("mock poisoned")
            .push(sha1_hex.to_string());
        {
            let mut fail = self.fail_next.lock().expect("mock poisoned");
            if *fail > 0 {
                *fail -= 1;
                return Err(ProviderError::Unavailable("mock outage".into()));
            }
        }
        let known = self
            .breached
            .lock()
            .expect("mock poisoned")
            .contains(sha1_hex);
        Ok(u64::from(known))
    }
}
