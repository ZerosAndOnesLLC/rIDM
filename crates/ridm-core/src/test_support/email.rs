use std::sync::Mutex;

use async_trait::async_trait;

use crate::providers::{EmailMessage, EmailSender, ProviderError};

/// Captures every message; optionally fails the next `n` sends.
#[derive(Debug, Default)]
pub struct MockEmailSender {
    sent: Mutex<Vec<EmailMessage>>,
    fail_next: Mutex<u32>,
}

impl MockEmailSender {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every message sent so far, oldest first.
    pub fn sent(&self) -> Vec<EmailMessage> {
        self.sent.lock().expect("mock poisoned").clone()
    }

    pub fn last(&self) -> Option<EmailMessage> {
        self.sent.lock().expect("mock poisoned").last().cloned()
    }

    /// Messages addressed to `email` (case-insensitive), oldest first.
    pub fn sent_to(&self, email: &str) -> Vec<EmailMessage> {
        self.sent()
            .into_iter()
            .filter(|m| m.to.iter().any(|a| a.email.eq_ignore_ascii_case(email)))
            .collect()
    }

    pub fn clear(&self) {
        self.sent.lock().expect("mock poisoned").clear();
    }

    /// Make the next `n` sends fail with a retryable error.
    pub fn fail_next(&self, n: u32) {
        *self.fail_next.lock().expect("mock poisoned") = n;
    }
}

#[async_trait]
impl EmailSender for MockEmailSender {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn send(&self, message: &EmailMessage) -> Result<(), ProviderError> {
        {
            let mut fail = self.fail_next.lock().expect("mock poisoned");
            if *fail > 0 {
                *fail -= 1;
                return Err(ProviderError::Unavailable("mock failure".into()));
            }
        }
        self.sent
            .lock()
            .expect("mock poisoned")
            .push(message.clone());
        Ok(())
    }
}
