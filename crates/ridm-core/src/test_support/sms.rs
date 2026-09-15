use std::sync::Mutex;

use async_trait::async_trait;

use crate::providers::{ProviderError, SmsMessage, SmsSender};

/// Captures every message; optionally fails the next `n` sends.
#[derive(Debug, Default)]
pub struct MockSmsSender {
    sent: Mutex<Vec<SmsMessage>>,
    fail_next: Mutex<u32>,
}

impl MockSmsSender {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sent(&self) -> Vec<SmsMessage> {
        self.sent.lock().expect("mock poisoned").clone()
    }

    pub fn last(&self) -> Option<SmsMessage> {
        self.sent.lock().expect("mock poisoned").last().cloned()
    }

    pub fn sent_to(&self, number: &str) -> Vec<SmsMessage> {
        self.sent().into_iter().filter(|m| m.to == number).collect()
    }

    pub fn clear(&self) {
        self.sent.lock().expect("mock poisoned").clear();
    }

    pub fn fail_next(&self, n: u32) {
        *self.fail_next.lock().expect("mock poisoned") = n;
    }
}

#[async_trait]
impl SmsSender for MockSmsSender {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn send(&self, message: &SmsMessage) -> Result<(), ProviderError> {
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
