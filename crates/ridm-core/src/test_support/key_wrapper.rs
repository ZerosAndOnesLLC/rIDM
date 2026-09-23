use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::providers::{KeyWrapper, ProviderError, WrappedKey};

/// **Insecure** key wrapper that still enforces the contract: the context must
/// match on unwrap, a key reference it did not issue is refused, and it can be
/// switched off to play an unreachable KMS.
#[derive(Debug)]
pub struct MockKeyWrapper {
    backend: &'static str,
    key_ref: String,
    secret: u8,
    down: AtomicBool,
    unwraps: AtomicUsize,
}

impl MockKeyWrapper {
    /// A wrapper reporting itself as `backend`, with its own key `secret`.
    pub fn new(backend: &'static str, key_ref: &str, secret: u8) -> Self {
        Self {
            backend,
            key_ref: key_ref.to_string(),
            secret,
            down: AtomicBool::new(false),
            unwraps: AtomicUsize::new(0),
        }
    }

    /// Make every call fail as unavailable (or recover).
    pub fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::SeqCst);
    }

    /// Successful unwraps so far.
    pub fn unwraps(&self) -> usize {
        self.unwraps.load(Ordering::SeqCst)
    }

    fn mask(&self, context: &[u8]) -> impl Iterator<Item = u8> + '_ {
        let tag = context
            .iter()
            .fold(self.secret, |a, b| a.wrapping_mul(31) ^ b);
        std::iter::repeat(tag)
    }

    fn check(&self) -> Result<(), ProviderError> {
        if self.down.load(Ordering::SeqCst) {
            return Err(ProviderError::Unavailable("mock KMS is down".into()));
        }
        Ok(())
    }
}

#[async_trait]
impl KeyWrapper for MockKeyWrapper {
    fn backend(&self) -> &'static str {
        self.backend
    }

    async fn wrap(&self, key: &[u8], context: &[u8]) -> Result<WrappedKey, ProviderError> {
        self.check()?;
        let mut wrapped: Vec<u8> = key
            .iter()
            .zip(self.mask(context))
            .map(|(k, m)| k ^ m)
            .collect();
        // A check byte so the wrong context or key is detected, as an AEAD would.
        wrapped.push(self.mask(context).next().unwrap_or_default() ^ 0xa5);
        Ok(WrappedKey {
            key_ref: self.key_ref.clone(),
            wrapped,
        })
    }

    async fn unwrap(
        &self,
        key_ref: &str,
        wrapped: &[u8],
        context: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        self.check()?;
        if key_ref != self.key_ref {
            return Err(ProviderError::Rejected(format!("unknown key {key_ref}")));
        }
        let Some((check, body)) = wrapped.split_last() else {
            return Err(ProviderError::Rejected("empty wrapped key".into()));
        };
        if *check != self.mask(context).next().unwrap_or_default() ^ 0xa5 {
            return Err(ProviderError::Rejected("context mismatch".into()));
        }
        self.unwraps.fetch_add(1, Ordering::SeqCst);
        Ok(Zeroizing::new(
            body.iter()
                .zip(self.mask(context))
                .map(|(w, m)| w ^ m)
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wraps_and_checks_context_and_key() {
        let w = MockKeyWrapper::new("mock", "k1", 9);
        let wrapped = w.wrap(&[1, 2, 3], b"gen:2").await.unwrap();
        assert_eq!(wrapped.key_ref, "k1");
        assert_eq!(
            &*w.unwrap("k1", &wrapped.wrapped, b"gen:2").await.unwrap(),
            &[1, 2, 3]
        );
        assert!(w.unwrap("k1", &wrapped.wrapped, b"gen:3").await.is_err());
        assert!(w.unwrap("k2", &wrapped.wrapped, b"gen:2").await.is_err());
        w.set_down(true);
        assert!(
            w.unwrap("k1", &wrapped.wrapped, b"gen:2")
                .await
                .unwrap_err()
                .is_retryable()
        );
    }
}
