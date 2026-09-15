use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::providers::{Encrypted, KeyEncryptor, ProviderError};

/// Reversible, **insecure** "encryption" that still enforces the contract:
/// the key version is recorded, the AAD must match on decrypt, and blobs
/// encrypted under an unknown version are rejected.
#[derive(Debug, Default)]
pub struct MockKeyEncryptor {
    version: AtomicU32,
}

impl MockKeyEncryptor {
    pub fn new(version: u32) -> Self {
        Self {
            version: AtomicU32::new(version),
        }
    }

    /// Simulate a master-key rotation.
    pub fn rotate(&self) -> u32 {
        self.version.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn keystream(version: u32, nonce: &[u8]) -> impl Iterator<Item = u8> + '_ {
        nonce
            .iter()
            .copied()
            .chain(version.to_le_bytes())
            .cycle()
            .map(move |b| b.wrapping_mul(31).wrapping_add(version as u8))
    }

    fn aad_tag(aad: &[u8]) -> [u8; 4] {
        // FNV-1a, enough to detect a mismatched AAD in tests.
        let mut h: u32 = 0x811c_9dc5;
        for b in aad {
            h ^= u32::from(*b);
            h = h.wrapping_mul(0x0100_0193);
        }
        h.to_le_bytes()
    }
}

#[async_trait]
impl KeyEncryptor for MockKeyEncryptor {
    fn current_version(&self) -> u32 {
        self.version.load(Ordering::SeqCst)
    }

    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Encrypted, ProviderError> {
        let version = self.current_version();
        let nonce = uuid::Uuid::new_v4().as_bytes()[..12].to_vec();
        let mut ciphertext: Vec<u8> = plaintext
            .iter()
            .zip(Self::keystream(version, &nonce))
            .map(|(p, k)| p ^ k)
            .collect();
        ciphertext.extend_from_slice(&Self::aad_tag(aad));
        Ok(Encrypted {
            key_version: version,
            nonce,
            ciphertext,
        })
    }

    async fn decrypt(
        &self,
        encrypted: &Encrypted,
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        if encrypted.key_version > self.current_version() {
            return Err(ProviderError::Rejected(format!(
                "unknown key version {}",
                encrypted.key_version
            )));
        }
        let Some(body_len) = encrypted.ciphertext.len().checked_sub(4) else {
            return Err(ProviderError::Rejected("ciphertext too short".into()));
        };
        let (body, tag) = encrypted.ciphertext.split_at(body_len);
        if tag != Self::aad_tag(aad) {
            return Err(ProviderError::Rejected("aad mismatch".into()));
        }
        Ok(Zeroizing::new(
            body.iter()
                .zip(Self::keystream(encrypted.key_version, &encrypted.nonce))
                .map(|(c, k)| c ^ k)
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_and_aad_binding() {
        let enc = MockKeyEncryptor::new(1);
        let e = enc.encrypt(b"secret", b"users:1").await.unwrap();
        assert_eq!(e.key_version, 1);
        assert_eq!(&*enc.decrypt(&e, b"users:1").await.unwrap(), b"secret");
        assert!(enc.decrypt(&e, b"users:2").await.is_err());

        assert_eq!(enc.rotate(), 2);
        // Old blobs still decrypt after rotation; new ones carry the new version.
        assert_eq!(&*enc.decrypt(&e, b"users:1").await.unwrap(), b"secret");
        assert_eq!(enc.encrypt(b"x", b"").await.unwrap().key_version, 2);
    }
}
