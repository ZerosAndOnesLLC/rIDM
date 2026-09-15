//! Default [`KeyEncryptor`]: XChaCha20-Poly1305 with the master key from the
//! environment (`MASTER_KEY` / `MASTER_KEY_FILE`). Supports several key
//! generations so the master key can be rotated without downtime: new
//! ciphertexts use `current`, decryption accepts any listed generation.

use std::collections::HashMap;

use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ridm_core::providers::{Encrypted, KeyEncryptor, ProviderError};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::util::secret::SecretBytes;

const NONCE_LEN: usize = 24;

pub struct MasterKeyEncryptor {
    current: u32,
    keys: HashMap<u32, SecretBytes>,
}

impl MasterKeyEncryptor {
    pub fn new(current: u32, current_key: SecretBytes, previous: Vec<(u32, SecretBytes)>) -> Self {
        let mut keys = HashMap::with_capacity(previous.len() + 1);
        for (v, k) in previous {
            keys.insert(v, k);
        }
        keys.insert(current, current_key);
        Self { current, keys }
    }

    pub fn from_config(config: &Config) -> Self {
        Self::new(
            config.master_key_version,
            config.master_key.clone(),
            config.master_key_previous.clone(),
        )
    }

    fn cipher(&self, version: u32) -> Result<XChaCha20Poly1305, ProviderError> {
        let key = self.keys.get(&version).ok_or_else(|| {
            ProviderError::Rejected(format!("unknown master key version {version}"))
        })?;
        XChaCha20Poly1305::new_from_slice(key.expose())
            .map_err(|_| ProviderError::Configuration("master key must be 32 bytes".into()))
    }

    pub fn known_versions(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.keys.keys().copied().collect();
        v.sort_unstable();
        v
    }
}

#[async_trait]
impl KeyEncryptor for MasterKeyEncryptor {
    fn current_version(&self) -> u32 {
        self.current
    }

    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Encrypted, ProviderError> {
        let cipher = self.cipher(self.current)?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::fill(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| ProviderError::Rejected("encryption failed".into()))?;
        Ok(Encrypted {
            key_version: self.current,
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    async fn decrypt(
        &self,
        encrypted: &Encrypted,
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        if encrypted.nonce.len() != NONCE_LEN {
            return Err(ProviderError::Rejected("bad nonce length".into()));
        }
        let cipher = self.cipher(encrypted.key_version)?;
        let nonce = XNonce::try_from(encrypted.nonce.as_slice())
            .map_err(|_| ProviderError::Rejected("bad nonce".into()))?;
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &encrypted.ciphertext,
                    aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| {
                ProviderError::Rejected(
                    "decryption failed (wrong key, aad, or tampered data)".into(),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SecretBytes {
        SecretBytes::new(vec![b; 32])
    }

    #[tokio::test]
    async fn round_trip_binds_aad_and_detects_tampering() {
        let enc = MasterKeyEncryptor::new(1, key(1), vec![]);
        let e = enc
            .encrypt(b"private key bytes", b"signing_keys:abc")
            .await
            .unwrap();
        assert_eq!(e.key_version, 1);
        assert_eq!(e.nonce.len(), NONCE_LEN);
        assert_ne!(e.ciphertext, b"private key bytes");
        let pt = enc.decrypt(&e, b"signing_keys:abc").await.unwrap();
        assert_eq!(&*pt, b"private key bytes");
        assert!(enc.decrypt(&e, b"signing_keys:other").await.is_err());
        let mut tampered = e.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(enc.decrypt(&tampered, b"signing_keys:abc").await.is_err());
        // Serialized blob survives the storage format.
        let blob = e.to_bytes();
        let back = Encrypted::from_bytes(&blob).unwrap();
        assert_eq!(
            &*enc.decrypt(&back, b"signing_keys:abc").await.unwrap(),
            b"private key bytes"
        );
    }

    #[tokio::test]
    async fn rotation_keeps_old_generations_readable() {
        let v1 = MasterKeyEncryptor::new(1, key(1), vec![]);
        let old = v1.encrypt(b"secret", b"a").await.unwrap();
        let v2 = MasterKeyEncryptor::new(2, key(2), vec![(1, key(1))]);
        assert_eq!(v2.current_version(), 2);
        assert_eq!(v2.known_versions(), vec![1, 2]);
        assert_eq!(&*v2.decrypt(&old, b"a").await.unwrap(), b"secret");
        let fresh = v2.encrypt(b"secret", b"a").await.unwrap();
        assert_eq!(fresh.key_version, 2);
        // A node that only has generation 2 cannot read generation 1 blobs.
        let v2_only = MasterKeyEncryptor::new(2, key(2), vec![]);
        assert!(v2_only.decrypt(&old, b"a").await.is_err());
        // Wrong key material for the same version fails authentication.
        let wrong = MasterKeyEncryptor::new(1, key(9), vec![]);
        assert!(wrong.decrypt(&old, b"a").await.is_err());
    }
}
