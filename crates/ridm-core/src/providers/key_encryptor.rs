//! Envelope encryption for secrets at rest (signing keys, IdP client secrets,
//! SMTP passwords, ...).
//!
//! The default implementation (in the server) uses ChaCha20-Poly1305 with a
//! master key from the environment or a mounted file. KMS / HSM backends
//! implement the same trait behind optional cargo features.

use async_trait::async_trait;
use zeroize::Zeroizing;

/// Format version of the serialized [`Encrypted`] blob.
const BLOB_FORMAT_V1: u8 = 1;

/// A ciphertext together with the master-key generation that produced it, so
/// that master-key rotation can re-encrypt rows incrementally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypted {
    /// Master key generation (see [`KeyEncryptor::current_version`]).
    pub key_version: u32,
    /// Backend-specific nonce / IV (empty for backends that manage it themselves).
    pub nonce: Vec<u8>,
    /// Ciphertext including any authentication tag.
    pub ciphertext: Vec<u8>,
}

impl Encrypted {
    /// Serialize to the on-disk layout stored in `*_enc bytea` columns:
    /// `format(1) || key_version(4, BE) || nonce_len(1) || nonce || ciphertext`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + self.nonce.len() + self.ciphertext.len());
        out.push(BLOB_FORMAT_V1);
        out.extend_from_slice(&self.key_version.to_be_bytes());
        out.push(self.nonce.len() as u8);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, super::ProviderError> {
        let err = || super::ProviderError::Rejected("malformed encrypted blob".into());
        if bytes.len() < 6 || bytes[0] != BLOB_FORMAT_V1 {
            return Err(err());
        }
        let key_version = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let nonce_len = bytes[5] as usize;
        let rest = &bytes[6..];
        if rest.len() < nonce_len {
            return Err(err());
        }
        Ok(Self {
            key_version,
            nonce: rest[..nonce_len].to_vec(),
            ciphertext: rest[nonce_len..].to_vec(),
        })
    }
}

#[async_trait]
pub trait KeyEncryptor: Send + Sync {
    /// Master key generation used for new encryptions. Rows whose
    /// `key_version` is older are candidates for re-encryption.
    fn current_version(&self) -> u32;

    /// Encrypt `plaintext`, binding it to `aad` (typically the row's table name
    /// and id so a ciphertext cannot be moved between rows).
    async fn encrypt(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Encrypted, super::ProviderError>;

    /// Decrypt with the key generation recorded in `encrypted`.
    async fn decrypt(
        &self,
        encrypted: &Encrypted,
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, super::ProviderError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_round_trips() {
        let e = Encrypted {
            key_version: 7,
            nonce: vec![1, 2, 3],
            ciphertext: vec![9; 40],
        };
        assert_eq!(Encrypted::from_bytes(&e.to_bytes()).unwrap(), e);
        assert!(Encrypted::from_bytes(&[]).is_err());
        assert!(Encrypted::from_bytes(&[2, 0, 0, 0, 1, 0]).is_err());
    }
}
