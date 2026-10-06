//! Envelope encryption for secrets at rest (signing keys, IdP client secrets,
//! SMTP passwords, ...).
//!
//! The default implementation (in the server) uses AES-256-GCM under a key
//! derived per message from a master-key generation, which comes from the
//! environment or a key custody backend (HSM or KMS, behind optional cargo
//! features). Blobs written before that are XChaCha20-Poly1305.

use async_trait::async_trait;
use zeroize::Zeroizing;

/// The cipher a blob was sealed with: its first byte on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// XChaCha20-Poly1305 under the generation key, a 24-byte nonce.
    XChaCha20Poly1305 = 1,
    /// AES-256-GCM under a key derived per message with HKDF-SHA-256 from
    /// the generation key and a random salt. The nonce field holds the salt
    /// (32 bytes) then the GCM IV (12 bytes).
    Aes256GcmHkdf = 2,
}

impl Cipher {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::XChaCha20Poly1305),
            2 => Some(Self::Aes256GcmHkdf),
            _ => None,
        }
    }
}

/// A ciphertext together with the master-key generation that produced it, so
/// that master-key rotation can re-encrypt rows incrementally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypted {
    pub cipher: Cipher,
    /// Master key generation (see [`KeyEncryptor::current_version`]).
    pub key_version: u32,
    /// Backend-specific nonce / IV (empty for backends that manage it themselves).
    pub nonce: Vec<u8>,
    /// Ciphertext including any authentication tag.
    pub ciphertext: Vec<u8>,
}

impl Encrypted {
    /// Serialize to the on-disk layout stored in `*_enc bytea` columns:
    /// `cipher(1) || key_version(4, BE) || nonce_len(1) || nonce || ciphertext`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + self.nonce.len() + self.ciphertext.len());
        out.push(self.cipher as u8);
        out.extend_from_slice(&self.key_version.to_be_bytes());
        out.push(self.nonce.len() as u8);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, super::ProviderError> {
        let err = || super::ProviderError::Rejected("malformed encrypted blob".into());
        if bytes.len() < 6 {
            return Err(err());
        }
        let cipher = Cipher::from_byte(bytes[0]).ok_or_else(err)?;
        let key_version = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let nonce_len = bytes[5] as usize;
        let rest = &bytes[6..];
        if rest.len() < nonce_len {
            return Err(err());
        }
        Ok(Self {
            cipher,
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

    /// Generations this encryptor can decrypt, if it knows (for status output).
    fn known_versions_hint(&self) -> Option<Vec<u32>> {
        None
    }

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
        for cipher in [Cipher::XChaCha20Poly1305, Cipher::Aes256GcmHkdf] {
            let e = Encrypted {
                cipher,
                key_version: 7,
                nonce: vec![1, 2, 3],
                ciphertext: vec![9; 40],
            };
            let bytes = e.to_bytes();
            assert_eq!(bytes[0], cipher as u8);
            assert_eq!(Encrypted::from_bytes(&bytes).unwrap(), e);
        }
        assert!(Encrypted::from_bytes(&[]).is_err());
        assert!(Encrypted::from_bytes(&[3, 0, 0, 0, 1, 0]).is_err());
    }
}
