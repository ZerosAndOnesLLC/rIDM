//! Key custody: an HSM or a key-management service that wraps the data keys
//! the [`KeyEncryptor`](super::KeyEncryptor) encrypts secrets with.
//!
//! This is envelope encryption. Each master-key generation is a random data
//! key; the custody backend encrypts ("wraps") it once, the wrapped form is
//! stored, and each node asks the backend to unwrap it when it starts. Rows are
//! then encrypted locally, so a token request or a TOTP check never waits on
//! the HSM or pays for a KMS call, and a backend outage stops only the start of
//! new nodes.

use async_trait::async_trait;
use zeroize::Zeroizing;

/// A data key as the custody backend returned it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedKey {
    /// Which backend key wrapped it (an ARN, a key label, a Key Vault key
    /// id...), as [`KeyWrapper::unwrap`] needs it back. Stored with the
    /// generation, so changing the configured key later leaves older
    /// generations readable.
    pub key_ref: String,
    /// The backend's ciphertext, opaque to rIDM.
    pub wrapped: Vec<u8>,
}

#[async_trait]
pub trait KeyWrapper: Send + Sync {
    /// Stable backend name stored with every generation it wraps
    /// (`pkcs11`, `aws-kms`, `vault`, `gcp-kms`, `azure-key-vault`).
    fn backend(&self) -> &'static str;

    /// Wrap `key`, binding it to `context` where the backend supports
    /// additional authenticated data (it identifies the generation, so a
    /// wrapped key cannot be passed off as another generation's).
    async fn wrap(&self, key: &[u8], context: &[u8]) -> Result<WrappedKey, super::ProviderError>;

    /// Unwrap what [`wrap`](Self::wrap) returned, with the same `context`.
    async fn unwrap(
        &self,
        key_ref: &str,
        wrapped: &[u8],
        context: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, super::ProviderError>;
}
