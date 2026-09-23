//! Key custody: who holds the master key that encrypts secrets at rest.
//!
//! By default the environment does (`MASTER_KEY`). With `KEY_WRAPPER` an HSM
//! (PKCS#11) or a key-management service (AWS KMS, Vault / OpenBao Transit,
//! Google Cloud KMS, Azure Key Vault) does instead: each master-key
//! generation is a random data key the backend wrapped, stored in
//! `master_key_generations` and unwrapped by each node at start-up
//! ([`EnvelopeEncryptor`]). Each backend is an optional cargo feature.

#[cfg(feature = "kms-aws")]
pub mod aws_kms;
#[cfg(feature = "kms-azure")]
pub mod azure_kv;
pub mod config;
mod envelope;
#[cfg(feature = "kms-gcp")]
pub mod gcp_kms;
pub mod generations;
#[cfg(any(feature = "kms-vault", feature = "kms-gcp", feature = "kms-azure"))]
mod http;
mod lifecycle;
#[cfg(feature = "hsm-pkcs11")]
pub mod pkcs11;
#[cfg(feature = "kms-vault")]
pub mod vault;
pub mod wrappers;

pub use config::{Backend, KeyCustodyConfig};
pub use envelope::*;
pub use lifecycle::*;
