//! Shared types, provider traits and event definitions for rIDM.
//!
//! This crate is dependency-light so that it can be reused by the `ridm-cli`
//! and `ridm-auth` crates without pulling in the whole server.
//!
//! * [`providers`]: pluggable backends (`KeyEncryptor`, `EmailSender`,
//!   `SmsSender`, `Captcha`, `PasswordHasher`). The server ships default
//!   implementations that need nothing cloud-specific; optional backends (KMS,
//!   HSM, SaaS mailers) implement the same traits behind cargo features.
//! * [`events`]: the typed internal event bus that feeds audit, webhooks,
//!   notifications and cache invalidation from a single emit point.
//! * [`audit_chain`]: the audit log's hash chain, so a tool can check an
//!   export without trusting the server that wrote it.

pub mod audit_chain;
pub mod events;
pub mod providers;
#[cfg(feature = "test-support")]
pub mod test_support;
