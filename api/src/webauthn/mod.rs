//! Passkeys (WebAuthn): rIDM's own relying party on aws-lc-rs (the AWS-LC
//! FIPS module in the FIPS build), compatible with what webauthn-rs, which
//! it replaces, stored and sent. The wire types come from
//! `webauthn-rs-proto`, which is serde types only.

mod cbor;
mod ceremony;
mod cose;
mod stored;

pub use ceremony::*;
pub use stored::{Assertion, StoredPasskey};
