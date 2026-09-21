//! SAML 2.0: rIDM's own XML signature, encryption and binding code (no C
//! XML libraries), and the identity-provider protocol on top of it.

pub mod binding;
pub mod c14n;
pub mod cert;
pub mod dsig;
pub mod error;
pub mod ns;
#[cfg(test)]
pub(crate) mod testkit;
pub mod xml;
pub mod xmlenc;
