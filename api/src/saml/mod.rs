//! SAML 2.0: rIDM's own XML signature, encryption and binding code (no C
//! XML libraries), and both protocol sides on top of it: rIDM as the
//! identity provider, and rIDM as the service provider of an upstream IdP.

pub mod binding;
pub mod c14n;
pub mod cert;
pub mod dsig;
pub mod error;
pub mod metadata;
pub mod ns;
pub mod protocol;
pub mod sp;
#[cfg(test)]
pub(crate) mod testkit;
pub mod xml;
pub mod xmlenc;
