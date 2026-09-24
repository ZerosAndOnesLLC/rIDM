//! Kerberos / SPNEGO: the pieces of desktop single sign-on that are
//! protocol, not policy. HTTP Negotiate tokens ([`spnego`]), the ticket
//! acceptor ([`Acceptor`]) on a small bounds-checked DER reader ([`der`]),
//! keytab files and principal names. The AES encryption comes from
//! `picky-krb` behind the `kerberos` cargo feature ([`crypto`]); without it
//! everything parses and nothing is accepted. Who a principal is in rIDM,
//! the replay cache and the login flow are [`crate::services::kerberos`].

mod acceptor;
pub mod crypto;
pub mod der;
mod keytab;
mod principal;
pub mod spnego;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;

pub use acceptor::*;
pub use keytab::*;
pub use principal::*;
