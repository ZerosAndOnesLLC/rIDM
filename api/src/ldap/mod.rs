//! LDAP / Active Directory: the client rIDM uses as an upstream directory
//! (connection over TLS through the SSRF-checked resolver, bind, search,
//! paged search, modify, password writes), filter building with escaping,
//! and a panic-free reader for search entries. The directory's policy
//! (who signs in, sync, write-back) is [`crate::services::ldap`].

mod client;
mod entry;
mod filter;

pub use client::*;
pub use entry::*;
pub use filter::*;
