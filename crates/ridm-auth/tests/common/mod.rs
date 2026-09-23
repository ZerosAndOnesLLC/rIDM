//! A stand-in rIDM tenant: a discovery document, a key set that can be rotated
//! or taken away, and a count of how often the key set was asked for.

// Each test binary compiles the whole harness and uses part of it.
#![allow(dead_code)]

mod issuer;
pub use issuer::*;
