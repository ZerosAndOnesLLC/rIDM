//! Validate [rIDM](https://github.com/ZerosAndOnesLLC/rIDM) access tokens in a
//! Rust API.
//!
//! rIDM issues signed JWT access tokens. A resource server that accepts them
//! has to verify the signature against the issuer's published keys, check that
//! the token was meant for *it* and not for some other API of the same tenant,
//! and then decide whether the subject may do what it is asking. This crate is
//! those three steps, and nothing else.
//!
//! ```no_run
//! # async fn f() -> Result<(), ridm_auth::AuthError> {
//! use ridm_auth::Validator;
//!
//! let validator = Validator::builder("https://idp.example/t/acme")
//!     .audience("urn:orders")
//!     .discover()
//!     .await?
//!     .shared();
//!
//! let claims = validator.validate("eyJhbGciOi...").await?;
//! claims.require_permission("orders:read")?;
//! println!("{} may read orders", claims.sub);
//! # Ok(()) }
//! ```
//!
//! With the default `axum` feature, [`axum::RidmClaims`] is an extractor and
//! [`axum::guard`] a route middleware; every refusal answers as RFC 6750 says
//! it should.
//!
//! # What it checks
//!
//! Signature against the issuer's JWKS (cached, refreshed when a token names a
//! key the cache has not seen), `typ` is `at+jwt`, `alg` is asymmetric and
//! matches what the key was published for, `iss` is the configured issuer,
//! `aud` names this API, `exp`/`nbf` allowing for clock skew, and the scopes,
//! permissions and roles that were asked for.
//!
//! # What it does not
//!
//! * **Revocation.** A verified token is accepted until it expires. rIDM's
//!   access tokens are short-lived by design; an API that must react to a
//!   revocation sooner should call the introspection endpoint instead.
//! * **DPoP proofs.** A sender-constrained token (`cnf.jkt`) is refused rather
//!   than silently downgraded to a bearer token — see
//!   [`ValidatorBuilder::allow_sender_constrained`].
//! * **Encrypted tokens.** rIDM encrypts ID tokens, never access tokens.
//! * **Getting a token.** This is the resource-server half; a client library
//!   is not part of it.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "axum")]
pub mod axum;
mod claims;
mod error;
mod jwks;
mod validator;

pub use claims::{Claims, Confirmation};
pub use error::{AuthError, Kind};
pub use validator::{ACCESS_TOKEN_TYPE, DEFAULT_ALGORITHMS, Validator, ValidatorBuilder, bearer};

/// Re-exported so a caller can narrow [`ValidatorBuilder::algorithms`] without
/// depending on `jsonwebtoken` directly.
pub use jsonwebtoken::Algorithm;
