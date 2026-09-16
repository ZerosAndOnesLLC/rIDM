//! In-memory providers for tests. Enabled with the `test-support` feature.
//!
//! Mocks capture what was sent so tests assert on content (links, codes)
//! instead of sleeping or polling. None of them is secure; never use outside
//! tests.

mod breach;
mod captcha;
mod email;
mod events;
mod key_encryptor;
mod sms;

pub use breach::*;
pub use captcha::*;
pub use email::*;
pub use events::*;
pub use key_encryptor::*;
pub use sms::*;
