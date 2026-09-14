//! Password hashing. The trait is synchronous because hashing is CPU-bound;
//! the server calls it through `spawn_blocking`.

use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordVerification {
    pub valid: bool,
    /// The stored hash uses a legacy algorithm or weaker parameters and should
    /// be replaced with a fresh hash now that the plaintext is known.
    pub needs_rehash: bool,
}

pub trait PasswordHasher: Send + Sync {
    /// Identifier stored in `users.password_algo` (e.g. `argon2id`).
    fn algorithm(&self) -> &'static str;

    /// Hash a plaintext password with the current algorithm and parameters.
    fn hash(&self, password: &Zeroizing<String>) -> Result<String, super::ProviderError>;

    /// Verify a plaintext against a stored hash. Must handle every algorithm
    /// the deployment accepts (current plus legacy imports) and report whether
    /// the hash should be upgraded.
    fn verify(
        &self,
        password: &Zeroizing<String>,
        stored_hash: &str,
    ) -> Result<PasswordVerification, super::ProviderError>;
}
