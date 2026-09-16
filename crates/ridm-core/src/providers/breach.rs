use async_trait::async_trait;
use sha1::{Digest as _, Sha1};

/// Tells how often a password appears in breach corpora, given only its
/// SHA-1 (the k-anonymity scheme Have I Been Pwned popularised: the
/// implementation sends the first five hex digits and matches the rest
/// locally, so no backend ever sees the password or its full hash).
#[async_trait]
pub trait BreachChecker: Send + Sync {
    /// Occurrences of the password whose upper-case SHA-1 hex is `sha1_hex`;
    /// zero when it is unknown to the corpus.
    async fn count(&self, sha1_hex: &str) -> Result<u64, super::ProviderError>;
}

/// Upper-case SHA-1 hex of a password, the form breach checkers work on.
pub fn password_sha1_hex(password: &str) -> String {
    let digest = Sha1::digest(password.as_bytes());
    let mut out = String::with_capacity(40);
    for b in digest {
        out.push_str(&format!("{b:02X}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_matches_the_known_vector() {
        // The HIBP documentation's example.
        assert_eq!(
            password_sha1_hex("password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
    }
}
