//! The rustls crypto provider behind every TLS connection rIDM accepts or
//! makes: rustls' FIPS provider in the `fips` build (AES-GCM suites and the
//! P-256/P-384 groups only, on the AWS-LC FIPS module), the aws-lc-rs default
//! otherwise. Every config rIDM builds takes its provider from here, and
//! [`install`] makes it the process default for the libraries that build
//! their own (reqwest, lettre, redis, the main listener).

use rustls::crypto::CryptoProvider;

/// The provider for this build.
pub fn provider() -> CryptoProvider {
    #[cfg(feature = "fips")]
    {
        rustls::crypto::default_fips_provider()
    }
    #[cfg(not(feature = "fips"))]
    {
        rustls::crypto::aws_lc_rs::default_provider()
    }
}

/// Make [`provider`] the process default. Fails when another provider was
/// installed first.
pub fn install() -> Result<(), &'static str> {
    provider()
        .install_default()
        .map_err(|_| "failed to install the rustls crypto provider")
}

#[cfg(test)]
mod tests {
    use rustls::CipherSuite;

    use super::provider;

    #[test]
    fn the_provider_is_fips_exactly_in_the_fips_build() {
        assert_eq!(provider().fips(), cfg!(feature = "fips"));
    }

    #[test]
    fn chacha20_is_offered_only_outside_the_fips_build() {
        let chacha = provider()
            .cipher_suites
            .iter()
            .any(|s| s.suite() == CipherSuite::TLS13_CHACHA20_POLY1305_SHA256);
        assert_eq!(chacha, !cfg!(feature = "fips"));
    }
}
