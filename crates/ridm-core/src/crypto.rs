//! The hashes, HMAC and random numbers rIDM uses, all from aws-lc-rs: the
//! AWS-LC FIPS module in the FIPS build (docs/src/deploy/fips.md), the same
//! library otherwise. The hash types mirror the RustCrypto API they replace
//! (`Sha256::digest`, `new`/`update`/`finalize`) and return plain arrays.

use aws_lc_rs::digest::{self, Algorithm, Context};
use aws_lc_rs::hmac;
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};

macro_rules! hash {
    ($(#[$doc:meta])* $name:ident, $alg:expr, $len:expr) => {
        $(#[$doc])*
        pub struct $name(Context);

        impl $name {
            /// The digest of `data`.
            pub fn digest(data: impl AsRef<[u8]>) -> [u8; $len] {
                to_array(digest::digest($alg, data.as_ref()).as_ref())
            }

            pub fn new() -> Self {
                Self(Context::new($alg))
            }

            pub fn update(&mut self, data: impl AsRef<[u8]>) {
                self.0.update(data.as_ref());
            }

            pub fn finalize(self) -> [u8; $len] {
                to_array(self.0.finish().as_ref())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

hash!(
    /// SHA-256.
    Sha256,
    &digest::SHA256,
    32
);
hash!(
    /// SHA-384.
    Sha384,
    &digest::SHA384,
    48
);
hash!(
    /// SHA-512.
    Sha512,
    &digest::SHA512,
    64
);
hash!(
    /// SHA-1, for interoperability only (the breach check's k-anonymity
    /// prefix, RFC 6238 defaults). Never for signatures or new designs.
    Sha1,
    LEGACY_SHA1,
    20
);

const LEGACY_SHA1: &Algorithm = &digest::SHA1_FOR_LEGACY_USE_ONLY;

fn to_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes
        .try_into()
        .expect("the digest has its algorithm's length")
}

/// HMAC-SHA-256 of `parts`, concatenated, under `key`.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut ctx = hmac::Context::with_key(&key);
    for part in parts {
        ctx.update(part);
    }
    to_array(ctx.sign().as_ref())
}

/// HMAC under `alg` of `data`, for the algorithms RFC 6238 allows.
pub fn hmac(alg: hmac::Algorithm, key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(alg, key), data)
        .as_ref()
        .to_vec()
}

pub use aws_lc_rs::hmac::{HMAC_SHA1_FOR_LEGACY_USE_ONLY as HMAC_SHA1, HMAC_SHA256, HMAC_SHA512};

/// Fill `buf` from the module's DRBG (SP 800-90A). Panics if the DRBG fails,
/// as `rand::fill` does: there is no safe way to carry on without randomness.
pub fn fill(buf: &mut [u8]) {
    SystemRandom::new()
        .fill(buf)
        .expect("the system random number generator failed");
}

/// `N` random bytes from the module's DRBG, as [`fill`].
pub fn random_bytes<const N: usize>() -> [u8; N] {
    aws_lc_rs::rand::generate(&SystemRandom::new())
        .expect("the system random number generator failed")
        .expose()
}

/// A random `u32` from [`fill`].
pub fn random_u32() -> u32 {
    u32::from_le_bytes(random_bytes())
}

/// A uniformly random index below `n` (`n > 0`), without modulo bias.
pub fn random_below(n: usize) -> usize {
    assert!(n > 0, "random_below(0)");
    let n = n as u64;
    // Reject the top partial range so every value is equally likely.
    let zone = u64::MAX - (u64::MAX % n);
    loop {
        let v = u64::from_le_bytes(random_bytes());
        if v < zone {
            return (v % n) as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_match_the_fips_180_examples() {
        assert_eq!(
            hex::encode(Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(Sha1::digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            &hex::encode(Sha384::digest(b"abc"))[..16],
            "cb00753f45a35e8b"
        );
        assert_eq!(
            &hex::encode(Sha512::digest(b"abc"))[..16],
            "ddaf35a193617aba"
        );
    }

    #[test]
    fn streaming_equals_one_shot() {
        let mut h = Sha256::new();
        h.update(b"a");
        h.update(b"bc");
        assert_eq!(h.finalize(), Sha256::digest(b"abc"));
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_2() {
        let tag = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
        assert_eq!(
            hex::encode(tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn random_values_differ_and_stay_in_range() {
        assert_ne!(random_bytes::<32>(), random_bytes::<32>());
        for _ in 0..1000 {
            assert!(random_below(7) < 7);
        }
        assert_eq!(random_below(1), 0);
    }
}
