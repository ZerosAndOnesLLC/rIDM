//! The RFC 3962 AES encryption types (`aes128-cts-hmac-sha1-96`,
//! `aes256-cts-hmac-sha1-96`), from `picky-krb` when rIDM is built with
//! the `kerberos` feature. Without it every operation says so, and nothing
//! else in the acceptor needs to know.

use super::keytab::etype_supported;

/// This build can accept Kerberos tickets.
pub const AVAILABLE: bool = cfg!(feature = "kerberos");

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("this build of rIDM has no Kerberos support (the `kerberos` feature)")]
    Unavailable,
    #[error("encryption type {0} is not supported")]
    Etype(i32),
    /// Wrong key, or the ciphertext was changed.
    #[error("integrity check failed")]
    Integrity,
}

#[cfg(feature = "kerberos")]
fn cipher(etype: i32) -> Result<Box<dyn picky_krb::crypto::Cipher>, CryptoError> {
    use picky_krb::crypto::CipherSuite;
    match etype {
        17 => Ok(CipherSuite::Aes128CtsHmacSha196.cipher()),
        18 => Ok(CipherSuite::Aes256CtsHmacSha196.cipher()),
        other => Err(CryptoError::Etype(other)),
    }
}

/// Decrypt and check the integrity of `data` under `key` for `usage`.
#[cfg(feature = "kerberos")]
pub fn decrypt(etype: i32, key: &[u8], usage: i32, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if !etype_supported(etype) {
        return Err(CryptoError::Etype(etype));
    }
    let c = cipher(etype)?;
    if key.len() != c.key_size() {
        return Err(CryptoError::Integrity);
    }
    c.decrypt(key, usage, data)
        .map_err(|_| CryptoError::Integrity)
}

#[cfg(not(feature = "kerberos"))]
pub fn decrypt(etype: i32, _: &[u8], _: i32, _: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if !etype_supported(etype) {
        return Err(CryptoError::Etype(etype));
    }
    Err(CryptoError::Unavailable)
}

/// Encrypt `data` under `key` for `usage` (a fresh confounder each time).
#[cfg(feature = "kerberos")]
pub fn encrypt(etype: i32, key: &[u8], usage: i32, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if !etype_supported(etype) {
        return Err(CryptoError::Etype(etype));
    }
    let c = cipher(etype)?;
    if key.len() != c.key_size() {
        return Err(CryptoError::Integrity);
    }
    c.encrypt(key, usage, data)
        .map_err(|_| CryptoError::Integrity)
}

#[cfg(not(feature = "kerberos"))]
pub fn encrypt(etype: i32, _: &[u8], _: i32, _: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if !etype_supported(etype) {
        return Err(CryptoError::Etype(etype));
    }
    Err(CryptoError::Unavailable)
}

#[cfg(all(test, feature = "kerberos"))]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper() {
        for (etype, len) in [(17, 16), (18, 32)] {
            let key = vec![9u8; len];
            let c = encrypt(etype, &key, 2, b"hello ticket").unwrap();
            assert_eq!(decrypt(etype, &key, 2, &c).unwrap(), b"hello ticket");
            assert_eq!(decrypt(etype, &key, 11, &c), Err(CryptoError::Integrity));
            let mut t = c.clone();
            let last = t.len() - 1;
            t[last] ^= 1;
            assert_eq!(decrypt(etype, &key, 2, &t), Err(CryptoError::Integrity));
            assert_eq!(
                decrypt(etype, &key, 2, &c[..5]),
                Err(CryptoError::Integrity)
            );
            assert_eq!(
                decrypt(etype, &key[..8], 2, &c),
                Err(CryptoError::Integrity)
            );
        }
        assert_eq!(decrypt(23, &[0; 16], 2, b"x"), Err(CryptoError::Etype(23)));
    }
}
