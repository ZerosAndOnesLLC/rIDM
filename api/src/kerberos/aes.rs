//! The Kerberos AES encryption types on aws-lc-rs (the AWS-LC FIPS module in
//! the FIPS build):
//!
//! | etype | name | RFC | key derivation | integrity |
//! |---|---|---|---|---|
//! | 17 | aes128-cts-hmac-sha1-96 | 3962 | RFC 3961 DK (n-fold, AES) | HMAC-SHA1-96 over the plaintext |
//! | 18 | aes256-cts-hmac-sha1-96 | 3962 | RFC 3961 DK (n-fold, AES) | HMAC-SHA1-96 over the plaintext |
//! | 19 | aes128-cts-hmac-sha256-128 | 8009 | SP 800-108 counter mode, HMAC-SHA256 | HMAC-SHA256-128 over IV and ciphertext |
//! | 20 | aes256-cts-hmac-sha384-192 | 8009 | SP 800-108 counter mode, HMAC-SHA384 | HMAC-SHA384-192 over IV and ciphertext |
//!
//! All four encrypt a 16-byte random confounder and the plaintext with AES
//! in CBC mode with ciphertext stealing (the last two blocks swapped, RFC
//! 3962 §5) under a zero IV. rIDM's keys come from keytabs, so no
//! string-to-key is needed.

use aws_lc_rs::cipher::{
    AES_128, AES_256, DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext,
    UnboundCipherKey,
};
use aws_lc_rs::hmac;
use aws_lc_rs::iv::FixedLength;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

const BLOCK: usize = 16;
const CONFOUNDER_LEN: usize = BLOCK;

/// One encryption type's parameters.
#[derive(Clone, Copy)]
pub(super) struct Profile {
    key_len: usize,
    kind: Kind,
}

#[derive(Clone, Copy)]
enum Kind {
    /// RFC 3962: DK key derivation, HMAC-SHA1 truncated to 96 bits.
    Sha1,
    /// RFC 8009: the SP 800-108 KDF and HMAC with this hash, `ki_len`-byte
    /// integrity key and `tag_len`-byte checksum.
    Sha2 {
        alg: hmac::Algorithm,
        ki_len: usize,
        tag_len: usize,
    },
}

/// The two keys one usage derives from the base key.
struct UsageKeys {
    /// Encryption (`Ke`).
    ke: Zeroizing<Vec<u8>>,
    /// Integrity (`Ki`).
    ki: Zeroizing<Vec<u8>>,
}

/// Why an operation failed: only a bad length or a failed integrity check,
/// so nothing about the key or the plaintext leaks through the error.
#[derive(Debug)]
pub(super) struct Failed;

impl Profile {
    pub(super) fn of(etype: i32) -> Option<Self> {
        let sha2 = |key_len, alg, ki_len, tag_len| Self {
            key_len,
            kind: Kind::Sha2 {
                alg,
                ki_len,
                tag_len,
            },
        };
        Some(match etype {
            17 => Self {
                key_len: 16,
                kind: Kind::Sha1,
            },
            18 => Self {
                key_len: 32,
                kind: Kind::Sha1,
            },
            19 => sha2(16, hmac::HMAC_SHA256, 16, 16),
            20 => sha2(32, hmac::HMAC_SHA384, 24, 24),
            _ => return None,
        })
    }

    pub(super) fn key_len(&self) -> usize {
        self.key_len
    }

    fn tag_len(&self) -> usize {
        match self.kind {
            Kind::Sha1 => 12,
            Kind::Sha2 { tag_len, .. } => tag_len,
        }
    }

    /// `Ke` and `Ki` for `usage` (RFC 3961 §5.3 constants `usage‖0xAA` and
    /// `usage‖0x55`).
    fn keys(&self, base: &[u8], usage: i32) -> Result<UsageKeys, Failed> {
        let constant = |suffix: u8| {
            let mut c = usage.to_be_bytes().to_vec();
            c.push(suffix);
            c
        };
        match self.kind {
            Kind::Sha1 => Ok(UsageKeys {
                ke: dk(base, &constant(0xAA), self.key_len)?,
                ki: dk(base, &constant(0x55), self.key_len)?,
            }),
            Kind::Sha2 { alg, ki_len, .. } => Ok(UsageKeys {
                ke: kdf_hmac_sha2(alg, base, &constant(0xAA), self.key_len),
                ki: kdf_hmac_sha2(alg, base, &constant(0x55), ki_len),
            }),
        }
    }

    pub(super) fn encrypt(&self, key: &[u8], usage: i32, data: &[u8]) -> Result<Vec<u8>, Failed> {
        let confounder: [u8; CONFOUNDER_LEN] = ridm_core::crypto::random_bytes();
        self.encrypt_with(key, usage, &confounder, data)
    }

    fn encrypt_with(
        &self,
        key: &[u8],
        usage: i32,
        confounder: &[u8; CONFOUNDER_LEN],
        data: &[u8],
    ) -> Result<Vec<u8>, Failed> {
        if key.len() != self.key_len {
            return Err(Failed);
        }
        let UsageKeys { ke, ki } = self.keys(key, usage)?;
        let mut plain = Zeroizing::new(Vec::with_capacity(CONFOUNDER_LEN + data.len()));
        plain.extend_from_slice(confounder);
        plain.extend_from_slice(data);
        let mut out = cts_encrypt(&ke, &plain)?;
        let tag = match self.kind {
            Kind::Sha1 => hmac_parts(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &ki, &[&plain]),
            Kind::Sha2 { alg, .. } => hmac_parts(alg, &ki, &[&[0u8; BLOCK], &out]),
        };
        out.extend_from_slice(&tag[..self.tag_len()]);
        Ok(out)
    }

    pub(super) fn decrypt(&self, key: &[u8], usage: i32, data: &[u8]) -> Result<Vec<u8>, Failed> {
        let tag_len = self.tag_len();
        if key.len() != self.key_len || data.len() < CONFOUNDER_LEN + tag_len {
            return Err(Failed);
        }
        let UsageKeys { ke, ki } = self.keys(key, usage)?;
        let (cipher, tag) = data.split_at(data.len() - tag_len);
        if let Kind::Sha2 { alg, .. } = self.kind {
            // Encrypt-then-MAC: check before decrypting anything.
            let expected = hmac_parts(alg, &ki, &[&[0u8; BLOCK], cipher]);
            if !bool::from(expected[..tag_len].ct_eq(tag)) {
                return Err(Failed);
            }
        }
        let plain = Zeroizing::new(cts_decrypt(&ke, cipher)?);
        if let Kind::Sha1 = self.kind {
            let expected = hmac_parts(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &ki, &[&plain]);
            if !bool::from(expected[..tag_len].ct_eq(tag)) {
                return Err(Failed);
            }
        }
        Ok(plain[CONFOUNDER_LEN..].to_vec())
    }
}

fn hmac_parts(alg: hmac::Algorithm, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let key = hmac::Key::new(alg, key);
    let mut ctx = hmac::Context::with_key(&key);
    for p in parts {
        ctx.update(p);
    }
    ctx.sign().as_ref().to_vec()
}

fn cipher_key(key: &[u8]) -> Result<UnboundCipherKey, Failed> {
    let alg = match key.len() {
        16 => &AES_128,
        32 => &AES_256,
        _ => return Err(Failed),
    };
    UnboundCipherKey::new(alg, key).map_err(|_| Failed)
}

/// AES of whole blocks in ECB mode (each block on its own).
fn ecb_encrypt(key: &[u8], blocks: &mut [u8]) -> Result<(), Failed> {
    EncryptingKey::ecb(cipher_key(key)?)
        .and_then(|k| k.less_safe_encrypt(blocks, EncryptionContext::None))
        .map(|_| ())
        .map_err(|_| Failed)
}

fn ecb_decrypt(key: &[u8], blocks: &mut [u8]) -> Result<(), Failed> {
    DecryptingKey::ecb(cipher_key(key)?)
        .and_then(|k| k.decrypt(blocks, DecryptionContext::None).map(|_| ()))
        .map_err(|_| Failed)
}

fn zero_iv() -> FixedLength<16> {
    FixedLength::from([0u8; BLOCK])
}

/// AES-CBC of whole blocks under a zero IV.
fn cbc_encrypt(key: &[u8], blocks: &mut [u8]) -> Result<(), Failed> {
    EncryptingKey::cbc(cipher_key(key)?)
        .and_then(|k| k.less_safe_encrypt(blocks, EncryptionContext::Iv128(zero_iv())))
        .map(|_| ())
        .map_err(|_| Failed)
}

fn cbc_decrypt(key: &[u8], blocks: &mut [u8]) -> Result<(), Failed> {
    DecryptingKey::cbc(cipher_key(key)?)
        .and_then(|k| {
            k.decrypt(blocks, DecryptionContext::Iv128(zero_iv()))
                .map(|_| ())
        })
        .map_err(|_| Failed)
}

/// CBC with ciphertext stealing, zero IV, at least one block: encrypt the
/// zero-padded input, then swap the last two blocks and cut the (new) last
/// one to the length of the input's partial block.
fn cts_encrypt(key: &[u8], plain: &[u8]) -> Result<Vec<u8>, Failed> {
    let len = plain.len();
    if len < BLOCK {
        return Err(Failed);
    }
    let blocks = len.div_ceil(BLOCK);
    let mut buf = plain.to_vec();
    buf.resize(blocks * BLOCK, 0);
    cbc_encrypt(key, &mut buf)?;
    if blocks == 1 {
        return Ok(buf);
    }
    let tail = len - (blocks - 1) * BLOCK; // 1..=16 bytes of the last block
    let (head, last_two) = buf.split_at(BLOCK * (blocks - 2));
    let mut out = head.to_vec();
    out.extend_from_slice(&last_two[BLOCK..]);
    out.extend_from_slice(&last_two[..tail]);
    Ok(out)
}

fn cts_decrypt(key: &[u8], cipher: &[u8]) -> Result<Vec<u8>, Failed> {
    let len = cipher.len();
    if len < BLOCK {
        return Err(Failed);
    }
    let blocks = len.div_ceil(BLOCK);
    if blocks == 1 {
        let mut buf = cipher.to_vec();
        cbc_decrypt(key, &mut buf)?;
        return Ok(buf);
    }
    let tail = len - (blocks - 1) * BLOCK;
    let head = &cipher[..BLOCK * (blocks - 2)];
    // What CBC called the last block, then the start of the one before it.
    let last = &cipher[BLOCK * (blocks - 2)..BLOCK * (blocks - 1)];
    let partial = &cipher[BLOCK * (blocks - 1)..];
    let mut x = last.to_vec();
    ecb_decrypt(key, &mut x)?;
    // The padded last plaintext block is zeros past `tail`, so those bytes
    // of the decrypted block are the stolen end of the block before it.
    let mut before_last = partial.to_vec();
    before_last.extend_from_slice(&x[tail..]);
    let last_plain: Vec<u8> = x[..tail]
        .iter()
        .zip(&before_last[..tail])
        .map(|(a, b)| a ^ b)
        .collect();
    let mut buf = head.to_vec();
    buf.extend_from_slice(&before_last);
    cbc_decrypt(key, &mut buf)?;
    buf.extend_from_slice(&last_plain);
    Ok(buf)
}

/// RFC 3961 §5.3 DK: random-to-key (identity for AES) of DR, the AES
/// encryption of the n-folded constant, chained until `len` bytes.
fn dk(base: &[u8], constant: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>, Failed> {
    let mut block = nfold(constant, BLOCK);
    let mut out = Zeroizing::new(Vec::with_capacity(len + BLOCK));
    while out.len() < len {
        ecb_encrypt(base, &mut block)?;
        out.extend_from_slice(&block);
    }
    out.truncate(len);
    Ok(out)
}

/// RFC 8009 §3 KDF-HMAC-SHA2: SP 800-108 in counter mode with HMAC, one
/// 32-bit counter, the label, a zero byte and the output length in bits.
fn kdf_hmac_sha2(alg: hmac::Algorithm, key: &[u8], label: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let bits = u32::try_from(len * 8).expect("a key length").to_be_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(len + 64));
    let mut counter: u32 = 1;
    while out.len() < len {
        out.extend_from_slice(&hmac_parts(
            alg,
            key,
            &[&counter.to_be_bytes(), label, &[0], &bits],
        ));
        counter += 1;
    }
    out.truncate(len);
    out
}

/// RFC 3961 §5.1 n-fold: `out_len` bytes from `input`, by summing (with
/// end-around carry) copies of it, each rotated 13 bits further right, over
/// the least common multiple of the two lengths.
fn nfold(input: &[u8], out_len: usize) -> Vec<u8> {
    let in_len = input.len();
    let lcm = out_len / gcd(out_len, in_len) * in_len;
    let in_bits = in_len * 8;
    let mut out = vec![0u8; out_len];
    let mut carry: u32 = 0;
    for i in (0..lcm).rev() {
        // The bit of the rotated input that byte i of the stream starts at.
        let msbit =
            ((in_bits - 1) + (in_bits + 13) * (i / in_len) + (in_len - i % in_len) * 8) % in_bits;
        let hi = u32::from(input[(in_len - 1 - (msbit >> 3)) % in_len]);
        let lo = u32::from(input[(in_len - (msbit >> 3)) % in_len]);
        carry += (((hi << 8) | lo) >> ((msbit & 7) + 1)) & 0xff;
        carry += u32::from(out[i % out_len]);
        out[i % out_len] = (carry & 0xff) as u8;
        carry >>= 8;
    }
    // End-around carry.
    while carry != 0 {
        for byte in out.iter_mut().rev() {
            carry += u32::from(*byte);
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
    }
    out
}

fn gcd(a: usize, b: usize) -> usize {
    if b == 0 { a } else { gcd(b, a % b) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    /// RFC 3961 appendix A.1.
    #[test]
    fn nfold_matches_rfc_3961() {
        for (bits, input, expected) in [
            (64, "012345", "be072631276b1955"),
            (56, "password", "78a07b6caf85fa"),
            (64, "Rough Consensus, and Running Code", "bb6ed30870b7f0e0"),
            (
                168,
                "password",
                "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e",
            ),
            (
                192,
                "MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
                "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b",
            ),
            (168, "Q", "518a54a215a8452a518a54a215a8452a518a54a215"),
            (64, "kerberos", "6b65726265726f73"),
            (128, "kerberos", "6b65726265726f737b9b5b2b93132b93"),
            (
                256,
                "kerberos",
                "6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4",
            ),
        ] {
            assert_eq!(
                hex::encode(nfold(input.as_bytes(), bits / 8)),
                expected,
                "{bits}-fold {input:?}"
            );
        }
    }

    /// RFC 3962 appendix B: AES-128 CTS under a zero IV, every edge of the
    /// stealing (17 bytes, two blocks less one, exactly two, three).
    #[test]
    fn cts_matches_rfc_3962() {
        let key = h("636869636b656e207465726979616b69");
        let plain = h(
            "4920776f756c64206c696b652074686520 47656e6572616c20476175277320436869 636b656e2c20706c656173652c20616e 6420776f6e746f6e20736f75702e",
        );
        for (len, expected) in [
            (17, "c6353568f2bf8cb4d8a580362da7ff7f97"),
            (
                31,
                "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5",
            ),
            (
                32,
                "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584",
            ),
            (
                47,
                "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5",
            ),
            (
                48,
                "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8",
            ),
            (
                64,
                "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8",
            ),
        ] {
            let c = cts_encrypt(&key, &plain[..len]).unwrap();
            assert_eq!(hex::encode(&c), expected, "{len} bytes");
            assert_eq!(
                cts_decrypt(&key, &c).unwrap(),
                plain[..len],
                "{len} bytes back"
            );
        }
    }

    /// RFC 8009 appendix A: key derivation for usage 2.
    #[test]
    fn rfc_8009_key_derivation() {
        let base19 = h("3705d96080c17728a0e800eab6e0d23c");
        let UsageKeys { ke, ki } = Profile::of(19).unwrap().keys(&base19, 2).unwrap();
        assert_eq!(hex::encode(&*ke), "9b197dd1e8c5609d6e67c3e37c62c72e");
        assert_eq!(hex::encode(&*ki), "9fda0e56ab2d85e1569a688696c26a6c");
        let base20 = h("6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52");
        let UsageKeys { ke, ki } = Profile::of(20).unwrap().keys(&base20, 2).unwrap();
        assert_eq!(
            hex::encode(&*ke),
            "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49"
        );
        assert_eq!(
            hex::encode(&*ki),
            "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f"
        );
    }

    /// RFC 8009 appendix A: encryption with a known confounder.
    #[test]
    fn rfc_8009_encryption() {
        let base19 = h("3705d96080c17728a0e800eab6e0d23c");
        let conf: [u8; 16] = h("7e5895eaf2672435bad817f545a37148").try_into().unwrap();
        let p = Profile::of(19).unwrap();
        let c = p.encrypt_with(&base19, 2, &conf, b"").unwrap();
        assert_eq!(
            hex::encode(&c),
            "ef85fb890bb8472f4dab20394dca781dad877eda39d50c870c0d5a0a8e48c718"
        );
        assert_eq!(p.decrypt(&base19, 2, &c).unwrap(), b"");
    }

    /// picky-krb (RustCrypto), which rIDM used before, reads what this
    /// writes and the other way round, for RFC 3962's types.
    #[test]
    fn rfc_3962_types_interoperate_with_picky_krb() {
        use picky_krb::crypto::CipherSuite;
        for (etype, suite, len) in [
            (17, CipherSuite::Aes128CtsHmacSha196, 16),
            (18, CipherSuite::Aes256CtsHmacSha196, 32),
        ] {
            let ours = Profile::of(etype).unwrap();
            let theirs = suite.cipher();
            let key: Vec<u8> = (0..len as u8).collect();
            for (usage, msg) in [
                (2, &b"a service ticket"[..]),
                (11, b""),
                (12, b"x".as_slice()),
            ] {
                let c = ours.encrypt(&key, usage, msg).unwrap();
                assert_eq!(
                    theirs.decrypt(&key, usage, &c).unwrap(),
                    msg,
                    "picky reads ours"
                );
                let c = theirs.encrypt(&key, usage, msg).unwrap();
                assert_eq!(
                    ours.decrypt(&key, usage, &c).unwrap(),
                    msg,
                    "we read picky's"
                );
            }
        }
    }

    #[test]
    fn every_etype_round_trips_and_detects_tampering() {
        for (etype, len) in [(17, 16), (18, 32), (19, 16), (20, 32)] {
            let p = Profile::of(etype).unwrap();
            let key = vec![9u8; len];
            for msg in [
                &b""[..],
                b"x",
                b"exactly sixteen!",
                b"a ticket of some forty-odd bytes, say",
            ] {
                let c = p.encrypt(&key, 2, msg).unwrap();
                assert_eq!(p.decrypt(&key, 2, &c).unwrap(), msg, "etype {etype}");
                assert!(p.decrypt(&key, 11, &c).is_err(), "usage is bound");
                for i in [0, c.len() / 2, c.len() - 1] {
                    let mut t = c.clone();
                    t[i] ^= 1;
                    assert!(p.decrypt(&key, 2, &t).is_err(), "etype {etype} byte {i}");
                }
                assert!(p.decrypt(&key, 2, &c[..c.len() - 1]).is_err());
            }
            assert!(p.decrypt(&key[..8], 2, &[0; 40]).is_err());
        }
        assert!(Profile::of(23).is_none());
    }
}
