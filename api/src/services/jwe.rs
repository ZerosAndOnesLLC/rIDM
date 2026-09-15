//! JWE compact serialization for encrypted ID tokens (OIDC Core §5.1 / RFC 7516).
//!
//! Supported: `alg` RSA-OAEP-256 / RSA-OAEP, `enc` A256GCM / A128GCM.
//! The plaintext is a signed JWT (nested JWS, `cty: "JWT"`).

use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::rsa::{
    OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, OaepPublicEncryptingKey,
    PublicEncryptingKey,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlg {
    RsaOaep256,
    RsaOaep,
}

impl KeyAlg {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "RSA-OAEP-256" => Some(Self::RsaOaep256),
            "RSA-OAEP" => Some(Self::RsaOaep),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RsaOaep256 => "RSA-OAEP-256",
            Self::RsaOaep => "RSA-OAEP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentEnc {
    A256Gcm,
    A128Gcm,
}

impl ContentEnc {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "A256GCM" => Some(Self::A256Gcm),
            "A128GCM" => Some(Self::A128Gcm),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::A256Gcm => "A256GCM",
            Self::A128Gcm => "A128GCM",
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::A256Gcm => 32,
            Self::A128Gcm => 16,
        }
    }

    fn algorithm(self) -> &'static aws_lc_rs::aead::Algorithm {
        match self {
            Self::A256Gcm => &AES_256_GCM,
            Self::A128Gcm => &AES_128_GCM,
        }
    }
}

/// Recipient RSA public key from a JWK (`n`, `e`).
fn rsa_public_from_jwk(jwk: &Value) -> AppResult<PublicEncryptingKey> {
    let n = URL_SAFE_NO_PAD
        .decode(jwk["n"].as_str().unwrap_or_default())
        .map_err(|_| AppError::BadRequest("jwk: bad n".into()))?;
    let e = URL_SAFE_NO_PAD
        .decode(jwk["e"].as_str().unwrap_or_default())
        .map_err(|_| AppError::BadRequest("jwk: bad e".into()))?;
    // aws-lc-rs wants X.509 SubjectPublicKeyInfo DER; build it from the components.
    use rsa::pkcs8::EncodePublicKey as _;
    let public = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&n),
        rsa::BigUint::from_bytes_be(&e),
    )
    .map_err(|_| AppError::BadRequest("jwk: invalid RSA public key".into()))?;
    let spki = public
        .to_public_key_der()
        .map_err(|_| AppError::BadRequest("jwk: cannot encode RSA public key".into()))?;
    PublicEncryptingKey::from_der(spki.as_bytes())
        .map_err(|_| AppError::BadRequest("jwk: invalid RSA public key".into()))
}

/// Encrypt `plaintext` (a compact JWS) for the recipient's RSA public JWK.
pub fn encrypt(
    plaintext: &[u8],
    recipient_jwk: &Value,
    alg: KeyAlg,
    enc: ContentEnc,
) -> AppResult<String> {
    let public = rsa_public_from_jwk(recipient_jwk)?;
    let oaep =
        OaepPublicEncryptingKey::new(public).map_err(|_| AppError::Internal("oaep key".into()))?;

    // Content encryption key and IV.
    let mut cek = vec![0u8; enc.key_len()];
    rand::fill(&mut cek[..]);
    let mut iv = [0u8; 12];
    rand::fill(&mut iv);

    let mut header = json!({"alg": alg.as_str(), "enc": enc.as_str(), "cty": "JWT"});
    if let Some(kid) = recipient_jwk.get("kid") {
        header["kid"] = kid.clone();
    }
    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);

    let oaep_alg = match alg {
        KeyAlg::RsaOaep256 => &OAEP_SHA256_MGF1SHA256,
        KeyAlg::RsaOaep => &OAEP_SHA1_MGF1SHA1,
    };
    let mut encrypted_key = vec![0u8; oaep.key_size_bytes()];
    let encrypted_key = oaep
        .encrypt(oaep_alg, &cek, &mut encrypted_key, None)
        .map_err(|_| AppError::Internal("oaep encrypt".into()))?
        .to_vec();

    let key = LessSafeKey::new(
        UnboundKey::new(enc.algorithm(), &cek).map_err(|_| AppError::Internal("cek".into()))?,
    );
    let mut in_out = plaintext.to_vec();
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(iv),
            Aad::from(protected.as_bytes()),
            &mut in_out,
        )
        .map_err(|_| AppError::Internal("aes-gcm seal".into()))?;

    Ok([
        protected,
        URL_SAFE_NO_PAD.encode(encrypted_key),
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(in_out),
        URL_SAFE_NO_PAD.encode(tag.as_ref()),
    ]
    .join("."))
}

/// Decrypt a compact JWE with an RSA private key (PKCS#8 DER). Used by tests
/// and by the token-exchange/introspection paths that accept encrypted input.
pub fn decrypt(jwe: &str, private_pkcs8_der: &[u8]) -> AppResult<Vec<u8>> {
    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.len() != 5 {
        return Err(AppError::BadRequest("malformed JWE".into()));
    }
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| AppError::BadRequest("malformed JWE header".into()))?,
    )?;
    let alg = KeyAlg::parse(header["alg"].as_str().unwrap_or_default())
        .ok_or_else(|| AppError::BadRequest("unsupported JWE alg".into()))?;
    let enc = ContentEnc::parse(header["enc"].as_str().unwrap_or_default())
        .ok_or_else(|| AppError::BadRequest("unsupported JWE enc".into()))?;
    let dec = |i: usize| {
        URL_SAFE_NO_PAD
            .decode(parts[i])
            .map_err(|_| AppError::BadRequest("malformed JWE segment".into()))
    };
    let (encrypted_key, iv, ciphertext, tag) = (dec(1)?, dec(2)?, dec(3)?, dec(4)?);

    let private = aws_lc_rs::rsa::PrivateDecryptingKey::from_pkcs8(private_pkcs8_der)
        .map_err(|_| AppError::BadRequest("invalid RSA private key".into()))?;
    let oaep = OaepPrivateDecryptingKey::new(private)
        .map_err(|_| AppError::Internal("oaep private".into()))?;
    let oaep_alg = match alg {
        KeyAlg::RsaOaep256 => &OAEP_SHA256_MGF1SHA256,
        KeyAlg::RsaOaep => &OAEP_SHA1_MGF1SHA1,
    };
    let mut cek_buf = vec![0u8; oaep.key_size_bytes()];
    let cek = oaep
        .decrypt(oaep_alg, &encrypted_key, &mut cek_buf, None)
        .map_err(|_| AppError::BadRequest("JWE key unwrap failed".into()))?;
    if cek.len() != enc.key_len() {
        return Err(AppError::BadRequest("JWE cek length".into()));
    }
    let iv: [u8; 12] = iv
        .try_into()
        .map_err(|_| AppError::BadRequest("JWE iv".into()))?;
    let key = LessSafeKey::new(
        UnboundKey::new(enc.algorithm(), cek).map_err(|_| AppError::Internal("cek".into()))?,
    );
    let mut in_out = ciphertext;
    in_out.extend_from_slice(&tag);
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(iv),
            Aad::from(parts[0].as_bytes()),
            &mut in_out,
        )
        .map_err(|_| AppError::BadRequest("JWE authentication failed".into()))?;
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{RsaBits, SigningAlg};
    use crate::services::keys;

    #[test]
    fn round_trip_all_supported_combinations() {
        let recipient = keys::generate(SigningAlg::RS256, RsaBits::B2048).unwrap();
        for alg in [KeyAlg::RsaOaep256, KeyAlg::RsaOaep] {
            for enc in [ContentEnc::A256Gcm, ContentEnc::A128Gcm] {
                let jwe =
                    encrypt(b"header.payload.signature", &recipient.public_jwk, alg, enc).unwrap();
                assert_eq!(jwe.split('.').count(), 5);
                let header: Value = serde_json::from_slice(
                    &URL_SAFE_NO_PAD
                        .decode(jwe.split('.').next().unwrap())
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(header["alg"], alg.as_str());
                assert_eq!(header["enc"], enc.as_str());
                assert_eq!(header["cty"], "JWT");
                assert_eq!(header["kid"], recipient.kid);
                assert_eq!(
                    decrypt(&jwe, &recipient.private_der).unwrap(),
                    b"header.payload.signature"
                );
            }
        }
    }

    #[test]
    fn wrong_key_and_tampering_are_rejected() {
        let a = keys::generate(SigningAlg::RS256, RsaBits::B2048).unwrap();
        let b = keys::generate(SigningAlg::RS256, RsaBits::B2048).unwrap();
        let jwe = encrypt(
            b"secret",
            &a.public_jwk,
            KeyAlg::RsaOaep256,
            ContentEnc::A256Gcm,
        )
        .unwrap();
        assert!(decrypt(&jwe, &b.private_der).is_err());
        let mut parts: Vec<String> = jwe.split('.').map(String::from).collect();
        parts[3] = URL_SAFE_NO_PAD.encode(b"tampered");
        assert!(decrypt(&parts.join("."), &a.private_der).is_err());
        assert!(
            encrypt(
                b"x",
                &json!({"kty": "EC"}),
                KeyAlg::RsaOaep256,
                ContentEnc::A256Gcm
            )
            .is_err()
        );
    }
}
