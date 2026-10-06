//! Credential public keys: read from the COSE key (RFC 9053) an
//! authenticator registers, stored in webauthn-rs's JSON shape (so passkeys
//! stored before rIDM verified them itself still read, and the other way
//! round), and used to verify assertions with aws-lc-rs.

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ED25519, ParsedPublicKey, RSA_PKCS1_2048_8192_SHA256,
    RsaPublicKeyComponents, UnparsedPublicKey,
};
use base64urlsafedata::HumanBinaryData;
use serde::{Deserialize, Serialize};

use super::cbor::Value;

/// A credential's key, as webauthn-rs stores it: `{"type_": .., "key": ..}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoseKey {
    pub type_: CoseAlgorithm,
    pub key: CoseKeyType,
}

/// COSE algorithms, spelled as webauthn-rs serialises them. Only ES256,
/// RS256 and EdDSA ever verify; the rest are named so a stored key that
/// carries one still reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoseAlgorithm {
    #[serde(alias = "ECDSA_SHA256")]
    ES256,
    #[serde(alias = "ECDSA_SHA384")]
    ES384,
    #[serde(alias = "ECDSA_SHA512")]
    ES512,
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    #[serde(rename = "EDDSA")]
    EdDsa,
    #[serde(rename = "INSECURE_RS1")]
    InsecureRs1,
    PinUvProtocol,
}

impl CoseAlgorithm {
    /// The COSE identifier (RFC 9053), as offered in `pubKeyCredParams`.
    pub fn id(self) -> i64 {
        match self {
            Self::ES256 => -7,
            Self::ES384 => -35,
            Self::ES512 => -36,
            Self::RS256 => -257,
            Self::RS384 => -258,
            Self::RS512 => -259,
            Self::PS256 => -37,
            Self::PS384 => -38,
            Self::PS512 => -39,
            Self::EdDsa => -8,
            Self::InsecureRs1 => -65535,
            Self::PinUvProtocol => -65534,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoseKeyType {
    #[serde(rename = "EC_EC2")]
    Ec2(Ec2Key),
    #[serde(rename = "EC_OKP")]
    Okp(OkpKey),
    #[serde(rename = "RSA")]
    Rsa(RsaKey),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ec2Key {
    pub curve: EcCurve,
    pub x: HumanBinaryData,
    pub y: HumanBinaryData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EcCurve {
    SECP256R1,
    SECP384R1,
    SECP521R1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OkpKey {
    pub curve: EdCurve,
    pub x: HumanBinaryData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdCurve {
    ED25519,
    ED448,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaKey {
    pub n: HumanBinaryData,
    /// Always three bytes, stored as a JSON array (webauthn-rs's `[u8; 3]`).
    pub e: [u8; 3],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoseError {
    #[error("the credential public key is not a COSE key rIDM accepts: {0}")]
    Unsupported(&'static str),
    #[error("the credential public key is invalid")]
    Invalid,
}

/// COSE key parameters (RFC 9052 §7, RFC 9053 §7).
const KTY: i128 = 1;
const ALG: i128 = 3;
const CRV: i128 = -1;
const X_OR_N: i128 = -2;
const Y_OR_E: i128 = -3;
const KTY_OKP: i128 = 1;
const KTY_EC2: i128 = 2;
const KTY_RSA: i128 = 3;
const CRV_P256: i128 = 1;
const CRV_ED25519: i128 = 6;

impl CoseKey {
    /// The key an authenticator registered, if it is one of `allowed`:
    /// ES256 on P-256, RS256 with a 2048-bit modulus (what webauthn-rs
    /// accepted), or EdDSA on Ed25519. The key itself is checked (a point
    /// on the curve, a usable modulus).
    pub fn from_cbor(v: &Value, allowed: &[CoseAlgorithm]) -> Result<Self, CoseError> {
        let int = |k| v.get_int(k).and_then(Value::as_int);
        let bytes = |k| v.get_int(k).and_then(Value::as_bytes);
        let kty = int(KTY).ok_or(CoseError::Unsupported("no key type"))?;
        let alg = int(ALG).ok_or(CoseError::Unsupported("no algorithm"))?;
        let key = match (kty, alg) {
            (KTY_EC2, -7) => {
                if int(CRV) != Some(CRV_P256) {
                    return Err(CoseError::Unsupported("ES256 needs P-256"));
                }
                let (x, y) = (bytes(X_OR_N), bytes(Y_OR_E));
                let (Some(x), Some(y)) = (x, y) else {
                    return Err(CoseError::Invalid);
                };
                if x.len() != 32 || y.len() != 32 {
                    return Err(CoseError::Invalid);
                }
                Self {
                    type_: CoseAlgorithm::ES256,
                    key: CoseKeyType::Ec2(Ec2Key {
                        curve: EcCurve::SECP256R1,
                        x: x.to_vec().into(),
                        y: y.to_vec().into(),
                    }),
                }
            }
            (KTY_RSA, -257) => {
                let (n, e) = (bytes(X_OR_N), bytes(Y_OR_E));
                let (Some(n), Some(e)) = (n, e) else {
                    return Err(CoseError::Invalid);
                };
                let e: [u8; 3] = e.try_into().map_err(|_| CoseError::Invalid)?;
                if n.len() != 256 {
                    return Err(CoseError::Unsupported("RS256 needs a 2048-bit key"));
                }
                Self {
                    type_: CoseAlgorithm::RS256,
                    key: CoseKeyType::Rsa(RsaKey {
                        n: n.to_vec().into(),
                        e,
                    }),
                }
            }
            (KTY_OKP, -8) => {
                if int(CRV) != Some(CRV_ED25519) {
                    return Err(CoseError::Unsupported("EdDSA needs Ed25519"));
                }
                let x = bytes(X_OR_N).ok_or(CoseError::Invalid)?;
                if x.len() != 32 {
                    return Err(CoseError::Invalid);
                }
                Self {
                    type_: CoseAlgorithm::EdDsa,
                    key: CoseKeyType::Okp(OkpKey {
                        curve: EdCurve::ED25519,
                        x: x.to_vec().into(),
                    }),
                }
            }
            _ => return Err(CoseError::Unsupported("key type and algorithm")),
        };
        if !allowed.contains(&key.type_) {
            return Err(CoseError::Unsupported("algorithm not offered"));
        }
        key.check()?;
        Ok(key)
    }

    /// The key parses as a public key of its algorithm.
    fn check(&self) -> Result<(), CoseError> {
        match (&self.type_, &self.key) {
            (CoseAlgorithm::ES256, CoseKeyType::Ec2(k)) => {
                ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, uncompressed(k))
                    .map(|_| ())
                    .map_err(|_| CoseError::Invalid)
            }
            (CoseAlgorithm::RS256, CoseKeyType::Rsa(k)) => {
                use aws_lc_rs::encoding::AsDer as _;
                aws_lc_rs::rsa::PublicKeyComponents {
                    n: k.n.as_ref(),
                    e: &k.e[..],
                }
                .as_der()
                .map(|_| ())
                .map_err(|_| CoseError::Invalid)
            }
            (CoseAlgorithm::EdDsa, CoseKeyType::Okp(k)) => {
                ParsedPublicKey::new(&ED25519, k.x.as_ref())
                    .map(|_| ())
                    .map_err(|_| CoseError::Invalid)
            }
            _ => Err(CoseError::Unsupported("key type and algorithm")),
        }
    }

    /// Verify `signature` over `message` (`authenticatorData ‖
    /// SHA-256(clientDataJSON)`): ES256 as an ASN.1 DER ECDSA signature,
    /// RS256 as PKCS#1 v1.5, EdDSA as the raw 64 bytes. The algorithm comes
    /// from the stored key, never from the assertion.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match (&self.type_, &self.key) {
            (CoseAlgorithm::ES256, CoseKeyType::Ec2(k)) if k.curve == EcCurve::SECP256R1 => {
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, uncompressed(k))
                    .verify(message, signature)
                    .is_ok()
            }
            (CoseAlgorithm::RS256, CoseKeyType::Rsa(k)) => RsaPublicKeyComponents {
                n: k.n.as_ref(),
                e: &k.e[..],
            }
            .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
            .is_ok(),
            (CoseAlgorithm::EdDsa, CoseKeyType::Okp(k)) if k.curve == EdCurve::ED25519 => {
                UnparsedPublicKey::new(&ED25519, k.x.as_ref())
                    .verify(message, signature)
                    .is_ok()
            }
            _ => false,
        }
    }
}

/// `0x04 ‖ x ‖ y`.
fn uncompressed(k: &Ec2Key) -> Vec<u8> {
    let mut point = Vec::with_capacity(1 + k.x.as_ref().len() + k.y.as_ref().len());
    point.push(0x04);
    point.extend_from_slice(k.x.as_ref());
    point.extend_from_slice(k.y.as_ref());
    point
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};

    use super::*;

    fn cose_es256(point: &[u8]) -> Value {
        Value::Map(vec![
            (Value::Int(KTY), Value::Int(KTY_EC2)),
            (Value::Int(ALG), Value::Int(-7)),
            (Value::Int(CRV), Value::Int(CRV_P256)),
            (Value::Int(X_OR_N), Value::Bytes(point[1..33].to_vec())),
            (Value::Int(Y_OR_E), Value::Bytes(point[33..].to_vec())),
        ])
    }

    #[test]
    fn an_es256_key_reads_verifies_and_round_trips_through_json() {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
        let key = CoseKey::from_cbor(
            &cose_es256(pair.public_key().as_ref()),
            &[CoseAlgorithm::ES256, CoseAlgorithm::RS256],
        )
        .unwrap();
        let sig = pair.sign(&SystemRandom::new(), b"message").unwrap();
        assert!(key.verify(b"message", sig.as_ref()));
        assert!(!key.verify(b"messagE", sig.as_ref()));
        let json = serde_json::to_value(&key).unwrap();
        assert_eq!(json["type_"], "ES256");
        assert_eq!(json["key"]["EC_EC2"]["curve"], "SECP256R1");
        assert!(json["key"]["EC_EC2"]["x"].is_string(), "{json}");
        assert_eq!(serde_json::from_value::<CoseKey>(json).unwrap(), key);
    }

    #[test]
    fn keys_outside_the_offer_or_off_the_curve_are_refused() {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
        let cose = cose_es256(pair.public_key().as_ref());
        assert!(CoseKey::from_cbor(&cose, &[CoseAlgorithm::RS256]).is_err());
        let mut point = pair.public_key().as_ref().to_vec();
        point[40] ^= 1; // y no longer on the curve
        assert_eq!(
            CoseKey::from_cbor(&cose_es256(&point), &[CoseAlgorithm::ES256]),
            Err(CoseError::Invalid)
        );
        let ed448 = Value::Map(vec![
            (Value::Int(KTY), Value::Int(KTY_OKP)),
            (Value::Int(ALG), Value::Int(-8)),
            (Value::Int(CRV), Value::Int(7)),
            (Value::Int(X_OR_N), Value::Bytes(vec![0; 57])),
        ]);
        assert!(CoseKey::from_cbor(&ed448, &[CoseAlgorithm::EdDsa]).is_err());
    }

    #[test]
    fn stored_keys_in_older_encodings_still_read() {
        // Integer arrays (webauthn-rs's older output) and the RSA exponent
        // as an array of three numbers.
        let json = serde_json::json!({
            "type_": "RS256",
            "key": {"RSA": {"n": vec![1u8; 256], "e": [1, 0, 1]}}
        });
        let key: CoseKey = serde_json::from_value(json).unwrap();
        assert_eq!(key.type_, CoseAlgorithm::RS256);
        let back = serde_json::to_value(&key).unwrap();
        assert!(back["key"]["RSA"]["n"].is_string());
        assert_eq!(back["key"]["RSA"]["e"], serde_json::json!([1, 0, 1]));
    }
}
