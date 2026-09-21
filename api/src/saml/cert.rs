//! X.509 certificates: the IdP's self-signed signing certificates (SAML
//! metadata carries keys as certificates) and the certificates SPs register
//! for request signatures and assertion encryption.

use aws_lc_rs::signature::{self, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Datelike, Utc};

use super::error::{SamlError, SamlResult};

/// A signature algorithm a certificate's key can verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlg {
    RsaSha256,
    RsaSha384,
    RsaSha512,
    EcdsaSha256,
    EcdsaSha384,
}

impl SignatureAlg {
    /// From an XML-DSig `SignatureMethod` or a Redirect-binding `SigAlg`.
    /// SHA-1 is refused.
    pub fn from_uri(uri: &str) -> SamlResult<Self> {
        use super::ns::alg;
        Ok(match uri {
            alg::RSA_SHA256 => Self::RsaSha256,
            alg::RSA_SHA384 => Self::RsaSha384,
            alg::RSA_SHA512 => Self::RsaSha512,
            alg::ECDSA_SHA256 => Self::EcdsaSha256,
            alg::ECDSA_SHA384 => Self::EcdsaSha384,
            alg::RSA_SHA1 => {
                return Err(SamlError::signature("SHA-1 signatures are not accepted"));
            }
            _ => return Err(SamlError::signature("unsupported signature algorithm")),
        })
    }

    pub fn uri(self) -> &'static str {
        use super::ns::alg;
        match self {
            Self::RsaSha256 => alg::RSA_SHA256,
            Self::RsaSha384 => alg::RSA_SHA384,
            Self::RsaSha512 => alg::RSA_SHA512,
            Self::EcdsaSha256 => alg::ECDSA_SHA256,
            Self::EcdsaSha384 => alg::ECDSA_SHA384,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Key {
    /// PKCS#1 `RSAPublicKey`.
    Rsa(Vec<u8>),
    /// Uncompressed points.
    EcP256(Vec<u8>),
    EcP384(Vec<u8>),
}

/// A parsed certificate. Only its public key and dates are used: SAML
/// trust comes from registration, not from a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub der: Vec<u8>,
    /// `SubjectPublicKeyInfo` DER (what RSA-OAEP encryption takes).
    spki: Vec<u8>,
    key: Key,
    pub subject: String,
    pub not_after: DateTime<Utc>,
}

impl Certificate {
    /// From PEM, or the bare base64 a metadata `X509Certificate` holds.
    pub fn parse(input: &str) -> SamlResult<Self> {
        let body: String = input
            .lines()
            .filter(|l| !l.trim_start().starts_with("-----"))
            .collect();
        let der = super::xml::base64_content(&body)
            .map_err(|_| SamlError::malformed("certificate is not PEM or base64 DER"))?;
        Self::from_der(der)
    }

    pub fn from_der(der: Vec<u8>) -> SamlResult<Self> {
        use x509_parser::public_key::PublicKey;
        let (rest, cert) = x509_parser::parse_x509_certificate(&der)
            .map_err(|_| SamlError::malformed("not an X.509 certificate"))?;
        if !rest.is_empty() {
            return Err(SamlError::malformed("trailing data after the certificate"));
        }
        let spki = cert.public_key();
        let key = match spki.parsed() {
            Ok(PublicKey::RSA(k)) => {
                if k.key_size() < 2048 {
                    return Err(SamlError::malformed(
                        "RSA keys under 2048 bits are not accepted",
                    ));
                }
                Key::Rsa(spki.subject_public_key.data.to_vec())
            }
            Ok(PublicKey::EC(p)) => match p.data().len() {
                65 => Key::EcP256(p.data().to_vec()),
                97 => Key::EcP384(p.data().to_vec()),
                _ => return Err(SamlError::malformed("unsupported elliptic curve")),
            },
            _ => return Err(SamlError::malformed("unsupported certificate key type")),
        };
        let not_after = DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        let subject = cert.subject().to_string();
        let spki = spki.raw.to_vec();
        Ok(Self {
            der,
            spki,
            key,
            subject,
            not_after,
        })
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(&self.der)
    }

    pub fn to_pem(&self) -> String {
        let b64 = self.to_base64();
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out
    }

    /// The RSA `SubjectPublicKeyInfo`, for key transport; `None` for EC.
    pub fn rsa_spki(&self) -> Option<&[u8]> {
        matches!(self.key, Key::Rsa(_)).then_some(self.spki.as_slice())
    }

    /// Whether `sig` is `alg`'s signature over `message` by this key. A
    /// curve that does not match the hash is refused, not guessed at.
    pub fn verify(&self, alg: SignatureAlg, message: &[u8], sig: &[u8]) -> bool {
        let (params, key): (&'static dyn signature::VerificationAlgorithm, &[u8]) =
            match (alg, &self.key) {
                (SignatureAlg::RsaSha256, Key::Rsa(k)) => {
                    (&signature::RSA_PKCS1_2048_8192_SHA256, k)
                }
                (SignatureAlg::RsaSha384, Key::Rsa(k)) => {
                    (&signature::RSA_PKCS1_2048_8192_SHA384, k)
                }
                (SignatureAlg::RsaSha512, Key::Rsa(k)) => {
                    (&signature::RSA_PKCS1_2048_8192_SHA512, k)
                }
                (SignatureAlg::EcdsaSha256, Key::EcP256(k)) => {
                    (&signature::ECDSA_P256_SHA256_FIXED, k)
                }
                (SignatureAlg::EcdsaSha384, Key::EcP384(k)) => {
                    (&signature::ECDSA_P384_SHA384_FIXED, k)
                }
                _ => return false,
            };
        UnparsedPublicKey::new(params, key)
            .verify(message, sig)
            .is_ok()
    }
}

/// A self-signed certificate for an RSA signing key (PKCS#8 DER), valid
/// from today for `years`. The certificate is only a container for the key
/// in metadata; SPs pin it, so it is made once per key and stored.
pub fn self_signed(pkcs8: &[u8], common_name: &str, years: i32) -> SamlResult<Vec<u8>> {
    let key = rcgen::KeyPair::try_from(pkcs8)
        .map_err(|e| SamlError::Crypto(format!("signing key: {e}")))?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .map_err(|e| SamlError::Crypto(format!("certificate parameters: {e}")))?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, common_name);
    params.distinguished_name = dn;
    let today = Utc::now();
    // Month and day stay within range for every year: Feb 29 falls back
    // to the 28th.
    let (m, d) = (today.month() as u8, today.day().min(28) as u8);
    params.not_before = rcgen::date_time_ymd(today.year(), m, d);
    params.not_after = rcgen::date_time_ymd(today.year() + years, m, d);
    let mut serial = [0u8; 16];
    rand::fill(&mut serial);
    serial[0] &= 0x7f;
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
    let cert = params
        .self_signed(&key)
        .map_err(|e| SamlError::Crypto(format!("certificate: {e}")))?;
    Ok(cert.der().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::saml::testkit::rsa_pkcs8;

    #[test]
    fn a_self_signed_certificate_carries_the_key() {
        let pkcs8 = rsa_pkcs8();
        let der = self_signed(&pkcs8, "rIDM test", 10).unwrap();
        let cert = Certificate::from_der(der).unwrap();
        // Messages that print the certificate would log key-derived data.
        assert!(cert.subject.contains("rIDM test"));
        assert!(cert.not_after > Utc::now() + chrono::Duration::days(3000));
        let pem = cert.to_pem();
        assert!(Certificate::parse(&pem).unwrap() == cert);
        assert!(Certificate::parse(&cert.to_base64()).unwrap() == cert);

        let kp = aws_lc_rs::rsa::KeyPair::from_pkcs8(&pkcs8).unwrap();
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(
            &signature::RSA_PKCS1_SHA256,
            &aws_lc_rs::rand::SystemRandom::new(),
            b"message",
            &mut sig,
        )
        .unwrap();
        assert!(cert.verify(SignatureAlg::RsaSha256, b"message", &sig));
        assert!(!cert.verify(SignatureAlg::RsaSha256, b"massage", &sig));
        assert!(!cert.verify(SignatureAlg::EcdsaSha256, b"message", &sig));
        assert!(cert.rsa_spki().is_some());
    }

    #[test]
    fn sha1_and_unknown_algorithms_are_refused() {
        assert!(SignatureAlg::from_uri(crate::saml::ns::alg::RSA_SHA1).is_err());
        assert!(SignatureAlg::from_uri("urn:nothing").is_err());
        assert_eq!(
            SignatureAlg::from_uri(crate::saml::ns::alg::RSA_SHA256).unwrap(),
            SignatureAlg::RsaSha256
        );
    }

    #[test]
    fn garbage_is_not_a_certificate() {
        assert!(Certificate::parse("not base64 !!").is_err());
        assert!(Certificate::parse("aGVsbG8=").is_err());
    }
}
