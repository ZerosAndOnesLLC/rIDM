//! XML Encryption of one element (an assertion) to a recipient's RSA
//! certificate: a random content key under AES, carried in an
//! `xenc:EncryptedKey` wrapped with RSA-OAEP.
//!
//! AES-GCM is the default. AES-CBC exists for SPs that have not moved on;
//! it has no integrity of its own, which only matters for decryption (the
//! upstream side, 13.2), where every failure looks the same.

use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::cipher::{
    AES_128, AES_256, DecryptingKey, DecryptionContext, PaddedBlockEncryptingKey, UnboundCipherKey,
};
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::rsa::{
    OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256, OaepAlgorithm, OaepPrivateDecryptingKey,
    OaepPublicEncryptingKey, PrivateDecryptingKey, PublicEncryptingKey,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use roxmltree::Node;
use serde::{Deserialize, Serialize};

use super::cert::Certificate;
use super::error::{SamlError, SamlResult};
use super::ns::{self, alg};
use super::xml::{El, base64_content, child, text_of};

/// The block cipher for the content.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "kebab-case")]
#[serde(rename_all = "kebab-case")]
pub enum DataEncryption {
    #[default]
    Aes256Gcm,
    Aes128Gcm,
    Aes256Cbc,
    Aes128Cbc,
}

impl DataEncryption {
    pub fn uri(self) -> &'static str {
        match self {
            Self::Aes256Gcm => alg::AES256_GCM,
            Self::Aes128Gcm => alg::AES128_GCM,
            Self::Aes256Cbc => alg::AES256_CBC,
            Self::Aes128Cbc => alg::AES128_CBC,
        }
    }

    fn from_uri(uri: &str) -> SamlResult<Self> {
        Ok(match uri {
            alg::AES256_GCM => Self::Aes256Gcm,
            alg::AES128_GCM => Self::Aes128Gcm,
            alg::AES256_CBC => Self::Aes256Cbc,
            alg::AES128_CBC => Self::Aes128Cbc,
            _ => {
                return Err(SamlError::Unsupported(
                    "content encryption algorithm".into(),
                ));
            }
        })
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes256Gcm | Self::Aes256Cbc => 32,
            Self::Aes128Gcm | Self::Aes128Cbc => 16,
        }
    }
}

/// How the content key travels.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "kebab-case")]
#[serde(rename_all = "kebab-case")]
pub enum KeyTransport {
    /// `xmlenc#rsa-oaep-mgf1p`: OAEP with SHA-1 and MGF1-SHA-1. SHA-1 is
    /// sound inside OAEP, and every SAML stack reads it.
    #[default]
    RsaOaepMgf1p,
    /// `xmlenc11#rsa-oaep` with SHA-256 and MGF1-SHA-256.
    RsaOaepSha256,
}

impl KeyTransport {
    fn oaep(self) -> &'static OaepAlgorithm {
        match self {
            Self::RsaOaepMgf1p => &OAEP_SHA1_MGF1SHA1,
            Self::RsaOaepSha256 => &OAEP_SHA256_MGF1SHA256,
        }
    }

    fn method(self) -> El {
        match self {
            Self::RsaOaepMgf1p => El::new("xenc:EncryptionMethod")
                .attr("Algorithm", alg::RSA_OAEP_MGF1P)
                .child(El::new("ds:DigestMethod").attr("Algorithm", alg::SHA1)),
            Self::RsaOaepSha256 => El::new("xenc:EncryptionMethod")
                .attr("Algorithm", alg::RSA_OAEP)
                .child(El::new("ds:DigestMethod").attr("Algorithm", alg::SHA256))
                .child(
                    El::new("xenc11:MGF")
                        .attr("xmlns:xenc11", ns::XENC11)
                        .attr("Algorithm", alg::MGF1_SHA256),
                ),
        }
    }
}

fn crypto(what: &str) -> SamlError {
    SamlError::Crypto(what.into())
}

/// Encrypt `plaintext` (a serialized element) for `recipient`: the
/// `xenc:EncryptedData` that replaces it, to be wrapped in the SAML
/// container (`saml:EncryptedAssertion`).
pub fn encrypt(
    plaintext: &str,
    recipient: &Certificate,
    data: DataEncryption,
    transport: KeyTransport,
) -> SamlResult<El> {
    let spki = recipient
        .rsa_spki()
        .ok_or_else(|| crypto("the encryption certificate must hold an RSA key"))?;
    let mut key = vec![0u8; data.key_len()];
    rand::fill(key.as_mut_slice());

    let cipher_value = match data {
        DataEncryption::Aes256Gcm | DataEncryption::Aes128Gcm => {
            let alg = if data == DataEncryption::Aes256Gcm {
                &aead::AES_256_GCM
            } else {
                &aead::AES_128_GCM
            };
            let sealing =
                LessSafeKey::new(UnboundKey::new(alg, &key).map_err(|_| crypto("content key"))?);
            let mut iv = [0u8; 12];
            rand::fill(&mut iv);
            let mut buf = plaintext.as_bytes().to_vec();
            sealing
                .seal_in_place_append_tag(Nonce::assume_unique_for_key(iv), Aad::empty(), &mut buf)
                .map_err(|_| crypto("content encryption"))?;
            let mut out = iv.to_vec();
            out.extend_from_slice(&buf);
            out
        }
        DataEncryption::Aes256Cbc | DataEncryption::Aes128Cbc => {
            let alg = if data == DataEncryption::Aes256Cbc {
                &AES_256
            } else {
                &AES_128
            };
            let enc = PaddedBlockEncryptingKey::cbc_pkcs7(
                UnboundCipherKey::new(alg, &key).map_err(|_| crypto("content key"))?,
            )
            .map_err(|_| crypto("content key"))?;
            let mut buf = plaintext.as_bytes().to_vec();
            let ctx = enc
                .encrypt(&mut buf)
                .map_err(|_| crypto("content encryption"))?;
            let iv: &[u8] = (&ctx).try_into().map_err(|_| crypto("content iv"))?;
            let mut out = iv.to_vec();
            out.extend_from_slice(&buf);
            out
        }
    };

    let public = OaepPublicEncryptingKey::new(
        PublicEncryptingKey::from_der(spki).map_err(|_| crypto("recipient key"))?,
    )
    .map_err(|_| crypto("recipient key"))?;
    let mut wrapped = vec![0u8; public.ciphertext_size()];
    let wrapped = public
        .encrypt(transport.oaep(), &key, &mut wrapped, None)
        .map_err(|_| crypto("key transport"))?
        .to_vec();

    Ok(El::new("xenc:EncryptedData")
        .attr("xmlns:xenc", ns::XENC)
        .attr("xmlns:ds", ns::DSIG)
        .attr("Type", alg::ENC_ELEMENT)
        .child(El::new("xenc:EncryptionMethod").attr("Algorithm", data.uri()))
        .child(
            El::new("ds:KeyInfo").child(
                El::new("xenc:EncryptedKey")
                    .child(transport.method())
                    .child(
                        El::new("xenc:CipherData")
                            .child(El::new("xenc:CipherValue").text(STANDARD.encode(&wrapped))),
                    ),
            ),
        )
        .child(
            El::new("xenc:CipherData")
                .child(El::new("xenc:CipherValue").text(STANDARD.encode(&cipher_value))),
        ))
}

fn required<'a, 'i>(
    node: Node<'a, 'i>,
    ns: &'a str,
    local: &'static str,
) -> SamlResult<Node<'a, 'i>> {
    child(node, ns, local)?.ok_or_else(|| SamlError::malformed(format!("{local} is missing")))
}

fn cipher_value(node: Node) -> SamlResult<Vec<u8>> {
    let data = required(node, ns::XENC, "CipherData")?;
    base64_content(&text_of(required(data, ns::XENC, "CipherValue")?))
}

/// Decrypt an `xenc:EncryptedData` with the RSA private key (PKCS#8 DER)
/// its content key was wrapped for. Every failure after parsing reads the
/// same, so a CBC padding error tells an attacker nothing.
pub fn decrypt(encrypted_data: Node, private_pkcs8: &[u8]) -> SamlResult<String> {
    let method = required(encrypted_data, ns::XENC, "EncryptionMethod")?;
    let data = DataEncryption::from_uri(method.attribute("Algorithm").unwrap_or_default())?;
    let key_info = required(encrypted_data, ns::DSIG, "KeyInfo")?;
    let encrypted_key = required(key_info, ns::XENC, "EncryptedKey")?;
    let key_method = required(encrypted_key, ns::XENC, "EncryptionMethod")?;
    let transport = match key_method.attribute("Algorithm") {
        Some(alg::RSA_OAEP_MGF1P) => KeyTransport::RsaOaepMgf1p,
        Some(alg::RSA_OAEP) => {
            let digest = child(key_method, ns::DSIG, "DigestMethod")?
                .and_then(|d| d.attribute("Algorithm"))
                .unwrap_or(alg::SHA1);
            let mgf = child(key_method, ns::XENC11, "MGF")?
                .and_then(|d| d.attribute("Algorithm"))
                .unwrap_or(alg::MGF1_SHA1);
            match (digest, mgf) {
                (alg::SHA256, alg::MGF1_SHA256) => KeyTransport::RsaOaepSha256,
                (alg::SHA1, alg::MGF1_SHA1) => KeyTransport::RsaOaepMgf1p,
                _ => {
                    return Err(SamlError::Unsupported(
                        "OAEP digest and mask combination".into(),
                    ));
                }
            }
        }
        _ => return Err(SamlError::Unsupported("key transport algorithm".into())),
    };
    let wrapped = cipher_value(encrypted_key)?;
    let content = cipher_value(encrypted_data)?;

    let failed = || crypto("decryption failed");
    let private = OaepPrivateDecryptingKey::new(
        PrivateDecryptingKey::from_pkcs8(private_pkcs8).map_err(|_| failed())?,
    )
    .map_err(|_| failed())?;
    let mut key = vec![0u8; private.min_output_size()];
    let key = private
        .decrypt(transport.oaep(), &wrapped, &mut key, None)
        .map_err(|_| failed())?
        .to_vec();
    if key.len() != data.key_len() {
        return Err(failed());
    }

    let plain = match data {
        DataEncryption::Aes256Gcm | DataEncryption::Aes128Gcm => {
            let alg = if data == DataEncryption::Aes256Gcm {
                &aead::AES_256_GCM
            } else {
                &aead::AES_128_GCM
            };
            if content.len() < 12 + 16 {
                return Err(failed());
            }
            let (iv, rest) = content.split_at(12);
            let opening = LessSafeKey::new(UnboundKey::new(alg, &key).map_err(|_| failed())?);
            let nonce = Nonce::try_assume_unique_for_key(iv).map_err(|_| failed())?;
            let mut buf = rest.to_vec();
            let plain = opening
                .open_in_place(nonce, Aad::empty(), &mut buf)
                .map_err(|_| failed())?;
            plain.to_vec()
        }
        DataEncryption::Aes256Cbc | DataEncryption::Aes128Cbc => {
            let alg = if data == DataEncryption::Aes256Cbc {
                &AES_256
            } else {
                &AES_128
            };
            if content.len() < 32 || content.len() % 16 != 0 {
                return Err(failed());
            }
            let (iv, rest) = content.split_at(16);
            let iv: [u8; 16] = iv.try_into().map_err(|_| failed())?;
            let dec = DecryptingKey::cbc(UnboundCipherKey::new(alg, &key).map_err(|_| failed())?)
                .map_err(|_| failed())?;
            let mut buf = rest.to_vec();
            let plain = dec
                .decrypt(&mut buf, DecryptionContext::Iv128(FixedLength::from(iv)))
                .map_err(|_| failed())?;
            // XML-Enc padding: the last byte is the pad length; the other
            // pad bytes are arbitrary (not PKCS#7).
            let pad = usize::from(*plain.last().ok_or_else(failed)?);
            if pad == 0 || pad > 16 || pad > plain.len() {
                return Err(failed());
            }
            plain[..plain.len() - pad].to_vec()
        }
    };
    String::from_utf8(plain).map_err(|_| failed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::saml::testkit::{other_rsa_pkcs8, rsa_cert, rsa_pkcs8};
    use crate::saml::xml;

    fn round_trip(data: DataEncryption, transport: KeyTransport) {
        let plain = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a">secret é</saml:Assertion>"#;
        let el = encrypt(plain, &rsa_cert(), data, transport).unwrap();
        let s = el.to_string();
        assert!(!s.contains("secret"));
        let doc = xml::parse(&s).unwrap();
        assert_eq!(decrypt(doc.root_element(), &rsa_pkcs8()).unwrap(), plain);
        assert!(decrypt(doc.root_element(), &other_rsa_pkcs8()).is_err());
    }

    #[test]
    fn every_combination_round_trips() {
        for data in [
            DataEncryption::Aes256Gcm,
            DataEncryption::Aes128Gcm,
            DataEncryption::Aes256Cbc,
            DataEncryption::Aes128Cbc,
        ] {
            for transport in [KeyTransport::RsaOaepMgf1p, KeyTransport::RsaOaepSha256] {
                round_trip(data, transport);
            }
        }
    }

    #[test]
    fn tampered_gcm_ciphertext_is_refused() {
        let el = encrypt(
            "<a/>",
            &rsa_cert(),
            DataEncryption::Aes256Gcm,
            KeyTransport::RsaOaepMgf1p,
        )
        .unwrap()
        .to_string();
        let doc = xml::parse(&el).unwrap();
        let root = doc.root_element();
        let data = required(root, ns::XENC, "CipherData").unwrap();
        let value = text_of(required(data, ns::XENC, "CipherValue").unwrap());
        let mut bytes = base64_content(&value).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let tampered = el.replace(&value, &STANDARD.encode(&bytes));
        let doc = xml::parse(&tampered).unwrap();
        assert!(decrypt(doc.root_element(), &rsa_pkcs8()).is_err());
    }

    #[test]
    fn xmlsec1_decrypts_what_we_encrypt() {
        use crate::saml::testkit::{rsa_key_pem, scratch, xmlsec1, xmlsec1_is_1_2, xmlsec1_lax};
        let Some(tool) = xmlsec1() else {
            eprintln!("xmlsec1 not installed; interop not checked");
            return;
        };
        let dir = scratch("xmlenc");
        let key = dir.join("key.pem");
        std::fs::write(&key, rsa_key_pem()).unwrap();
        let plain = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a"><saml:Issuer>é</saml:Issuer></saml:Assertion>"#;
        for data in [DataEncryption::Aes256Gcm, DataEncryption::Aes128Cbc] {
            for transport in [KeyTransport::RsaOaepMgf1p, KeyTransport::RsaOaepSha256] {
                // xmlsec1 1.2 predates XML-Enc 1.1's `rsa-oaep`; SPs built
                // on it need the default, `rsa-oaep-mgf1p`.
                if transport == KeyTransport::RsaOaepSha256 && xmlsec1_is_1_2() {
                    continue;
                }
                let el = encrypt(plain, &rsa_cert(), data, transport).unwrap();
                let file = dir.join("enc.xml");
                std::fs::write(&file, el.to_string()).unwrap();
                let out = std::process::Command::new(&tool)
                    .arg("--decrypt")
                    .args(xmlsec1_lax())
                    .arg("--privkey-pem")
                    .arg(&key)
                    .arg(&file)
                    .output()
                    .unwrap();
                assert!(
                    out.status.success(),
                    "{data:?}/{transport:?}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                // xmlsec1 re-serializes (`é` as a character reference), so
                // the two are compared canonically.
                let got = String::from_utf8(out.stdout).unwrap();
                let got = xml::parse(&got).unwrap();
                let want = xml::parse(plain).unwrap();
                assert_eq!(
                    crate::saml::c14n::canonicalize(got.root_element(), None, &[]),
                    crate::saml::c14n::canonicalize(want.root_element(), None, &[]),
                    "{data:?}/{transport:?}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
