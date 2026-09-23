//! What the HTTP backends (Vault, Cloud KMS, Key Vault) share: a client for
//! an operator-configured endpoint, and how an answer maps onto
//! [`ProviderError`].
//!
//! These endpoints come from the deployment's own configuration, never from a
//! tenant, so they do not go through the outbound SSRF resolver: a Vault on a
//! private address is the normal case. Redirects are not followed, so a token
//! is only ever sent where it was configured to go.

use std::io::BufReader;
use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use ridm_core::providers::ProviderError;
use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use serde_json::Value;
use zeroize::Zeroizing;

const TIMEOUT: Duration = Duration::from_secs(15);

/// Longest part of an error body quoted in a message.
const ERROR_BODY_MAX: usize = 300;

pub fn client(ca_file: Option<&Path>) -> Result<reqwest::Client, ProviderError> {
    let mut builder = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(path) = ca_file {
        let file = std::fs::File::open(path).map_err(|e| {
            ProviderError::Configuration(format!("CA file {}: {e}", path.display()))
        })?;
        let certs = CertificateDer::pem_reader_iter(&mut BufReader::new(file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                ProviderError::Configuration(format!("CA file {}: {e}", path.display()))
            })?;
        if certs.is_empty() {
            return Err(ProviderError::Configuration(format!(
                "CA file {} holds no certificate",
                path.display()
            )));
        }
        let certs = certs
            .iter()
            .map(|der| reqwest::Certificate::from_der(der.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ProviderError::Configuration(format!("CA file: {e}")))?;
        builder = builder.tls_certs_only(certs);
    }
    builder
        .build()
        .map_err(|e| ProviderError::Configuration(format!("http client: {e}")))
}

/// Send `request` and read a JSON answer. Transport failures, 5xx and 429
/// are retryable; 401/403 are the deployment's credentials; anything else is
/// a refusal.
pub async fn json(request: reqwest::RequestBuilder, what: &str) -> Result<Value, ProviderError> {
    let response = request
        .send()
        .await
        .map_err(|e| ProviderError::Unavailable(format!("{what}: {}", without_url(&e))))?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|e| ProviderError::Unavailable(format!("{what}: {}", without_url(&e))))?;
    if status.is_success() {
        return serde_json::from_slice(&body)
            .map_err(|e| ProviderError::Rejected(format!("{what}: unreadable answer: {e}")));
    }
    let detail: String = String::from_utf8_lossy(&body)
        .chars()
        .take(ERROR_BODY_MAX)
        .collect();
    let msg = format!("{what}: HTTP {status}: {detail}");
    Err(match status.as_u16() {
        429 | 500..=599 => ProviderError::Unavailable(msg),
        401 | 403 => ProviderError::Configuration(msg),
        _ => ProviderError::Rejected(msg),
    })
}

/// The string at `pointer` (`/data/ciphertext`).
pub fn string<'a>(value: &'a Value, pointer: &str, what: &str) -> Result<&'a str, ProviderError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| ProviderError::Rejected(format!("{what}: answer has no `{pointer}`")))
}

/// Standard base64 (with or without padding) into key material.
pub fn decode_b64(v: &str, what: &str) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    STANDARD
        .decode(v)
        .or_else(|_| STANDARD_NO_PAD.decode(v))
        .or_else(|_| URL_SAFE_NO_PAD.decode(v))
        .map(Zeroizing::new)
        .map_err(|_| ProviderError::Rejected(format!("{what}: not base64")))
}

#[cfg(any(feature = "kms-vault", feature = "kms-gcp"))]
pub fn b64(v: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(v)
}

#[cfg(feature = "kms-azure")]
pub fn b64url(v: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v)
}

/// A reqwest error's text without the URL, whose query may carry a token.
fn without_url(e: &reqwest::Error) -> String {
    let mut s = e.to_string();
    if let Some(url) = e.url() {
        s = s.replace(url.as_str(), "<endpoint>");
    }
    s
}

/// Read a token file (a projected service-account or federated token).
pub async fn read_token_file(path: &Path, what: &str) -> Result<Zeroizing<String>, ProviderError> {
    let raw = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| ProviderError::Configuration(format!("{what} {}: {e}", path.display())))?;
    let token = raw.trim();
    if token.is_empty() {
        return Err(ProviderError::Configuration(format!(
            "{what} {} is empty",
            path.display()
        )));
    }
    Ok(Zeroizing::new(token.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_variants_decode() {
        assert_eq!(&*decode_b64("AQID", "t").unwrap(), &[1, 2, 3]);
        assert_eq!(&*decode_b64("AQI=", "t").unwrap(), &[1, 2]);
        assert_eq!(&*decode_b64("AQI", "t").unwrap(), &[1, 2]);
        assert_eq!(&*decode_b64("-_8", "t").unwrap(), &[0xfb, 0xff]);
        assert!(decode_b64("***", "t").is_err());
    }
}
