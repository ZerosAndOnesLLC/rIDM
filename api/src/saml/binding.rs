//! The two browser bindings (SAML Bindings §3.4, §3.5).
//!
//! HTTP-Redirect: the message is DEFLATEd, base64'd and put in the query
//! string; a signature covers the query parameters as they were encoded,
//! not the XML. HTTP-POST: the message is base64'd into an auto-submitting
//! form; a signature, if any, is inside the XML.

use std::io::{Read as _, Write as _};

use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;

use super::cert::{Certificate, SignatureAlg};
use super::dsig::Signer;
use super::error::{SamlError, SamlResult};
use super::xml::MAX_DOCUMENT_BYTES;

/// Longest `RelayState` accepted. The spec says 80 bytes; SPs in the wild
/// send far more (a return URL), so this is generous but bounded.
pub const MAX_RELAY_STATE: usize = 2048;

/// Which parameter carries the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Request,
    Response,
}

impl Kind {
    pub fn param(self) -> &'static str {
        match self {
            Self::Request => "SAMLRequest",
            Self::Response => "SAMLResponse",
        }
    }
}

/// A detached Redirect-binding signature, to check against the sender's
/// registered certificates.
#[derive(Debug, Clone)]
pub struct RedirectSignature {
    pub alg: SignatureAlg,
    pub value: Vec<u8>,
    /// The octets that were signed: the parameters in their received
    /// encoding, in the order the spec fixes.
    pub signed: String,
}

impl RedirectSignature {
    pub fn verify(&self, certs: &[Certificate]) -> SamlResult<()> {
        if certs.is_empty() {
            return Err(SamlError::signature(
                "no certificate is registered to verify with",
            ));
        }
        if certs
            .iter()
            .any(|c| c.verify(self.alg, self.signed.as_bytes(), &self.value))
        {
            Ok(())
        } else {
            Err(SamlError::signature(
                "the signature does not verify with a registered certificate",
            ))
        }
    }
}

/// A message as it arrived, decoded to its XML.
#[derive(Debug, Clone)]
pub struct Received {
    pub kind: Kind,
    pub xml: String,
    pub relay_state: Option<String>,
    /// Redirect binding only: the query-string signature, if one was sent.
    pub signature: Option<RedirectSignature>,
}

fn decode_component(raw: &str) -> String {
    url::form_urlencoded::parse(format!("x={raw}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

fn relay_state(v: Option<String>) -> SamlResult<Option<String>> {
    match v {
        Some(r) if r.len() > MAX_RELAY_STATE => Err(SamlError::malformed("RelayState is too long")),
        Some(r) if r.is_empty() => Ok(None),
        other => Ok(other),
    }
}

fn inflate(compressed: &[u8]) -> SamlResult<String> {
    let mut out = Vec::new();
    DeflateDecoder::new(compressed)
        .take(MAX_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| SamlError::malformed("the message is not DEFLATE-compressed"))?;
    if out.len() > MAX_DOCUMENT_BYTES {
        return Err(SamlError::malformed("the message is too large"));
    }
    String::from_utf8(out).map_err(|_| SamlError::malformed("the message is not UTF-8"))
}

/// Read an HTTP-Redirect message from the raw (still percent-encoded)
/// query string.
pub fn from_redirect(raw_query: &str) -> SamlResult<Received> {
    let mut message: Option<(Kind, &str)> = None;
    let (mut relay, mut sig_alg, mut signature): (Option<&str>, Option<&str>, Option<&str>) =
        (None, None, None);
    for pair in raw_query.split('&').filter(|p| !p.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let slot = match name {
            "SAMLRequest" | "SAMLResponse" => {
                if message.is_some() {
                    return Err(SamlError::malformed("more than one SAML message"));
                }
                let kind = if name == "SAMLRequest" {
                    Kind::Request
                } else {
                    Kind::Response
                };
                message = Some((kind, value));
                continue;
            }
            "RelayState" => &mut relay,
            "SigAlg" => &mut sig_alg,
            "Signature" => &mut signature,
            _ => continue,
        };
        if slot.replace(value).is_some() {
            return Err(SamlError::malformed(format!("{name} is repeated")));
        }
    }
    let (kind, raw_message) = message.ok_or_else(|| SamlError::malformed("no SAML message"))?;
    if raw_message.len() > MAX_DOCUMENT_BYTES {
        return Err(SamlError::malformed("the message is too large"));
    }
    let compressed = super::xml::base64_content(&decode_component(raw_message))?;
    let xml = inflate(&compressed)?;

    let signature = match (sig_alg, signature) {
        (None, None) => None,
        (Some(a), Some(s)) => {
            let mut signed = format!("{}={raw_message}", kind.param());
            if let Some(r) = relay {
                signed.push_str("&RelayState=");
                signed.push_str(r);
            }
            signed.push_str("&SigAlg=");
            signed.push_str(a);
            Some(RedirectSignature {
                alg: SignatureAlg::from_uri(&decode_component(a))?,
                value: super::xml::base64_content(&decode_component(s))?,
                signed,
            })
        }
        _ => return Err(SamlError::signature("SigAlg and Signature come together")),
    };
    Ok(Received {
        kind,
        xml,
        relay_state: relay_state(relay.map(decode_component))?,
        signature,
    })
}

/// Read an HTTP-POST message from its form fields.
pub fn from_post(kind: Kind, encoded: &str, relay: Option<String>) -> SamlResult<Received> {
    if encoded.len() > MAX_DOCUMENT_BYTES / 3 * 4 + 4 {
        return Err(SamlError::malformed("the message is too large"));
    }
    let bytes = super::xml::base64_content(encoded)?;
    let xml =
        String::from_utf8(bytes).map_err(|_| SamlError::malformed("the message is not UTF-8"))?;
    Ok(Received {
        kind,
        xml,
        relay_state: relay_state(relay)?,
        signature: None,
    })
}

fn encode_component(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// The URL that delivers `xml` to `endpoint` by HTTP-Redirect, signed
/// when a signer is given.
pub fn to_redirect(
    endpoint: &str,
    kind: Kind,
    xml: &str,
    relay: Option<&str>,
    signer: Option<&Signer>,
) -> SamlResult<String> {
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
    enc.write_all(xml.as_bytes())
        .and_then(|_| enc.flush())
        .map_err(|_| SamlError::Crypto("compression failed".into()))?;
    let compressed = enc
        .finish()
        .map_err(|_| SamlError::Crypto("compression failed".into()))?;
    let mut query = format!(
        "{}={}",
        kind.param(),
        encode_component(&STANDARD.encode(compressed))
    );
    if let Some(r) = relay {
        query.push_str("&RelayState=");
        query.push_str(&encode_component(r));
    }
    if let Some(signer) = signer {
        query.push_str("&SigAlg=");
        query.push_str(&encode_component(signer.alg().uri()));
        let sig = signer.sign(query.as_bytes())?;
        query.push_str("&Signature=");
        query.push_str(&encode_component(&STANDARD.encode(sig)));
    }
    let sep = if endpoint.contains('?') { '&' } else { '?' };
    Ok(format!("{endpoint}{sep}{query}"))
}

/// The auto-submitting page that delivers `xml` to `endpoint` by HTTP-POST.
pub fn to_post(endpoint: &str, kind: Kind, xml: &str, relay: Option<&str>) -> Response {
    let mut params = vec![(kind.param(), STANDARD.encode(xml.as_bytes()))];
    if let Some(r) = relay {
        params.push(("RelayState", r.to_string()));
    }
    crate::oidc::authorize::deliver(
        endpoint,
        crate::services::login_flows::ResponseMode::FormPost,
        &params,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::saml::testkit::{other_rsa_cert, rsa_cert, rsa_pkcs8};

    fn signer() -> Signer {
        Signer::new(&rsa_pkcs8(), &rsa_cert().der).unwrap()
    }

    fn query_of(url: &str) -> &str {
        url.split_once('?').unwrap().1
    }

    #[test]
    fn a_signed_redirect_round_trips() {
        let url = to_redirect(
            "https://sp.example/slo?x=1",
            Kind::Request,
            "<a>é &amp; b</a>",
            Some("state/with?chars=&"),
            Some(&signer()),
        )
        .unwrap();
        assert!(url.starts_with("https://sp.example/slo?x=1&SAMLRequest="));
        let got = from_redirect(query_of(&url)).unwrap();
        assert_eq!(got.kind, Kind::Request);
        assert_eq!(got.xml, "<a>é &amp; b</a>");
        assert_eq!(got.relay_state.as_deref(), Some("state/with?chars=&"));
        let sig = got.signature.unwrap();
        sig.verify(&[rsa_cert()]).unwrap();
        assert!(sig.verify(&[other_rsa_cert()]).is_err());
    }

    #[test]
    fn a_changed_parameter_breaks_the_signature() {
        let url = to_redirect(
            "https://sp",
            Kind::Response,
            "<a/>",
            Some("one"),
            Some(&signer()),
        )
        .unwrap();
        let tampered = url.replace("RelayState=one", "RelayState=two");
        let got = from_redirect(query_of(&tampered)).unwrap();
        assert!(got.signature.unwrap().verify(&[rsa_cert()]).is_err());
        // Dropping the signature leaves an unsigned message, which the
        // caller decides about; dropping half of it is an error.
        let half = url.split("&Signature=").next().unwrap().to_string();
        assert!(from_redirect(query_of(&half)).is_err());
    }

    #[test]
    fn unsigned_and_repeated_and_oversized_messages() {
        let url = to_redirect("https://sp", Kind::Request, "<a/>", None, None).unwrap();
        let got = from_redirect(query_of(&url)).unwrap();
        assert!(got.signature.is_none() && got.relay_state.is_none());
        let q = query_of(&url);
        assert!(from_redirect(&format!("{q}&{q}")).is_err());
        assert!(from_redirect("RelayState=x").is_err());
        // A DEFLATE bomb: tiny compressed, too big inflated.
        let bomb = "a".repeat(MAX_DOCUMENT_BYTES + 10);
        let url = to_redirect("https://sp", Kind::Request, &bomb, None, None).unwrap();
        assert!(query_of(&url).len() < 4096);
        assert!(
            from_redirect(query_of(&url))
                .unwrap_err()
                .to_string()
                .contains("too large")
        );
        let long = format!(
            "{}&RelayState={}",
            query_of(&to_redirect("https://sp", Kind::Request, "<a/>", None, None).unwrap()),
            "r".repeat(MAX_RELAY_STATE + 1)
        );
        assert!(from_redirect(&long).is_err());
    }

    #[test]
    fn post_messages_are_plain_base64() {
        let got = from_post(
            Kind::Response,
            &STANDARD.encode("<a/>"),
            Some(String::new()),
        )
        .unwrap();
        assert_eq!(got.xml, "<a/>");
        assert!(got.relay_state.is_none());
        assert!(from_post(Kind::Response, "%%%", None).is_err());
    }
}
