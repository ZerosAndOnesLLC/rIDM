//! Mutual-TLS client authentication and certificate-bound tokens (RFC 8705).
//!
//! A client certificate reaches rIDM in one of two ways:
//!
//! * over rIDM's own mTLS listener (`MTLS_BIND`, see [`crate::tls`]), which
//!   asks every connection for a certificate, checks the handshake signature
//!   (so the client holds the key) and hands the chain to the request as
//!   [`PeerCertificates`];
//! * in a header (`CLIENT_CERT_HEADER`) set by a reverse proxy that
//!   terminated the connection, believed only from a `TRUSTED_PROXIES` peer.
//!
//! What the certificate proves is decided here, per client:
//!
//! * `tls_client_auth` (§2.1): the chain reaches one of the tenant's trust
//!   anchors (`mtls_trust_anchors`), the certificate is valid now and allows
//!   client authentication, and it carries the one subject registered for the
//!   client (subject DN, or a DNS, URI, IP or email SAN);
//! * `self_signed_tls_client_auth` (§2.2): the certificate is one of those in
//!   the client's JWK Set (`x5c`), with no chain to check;
//! * certificate-bound tokens (§3): whatever the client authenticated with,
//!   its access tokens carry `cnf.x5t#S256`, the certificate's SHA-256
//!   thumbprint, and a resource refuses them without that certificate.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{Extensions, HeaderMap};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rustls::pki_types::{CertificateDer, UnixTime};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use x509_parser::prelude::{FromDer as _, GeneralName, X509Certificate, X509Name};

use crate::error::{OAuthError, OAuthErrorCode};
use crate::middleware::TenantCtx;
use crate::models::{Client, TokenEndpointAuthMethod};
use crate::services::{client_keys, mtls_trust_anchors};
use crate::state::AppState;

/// The `cnf` member a certificate-bound token carries (RFC 8705 §3.1).
pub const CNF_X5T: &str = "x5t#S256";
/// Largest header value a proxy may hand over, and the most certificates in it.
const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_CHAIN: usize = 5;

/// The chain a client presented on rIDM's own mTLS listener, leaf first. The
/// listener has already checked that the client holds the leaf's key.
#[derive(Debug, Clone)]
pub struct PeerCertificates(pub Arc<[CertificateDer<'static>]>);

/// A client certificate, parsed once.
#[derive(Debug, Clone)]
pub struct ClientCert {
    der: Vec<u8>,
    chain: Vec<Vec<u8>>,
    thumbprint: String,
    subject: Vec<Vec<(String, Option<String>)>>,
    subject_dn: String,
    /// See [`ClientCert::subject_is_textual`].
    textual: bool,
    dns: Vec<String>,
    uris: Vec<String>,
    ips: Vec<IpAddr>,
    emails: Vec<String>,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

impl ClientCert {
    /// Parse a leaf and the intermediates that came with it; `None` when the
    /// leaf is not an X.509 certificate.
    pub fn from_chain(leaf: Vec<u8>, chain: Vec<Vec<u8>>) -> Option<Self> {
        let (rest, cert) = X509Certificate::from_der(&leaf).ok()?;
        if !rest.is_empty() {
            return None;
        }
        let subject = name_parts(cert.subject());
        let subject_dn = format_dn(&subject);
        // Only a subject whose printed DN names it again can be registered:
        // every attribute a string under a well-formed OID, and the string
        // parsing back to the same RDNs (a mangled certificate can carry an
        // attribute type with no OID, which prints as `=`).
        let textual = !subject.is_empty()
            && subject.iter().all(|rdn| {
                !rdn.is_empty() && rdn.iter().all(|(oid, v)| v.is_some() && is_dotted_oid(oid))
            })
            && dn_matches(&subject, &subject_dn);
        let (mut dns, mut uris, mut ips, mut emails) = (vec![], vec![], vec![], vec![]);
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for name in &san.value.general_names {
                match name {
                    GeneralName::DNSName(d) => dns.push(d.to_ascii_lowercase()),
                    GeneralName::URI(u) => uris.push((*u).to_string()),
                    GeneralName::RFC822Name(e) => emails.push(e.to_ascii_lowercase()),
                    GeneralName::IPAddress(b) => {
                        if let Some(ip) = ip_from_bytes(b) {
                            ips.push(ip);
                        }
                    }
                    _ => {}
                }
            }
        }
        let validity = cert.validity();
        let at = |t: i64| DateTime::from_timestamp(t, 0).unwrap_or_default();
        let not_before = at(validity.not_before.timestamp());
        let not_after = at(validity.not_after.timestamp());
        let thumbprint = thumbprint(&leaf);
        Some(Self {
            der: leaf,
            chain,
            thumbprint,
            subject,
            subject_dn,
            textual,
            dns,
            uris,
            ips,
            emails,
            not_before,
            not_after,
        })
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// `x5t#S256`: base64url(SHA-256(DER)).
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// The subject as an RFC 4514 string.
    pub fn subject_dn(&self) -> &str {
        &self.subject_dn
    }

    pub fn not_before(&self) -> DateTime<Utc> {
        self.not_before
    }

    pub fn not_after(&self) -> DateTime<Utc> {
        self.not_after
    }

    /// Whether the subject is non-empty, every attribute of it a string
    /// under a well-formed OID, and [`Self::subject_dn`] matches it again, so
    /// that it can be registered and matched. (A certificate that names its
    /// holder only in SANs has an empty subject.)
    pub fn subject_is_textual(&self) -> bool {
        self.textual
    }
}

/// base64url(SHA-256(`der`)), the RFC 8705 §3.1 thumbprint.
pub fn thumbprint(der: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(der))
}

fn ip_from_bytes(b: &[u8]) -> Option<IpAddr> {
    match b.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(b).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(b).ok()?)),
        _ => None,
    }
}

/// The client certificate of this request, if one arrived in a way rIDM
/// believes: the mTLS listener's handshake, else the proxy header from a
/// trusted peer. A header from anyone else is ignored.
pub fn presented(
    state: &AppState,
    extensions: &Extensions,
    headers: &HeaderMap,
) -> Option<ClientCert> {
    if let Some(PeerCertificates(chain)) = extensions.get::<PeerCertificates>() {
        let mut it = chain.iter().map(|c| c.as_ref().to_vec());
        let leaf = it.next()?;
        return ClientCert::from_chain(leaf, it.take(MAX_CHAIN - 1).collect());
    }
    let name = state.config.mtls.cert_header.as_deref()?;
    let peer = extensions.get::<ConnectInfo<SocketAddr>>()?.0.ip();
    if !state
        .config
        .trusted_proxies
        .iter()
        .any(|n| n.contains(&peer))
    {
        return None;
    }
    let value = headers.get(name)?.to_str().ok()?;
    let mut ders = parse_header(value)?.into_iter();
    let leaf = ders.next()?;
    ClientCert::from_chain(leaf, ders.collect())
}

/// The request's client certificate as an extractor; never rejects.
#[derive(Debug, Clone, Default)]
pub struct ClientCertificate(pub Option<Arc<ClientCert>>);

impl ClientCertificate {
    pub fn get(&self) -> Option<&ClientCert> {
        self.0.as_deref()
    }
}

impl FromRequestParts<AppState> for ClientCertificate {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(
            presented(state, &parts.extensions, &parts.headers).map(Arc::new),
        ))
    }
}

/// The certificates in a proxy's header, leaf first, as DER. Accepted forms:
///
/// * PEM, possibly URL-encoded (nginx `$ssl_client_escaped_cert`, HAProxy,
///   Envoy's `Cert=` value), one or more `CERTIFICATE` blocks;
/// * base64 DER, possibly URL-encoded, several separated by commas (Caddy's
///   `certificate_der_base64`, Traefik's `X-Forwarded-Tls-Client-Cert`).
///
/// `None` for anything else, or more than it should hold.
pub fn parse_header(value: &str) -> Option<Vec<Vec<u8>>> {
    if value.is_empty() || value.len() > MAX_HEADER_BYTES {
        return None;
    }
    let decoded = percent_decode(value.trim())?;
    let ders = if decoded.contains("-----BEGIN") {
        pem_blocks(&decoded)?
    } else {
        decoded
            .split(',')
            .map(|part| decode_base64(part.trim().trim_matches('"')))
            .collect::<Option<Vec<_>>>()?
    };
    (!ders.is_empty() && ders.len() <= MAX_CHAIN && ders.iter().all(|d| !d.is_empty()))
        .then_some(ders)
}

/// `%XX` decoding that leaves `+` alone (base64 is full of them).
fn percent_decode(s: &str) -> Option<String> {
    if !s.contains('%') {
        return Some(s.to_string());
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            let hex = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn decode_base64(s: &str) -> Option<Vec<u8>> {
    let compact: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.is_empty() {
        return None;
    }
    STANDARD.decode(compact).ok()
}

/// Every `CERTIFICATE` block of a PEM text, in order.
fn pem_blocks(text: &str) -> Option<Vec<Vec<u8>>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = vec![];
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let body = &rest[start + BEGIN.len()..];
        let end = body.find(END)?;
        out.push(decode_base64(&body[..end])?);
        if out.len() > MAX_CHAIN {
            return None;
        }
        rest = &body[end + END.len()..];
    }
    Some(out)
}

/// Short names RFC 4514 §3 defines, plus the email and serial number
/// attributes certificates commonly carry.
const NAMES: &[(&str, &str)] = &[
    ("CN", "2.5.4.3"),
    ("SERIALNUMBER", "2.5.4.5"),
    ("C", "2.5.4.6"),
    ("L", "2.5.4.7"),
    ("ST", "2.5.4.8"),
    ("STREET", "2.5.4.9"),
    ("O", "2.5.4.10"),
    ("OU", "2.5.4.11"),
    ("DC", "0.9.2342.19200300.100.1.25"),
    ("UID", "0.9.2342.19200300.100.1.1"),
    ("EMAILADDRESS", "1.2.840.113549.1.9.1"),
];

fn oid_of(name: &str) -> Option<String> {
    let upper = name.trim().to_ascii_uppercase();
    let upper = upper.strip_prefix("OID.").unwrap_or(&upper);
    if let Some((_, oid)) = NAMES.iter().find(|(n, _)| *n == upper) {
        return Some((*oid).to_string());
    }
    if upper == "E" {
        return Some("1.2.840.113549.1.9.1".into());
    }
    is_dotted_oid(upper).then(|| upper.to_string())
}

/// `1.2.840…`: non-empty arcs of digits.
fn is_dotted_oid(s: &str) -> bool {
    !s.is_empty()
        && s.split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn name_of(oid: &str) -> &str {
    NAMES
        .iter()
        .find(|(_, o)| *o == oid)
        .map(|(n, _)| *n)
        .unwrap_or(oid)
}

/// A certificate name as RDNs in RFC 4514 order (most specific first), each
/// a list of (OID, string value); a value that is not a string is `None`
/// and matches nothing.
fn name_parts(name: &X509Name<'_>) -> Vec<Vec<(String, Option<String>)>> {
    let mut rdns: Vec<Vec<(String, Option<String>)>> = name
        .iter()
        .map(|rdn| {
            rdn.iter()
                .map(|atv| {
                    (
                        atv.attr_type().to_id_string(),
                        atv.as_str().ok().map(str::to_string),
                    )
                })
                .collect()
        })
        .collect();
    rdns.reverse();
    rdns
}

/// RFC 4514 string of a name from [`name_parts`].
fn format_dn(rdns: &[Vec<(String, Option<String>)>]) -> String {
    rdns.iter()
        .map(|rdn| {
            rdn.iter()
                .map(|(oid, value)| match value {
                    Some(v) => format!("{}={}", name_of(oid), escape_value(v)),
                    None => format!("{}=#", name_of(oid)),
                })
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn escape_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let last = v.chars().count().saturating_sub(1);
    for (i, c) in v.chars().enumerate() {
        let lead = i == 0 && (c == ' ' || c == '#');
        let trail = i == last && c == ' ';
        if lead || trail || matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=') {
            out.push('\\');
            out.push(c);
        } else if c == '\0' {
            out.push_str("\\00");
        } else {
            out.push(c);
        }
    }
    out
}

/// Parse an RFC 4514 distinguished name into RDNs of (OID, value). Types may
/// be short names or dotted OIDs; `#`-hex values are not supported. Spaces
/// around a value are dropped unless escaped (`\ `).
pub fn parse_dn(dn: &str) -> Result<Vec<Vec<(String, String)>>, String> {
    if dn.trim().is_empty() {
        return Err("the subject DN is empty".into());
    }
    let mut rdns = vec![];
    let mut rdn = vec![];
    let mut chars = dn.chars().peekable();
    loop {
        // attribute type
        let mut ty = String::new();
        for c in chars.by_ref() {
            if c == '=' {
                break;
            }
            ty.push(c);
        }
        let oid = oid_of(&ty).ok_or_else(|| format!("unknown attribute type `{}`", ty.trim()))?;
        // attribute value, each character marked when it came escaped
        let mut value: Vec<(char, bool)> = vec![];
        let mut pending: Vec<u8> = vec![];
        let mut end = None;
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    let next = chars.next().ok_or("a trailing backslash")?;
                    if next.is_ascii_hexdigit() {
                        let lo = chars
                            .next()
                            .filter(char::is_ascii_hexdigit)
                            .ok_or("a bad \\XX escape")?;
                        let byte = u8::from_str_radix(&format!("{next}{lo}"), 16)
                            .map_err(|e| e.to_string())?;
                        pending.push(byte);
                        continue;
                    }
                    flush(&mut pending, &mut value)?;
                    value.push((next, true));
                }
                ',' | ';' | '+' => {
                    end = Some(c);
                    break;
                }
                _ => {
                    flush(&mut pending, &mut value)?;
                    value.push((c, false));
                }
            }
        }
        flush(&mut pending, &mut value)?;
        let bare = |&(c, escaped): &(char, bool)| !escaped && c.is_whitespace();
        let start = value.iter().position(|x| !bare(x)).unwrap_or(value.len());
        let stop = value
            .iter()
            .rposition(|x| !bare(x))
            .map_or(start, |i| i + 1);
        if value.get(start) == Some(&('#', false)) {
            return Err("hex-encoded (#) attribute values are not supported".into());
        }
        let value: String = value[start..stop].iter().map(|(c, _)| c).collect();
        rdn.push((oid, value));
        match end {
            Some('+') => {}
            Some(_) => rdns.push(std::mem::take(&mut rdn)),
            None => {
                rdns.push(rdn);
                break;
            }
        }
    }
    Ok(rdns)
}

fn flush(pending: &mut Vec<u8>, value: &mut Vec<(char, bool)>) -> Result<(), String> {
    if !pending.is_empty() {
        let text = std::str::from_utf8(pending).map_err(|_| "an escape that is not UTF-8")?;
        value.extend(text.chars().map(|c| (c, true)));
        pending.clear();
    }
    Ok(())
}

/// Case-insensitive, whitespace-collapsing comparison (LDAP `caseIgnoreMatch`).
fn same_value(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        s.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    };
    norm(a) == norm(b)
}

/// Whether a certificate's subject is the registered DN: the same RDNs in
/// the same order, each with the same attributes (in any order within it).
pub fn subject_matches(cert: &ClientCert, registered: &str) -> bool {
    dn_matches(&cert.subject, registered)
}

fn dn_matches(subject: &[Vec<(String, Option<String>)>], registered: &str) -> bool {
    let Ok(want) = parse_dn(registered) else {
        return false;
    };
    want.len() == subject.len()
        && want.iter().zip(subject).all(|(w, have)| {
            w.len() == have.len()
                && w.iter().all(|(oid, v)| {
                    have.iter().any(|(o, hv)| {
                        o == oid && hv.as_deref().is_some_and(|hv| same_value(hv, v))
                    })
                })
        })
}

/// Whether `cert` carries the subject registered for a `tls_client_auth`
/// client (RFC 8705 §2.1.2).
pub fn carries_registered_subject(client: &Client, cert: &ClientCert) -> bool {
    if let Some(dn) = &client.tls_client_auth_subject_dn {
        return subject_matches(cert, dn);
    }
    if let Some(dns) = &client.tls_client_auth_san_dns {
        return cert.dns.iter().any(|d| d.eq_ignore_ascii_case(dns));
    }
    if let Some(uri) = &client.tls_client_auth_san_uri {
        return cert.uris.iter().any(|u| u == uri);
    }
    if let Some(ip) = &client.tls_client_auth_san_ip {
        return ip.parse::<IpAddr>().is_ok_and(|ip| cert.ips.contains(&ip));
    }
    if let Some(email) = &client.tls_client_auth_san_email {
        return cert.emails.iter().any(|e| e.eq_ignore_ascii_case(email));
    }
    false
}

/// Check the registered subject a `tls_client_auth` client would be matched
/// by, at registration.
pub fn validate_registered_subject(client: &Client) -> Result<(), String> {
    for (name, value, max) in [
        (
            "tls_client_auth_subject_dn",
            &client.tls_client_auth_subject_dn,
            1024,
        ),
        (
            "tls_client_auth_san_dns",
            &client.tls_client_auth_san_dns,
            253,
        ),
        (
            "tls_client_auth_san_uri",
            &client.tls_client_auth_san_uri,
            2048,
        ),
        ("tls_client_auth_san_ip", &client.tls_client_auth_san_ip, 45),
        (
            "tls_client_auth_san_email",
            &client.tls_client_auth_san_email,
            320,
        ),
    ] {
        if value.as_ref().is_some_and(|v| v.len() > max) {
            return Err(format!("{name} is longer than {max} characters"));
        }
    }
    if let Some(dn) = &client.tls_client_auth_subject_dn {
        parse_dn(dn).map_err(|e| format!("tls_client_auth_subject_dn: {e}"))?;
    }
    if let Some(ip) = &client.tls_client_auth_san_ip
        && ip.parse::<IpAddr>().is_err()
    {
        return Err("tls_client_auth_san_ip must be an IPv4 or IPv6 address".into());
    }
    if let Some(uri) = &client.tls_client_auth_san_uri
        && url::Url::parse(uri).is_err()
    {
        return Err("tls_client_auth_san_uri must be an absolute URI".into());
    }
    if let Some(email) = &client.tls_client_auth_san_email
        && !email.contains('@')
    {
        return Err("tls_client_auth_san_email must be an email address".into());
    }
    if let Some(dns) = &client.tls_client_auth_san_dns
        && (dns.is_empty() || dns.contains(char::is_whitespace))
    {
        return Err("tls_client_auth_san_dns must be a DNS name".into());
    }
    Ok(())
}

fn invalid_client(desc: &str) -> OAuthError {
    OAuthError::new(OAuthErrorCode::InvalidClient, desc)
}

/// Authenticate a client registered for one of the mTLS methods with the
/// certificate of this request.
pub async fn authenticate_client(
    state: &AppState,
    tenant: &TenantCtx,
    client: &Client,
    cert: Option<&ClientCert>,
) -> Result<(), OAuthError> {
    let cert = cert.ok_or_else(|| invalid_client("a client certificate is required"))?;
    match client.token_endpoint_auth_method {
        TokenEndpointAuthMethod::TlsClientAuth => {
            let Some(verifier) = mtls_trust_anchors::verifier(state, tenant.id())
                .await
                .map_err(OAuthError::from)?
            else {
                return Err(invalid_client(
                    "no certificate authority is configured for client certificates",
                ));
            };
            verifier.verify(cert).map_err(|e| {
                    tracing::debug!(error = %e, client_id = %client.client_id, "client certificate chain refused");
                    invalid_client("the client certificate is not trusted")
                })?;
            if !carries_registered_subject(client, cert) {
                return Err(invalid_client(
                    "the client certificate does not carry the registered subject",
                ));
            }
            Ok(())
        }
        TokenEndpointAuthMethod::SelfSignedTlsClientAuth => {
            let registered = |keys: &[Value]| {
                keys.iter().any(|k| {
                    k["x5c"][0]
                        .as_str()
                        .and_then(decode_base64)
                        .is_some_and(|der| der == cert.der())
                })
            };
            let mut keys = client_keys::jwks(state, client, false)
                .await
                .map_err(OAuthError::from)?;
            if !registered(&keys) && client.jwks_uri.is_some() {
                keys = client_keys::jwks(state, client, true)
                    .await
                    .map_err(OAuthError::from)?;
            }
            if !registered(&keys) {
                return Err(invalid_client(
                    "the client certificate is not registered for this client",
                ));
            }
            Ok(())
        }
        _ => Err(invalid_client(
            "client authentication method does not match the registered method",
        )),
    }
}

/// What the console shows of a trust anchor.
pub struct CaInfo {
    pub subject: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

/// Check that `der` is a CA certificate rIDM can verify chains with.
pub fn describe_ca(der: &[u8]) -> Result<CaInfo, String> {
    let (rest, cert) = X509Certificate::from_der(der).map_err(|_| "not an X.509 certificate")?;
    if !rest.is_empty() {
        return Err("trailing data after the certificate".into());
    }
    if !cert.is_ca() {
        return Err("not a CA certificate (basic constraints cA is not set)".into());
    }
    rustls::RootCertStore::empty()
        .add(CertificateDer::from(der.to_vec()))
        .map_err(|e| format!("unusable as a trust anchor: {e}"))?;
    let parsed = ClientCert::from_chain(der.to_vec(), vec![]).ok_or("not an X.509 certificate")?;
    Ok(CaInfo {
        subject: parsed.subject_dn,
        not_before: parsed.not_before,
        not_after: parsed.not_after,
    })
}

/// A verifier for client certificates against a set of trust anchors,
/// built once and reused for every certificate (see
/// [`mtls_trust_anchors::verifier`]).
pub struct ChainVerifier(Arc<dyn rustls::server::danger::ClientCertVerifier>);

impl ChainVerifier {
    /// From `anchors` (DER); an anchor may itself be an intermediate CA.
    pub fn new(anchors: &[&[u8]]) -> Result<Self, String> {
        let mut roots = rustls::RootCertStore::empty();
        for der in anchors {
            roots
                .add(CertificateDer::from(der.to_vec()))
                .map_err(|e| format!("trust anchor: {e}"))?;
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier =
            rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|e| e.to_string())?;
        Ok(Self(verifier))
    }

    /// Does `cert` chain to one of the anchors, is it valid now, and may it
    /// be used for client authentication? Intermediates come from what the
    /// client presented.
    pub fn verify(&self, cert: &ClientCert) -> Result<(), String> {
        let intermediates: Vec<CertificateDer<'static>> = cert
            .chain
            .iter()
            .map(|d| CertificateDer::from(d.clone()))
            .collect();
        self.0
            .verify_client_cert(
                &CertificateDer::from(cert.der.clone()),
                &intermediates,
                UnixTime::now(),
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// The certificate thumbprint a token is bound to, if any.
pub fn bound_x5t(claims: &Map<String, Value>) -> Option<&str> {
    claims.get("cnf")?.get(CNF_X5T)?.as_str()
}

/// At a resource: a certificate-bound token must arrive with the same
/// certificate (RFC 8705 §3). Unbound tokens pass.
pub fn enforce_binding(
    claims: &Map<String, Value>,
    cert: Option<&ClientCert>,
) -> Result<(), String> {
    let Some(expected) = bound_x5t(claims) else {
        return Ok(());
    };
    match cert {
        None => Err("this token is bound to a client certificate, and none was presented".into()),
        Some(c) if c.thumbprint() != expected => {
            Err("the client certificate does not match the token's binding".into())
        }
        Some(_) => Ok(()),
    }
}

/// `mtls_endpoint_aliases` base for a tenant: `{MTLS_PUBLIC_URL}/t/{slug}`.
pub fn alias_base(state: &AppState, slug: &str) -> Option<String> {
    let base = state.config.mtls.public_url.as_ref()?;
    Some(format!("{}/t/{slug}", base.as_str().trim_end_matches('/')))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_with(dn: &[(rcgen::DnType, &str)], sans: Vec<rcgen::SanType>) -> ClientCert {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::default();
        let mut name = rcgen::DistinguishedName::new();
        for (t, v) in dn {
            name.push(t.clone(), *v);
        }
        params.distinguished_name = name;
        params.subject_alt_names = sans;
        let cert = params.self_signed(&key).expect("cert");
        ClientCert::from_chain(cert.der().to_vec(), vec![]).expect("parse")
    }

    #[test]
    fn the_subject_prints_most_specific_first() {
        let c = cert_with(
            &[
                (rcgen::DnType::CountryName, "US"),
                (rcgen::DnType::OrganizationName, "Acme, Inc."),
                (rcgen::DnType::CommonName, "billing"),
            ],
            vec![],
        );
        assert_eq!(c.subject_dn(), "CN=billing,O=Acme\\, Inc.,C=US");
        assert!(subject_matches(&c, "CN=billing,O=Acme\\, Inc.,C=US"));
        assert!(subject_matches(&c, "cn=Billing, o=acme\\2C inc., c=us"));
        assert!(subject_matches(&c, "2.5.4.3=billing,O=Acme\\, Inc.,C=US"));
        // Another order is another name.
        assert!(!subject_matches(&c, "C=US,O=Acme\\, Inc.,CN=billing"));
        assert!(!subject_matches(&c, "CN=billing,O=Acme\\, Inc."));
        assert!(!subject_matches(&c, "CN=billing2,O=Acme\\, Inc.,C=US"));
    }

    #[test]
    fn dn_parsing_refuses_what_it_cannot_match() {
        assert!(parse_dn("").is_err());
        assert!(parse_dn("XYZ=a").is_err());
        assert!(parse_dn("CN=#0403616263").is_err());
        assert!(parse_dn("CN=a\\").is_err());
        // Escaped spaces and a leading escaped `#` are part of the value.
        assert_eq!(parse_dn("CN=\\ a\\ ").unwrap()[0][0].1, " a ");
        assert_eq!(parse_dn(" CN = a , O=b ").unwrap()[0][0].1, "a");
        assert_eq!(parse_dn("CN=\\#1").unwrap()[0][0].1, "#1");
        let rdns = parse_dn("CN=a+UID=b,DC=example,DC=com").expect("parse");
        assert_eq!(rdns.len(), 3);
        assert_eq!(rdns[0].len(), 2);
    }

    #[test]
    fn sans_are_matched_by_kind() {
        let c = cert_with(
            &[(rcgen::DnType::CommonName, "x")],
            vec![
                rcgen::SanType::DnsName("Svc.Example.com".try_into().expect("dns")),
                rcgen::SanType::URI("spiffe://example.com/billing".try_into().expect("uri")),
                rcgen::SanType::IpAddress("10.1.2.3".parse().expect("ip")),
                rcgen::SanType::Rfc822Name("ops@example.com".try_into().expect("email")),
            ],
        );
        assert_eq!(c.dns, vec!["svc.example.com"]);
        assert_eq!(c.uris, vec!["spiffe://example.com/billing"]);
        assert_eq!(c.ips, vec!["10.1.2.3".parse::<IpAddr>().expect("ip")]);
        assert_eq!(c.emails, vec!["ops@example.com"]);
    }

    #[test]
    fn proxy_headers_in_every_common_form() {
        let c = cert_with(&[(rcgen::DnType::CommonName, "x")], vec![]);
        let b64 = STANDARD.encode(c.der());
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            b64.as_bytes()
                .chunks(64)
                .map(|l| std::str::from_utf8(l).expect("ascii"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        let escaped: String = pem
            .bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect();
        for value in [pem.clone(), escaped, b64.clone(), format!("{b64},{b64}")] {
            let ders = parse_header(&value).expect("parsed");
            assert_eq!(ders[0], c.der(), "{value:.40}");
        }
        assert!(parse_header("").is_none());
        assert!(parse_header("%zz").is_none());
        assert!(parse_header("-----BEGIN CERTIFICATE-----abc").is_none());
        assert!(parse_header(&[b64.as_str(); 6].join(",")).is_none());
        assert!(parse_header(&"A".repeat(MAX_HEADER_BYTES + 1)).is_none());
    }

    #[test]
    fn bound_tokens_need_the_same_certificate() {
        let a = cert_with(&[(rcgen::DnType::CommonName, "a")], vec![]);
        let b = cert_with(&[(rcgen::DnType::CommonName, "b")], vec![]);
        let mut claims = Map::new();
        assert!(enforce_binding(&claims, None).is_ok());
        claims.insert("cnf".into(), serde_json::json!({ CNF_X5T: a.thumbprint() }));
        assert!(enforce_binding(&claims, None).is_err());
        assert!(enforce_binding(&claims, Some(&b)).is_err());
        assert!(enforce_binding(&claims, Some(&a)).is_ok());
    }
}
