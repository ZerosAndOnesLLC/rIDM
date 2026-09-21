//! Keys shared by the SAML unit tests: RSA generation is slow in debug
//! builds, so each is made once per test binary.

use std::sync::OnceLock;

/// An RSA-2048 private key, PKCS#8 DER.
pub fn rsa_pkcs8() -> Vec<u8> {
    static KEY: OnceLock<Vec<u8>> = OnceLock::new();
    KEY.get_or_init(generate_rsa).clone()
}

/// A second, unrelated RSA key.
pub fn other_rsa_pkcs8() -> Vec<u8> {
    static KEY: OnceLock<Vec<u8>> = OnceLock::new();
    KEY.get_or_init(generate_rsa).clone()
}

fn generate_rsa() -> Vec<u8> {
    crate::services::keys::generate(
        crate::models::SigningAlg::RS256,
        crate::models::RsaBits::B2048,
    )
    .expect("RSA key generation")
    .private_der
    .to_vec()
}

/// A self-signed certificate for [`rsa_pkcs8`].
pub fn rsa_cert() -> crate::saml::cert::Certificate {
    static CERT: OnceLock<Vec<u8>> = OnceLock::new();
    let der = CERT.get_or_init(|| crate::saml::cert::self_signed(&rsa_pkcs8(), "test", 1).unwrap());
    crate::saml::cert::Certificate::from_der(der.clone()).unwrap()
}

/// A self-signed certificate for [`other_rsa_pkcs8`].
pub fn other_rsa_cert() -> crate::saml::cert::Certificate {
    static CERT: OnceLock<Vec<u8>> = OnceLock::new();
    let der = CERT
        .get_or_init(|| crate::saml::cert::self_signed(&other_rsa_pkcs8(), "other", 1).unwrap());
    crate::saml::cert::Certificate::from_der(der.clone()).unwrap()
}

/// The `xmlsec1` command-line tool, when installed: an independent XML
/// signature and encryption implementation to check rIDM's against. The
/// interop tests skip without it, unless `RIDM_REQUIRE_XMLSEC1` is set, as
/// CI sets it.
pub fn xmlsec1() -> Option<std::path::PathBuf> {
    let found = std::process::Command::new("xmlsec1")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !found && std::env::var_os("RIDM_REQUIRE_XMLSEC1").is_some() {
        panic!("RIDM_REQUIRE_XMLSEC1 is set but xmlsec1 is not installed");
    }
    found.then(|| "xmlsec1".into())
}

/// `--lax-key-search` where it exists: xmlsec1 1.3 searches keys strictly by
/// default and needs it; 1.2 (Ubuntu's) is lax already and refuses the flag.
pub fn xmlsec1_lax() -> Vec<&'static str> {
    let version = std::process::Command::new("xmlsec1")
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    if version.contains(" 1.2.") {
        vec![]
    } else {
        vec!["--lax-key-search"]
    }
}

/// A scratch directory for files handed to `xmlsec1`.
pub fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ridm-saml-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// [`rsa_pkcs8`] as PEM.
pub fn rsa_key_pem() -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(rsa_pkcs8());
    let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END PRIVATE KEY-----\n");
    out
}
