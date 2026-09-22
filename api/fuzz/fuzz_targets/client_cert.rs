//! Client certificates as a reverse proxy forwards them (RFC 8705), and the
//! RFC 4514 subject DNs `tls_client_auth` clients register.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ridm_api::oidc::mtls::{self, ClientCert};

fuzz_target!(|data: &[u8]| {
    // Raw DER straight into the certificate reader.
    if let Some(cert) = ClientCert::from_chain(data.to_vec(), vec![]) {
        check(&cert);
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // A header value: PEM, URL-encoded PEM or base64 DER.
    if let Some(ders) = mtls::parse_header(text) {
        assert!(!ders.is_empty() && ders.len() <= 5);
        let mut it = ders.into_iter();
        let leaf = it.next().expect("at least one");
        if let Some(cert) = ClientCert::from_chain(leaf, it.collect()) {
            check(&cert);
        }
    }
    // A registered subject DN.
    let _ = mtls::parse_dn(text);
});

/// What rIDM prints of a certificate's subject names that subject again.
fn check(cert: &ClientCert) {
    assert_eq!(cert.thumbprint(), mtls::thumbprint(cert.der()));
    if cert.subject_is_textual() {
        let dn = cert.subject_dn();
        assert!(
            mtls::subject_matches(cert, dn),
            "the subject `{dn}` does not match its own certificate"
        );
    }
}
