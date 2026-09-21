//! SAML messages: whatever an SP (or anyone) sends to `/saml/sso` and
//! `/saml/slo`, and the metadata an administrator pastes. The input is
//! tried as an HTTP-Redirect query string and as an XML document; nothing
//! may panic, and exclusive C14N must give well-formed, stable output.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use ridm_api::saml::{binding, c14n, cert, dsig, metadata, protocol, xml};

/// A certificate to verify against (never the signer of the input, so any
/// signature must be refused, never accepted or panicked on).
fn cert() -> &'static cert::Certificate {
    static CERT: OnceLock<cert::Certificate> = OnceLock::new();
    CERT.get_or_init(|| {
        let key = ridm_api::services::keys::generate(
            ridm_api::models::SigningAlg::RS256,
            ridm_api::models::RsaBits::B2048,
        )
        .expect("key");
        let der = cert::self_signed(&key.private_der, "fuzz", 1).expect("certificate");
        cert::Certificate::from_der(der).expect("parse")
    })
}

fn document(text: &str) {
    let _ = metadata::parse_sp_metadata(text);
    let Ok(doc) = xml::parse(text) else {
        return;
    };
    let _ = protocol::parse_authn_request(&doc);
    let _ = protocol::parse_logout_request(&doc);
    let _ = protocol::parse_logout_response(&doc);
    for el in doc.descendants().filter(|n| n.is_element()).take(64) {
        let once = c14n::canonicalize(el, None, &[]);
        let again = xml::parse(&once).expect("canonical output is well-formed");
        assert_eq!(
            c14n::canonicalize(again.root_element(), None, &[]),
            once,
            "canonicalization is idempotent"
        );
        if dsig::signature_of(el).ok().flatten().is_some() {
            assert!(dsig::verify_enveloped(&doc, el, std::slice::from_ref(cert())).is_err());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(received) = binding::from_redirect(text) {
        if let Some(sig) = &received.signature {
            assert!(sig.verify(std::slice::from_ref(cert())).is_err());
        }
        document(&received.xml);
    }
    document(text);
});
