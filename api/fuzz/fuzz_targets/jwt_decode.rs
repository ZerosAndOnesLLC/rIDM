//! JWT decoding on the paths that read a token from the wire: the header of a
//! DPoP proof, a request object or a client assertion, the embedded JWK such a
//! header may carry, and verification against a key rIDM holds. Alongside it
//! the other decoders that read what a caller sent: the master-key blob, a
//! pagination cursor and a legacy password hash.
#![no_main]

use std::sync::LazyLock;

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use libfuzzer_sys::fuzz_target;
use ridm_api::models::{RsaBits, SigningAlg};
use ridm_api::services::keys;
use serde_json::Value;

/// One key pair per process: verification must refuse every input that is not
/// a token signed by it, and never panic doing so.
static KEY: LazyLock<(DecodingKey, Value)> = LazyLock::new(|| {
    let pair = keys::generate(SigningAlg::ES256, RsaBits::B2048).expect("es256 key");
    let jwk = serde_json::from_value(pair.public_jwk.clone()).expect("jwk");
    (DecodingKey::from_jwk(&jwk).expect("decoding key"), pair.public_jwk)
});

fuzz_target!(|data: &[u8]| {
    // The master-key blob parser reads raw bytes, not text.
    let _ = ridm_core::providers::Encrypted::from_bytes(data);
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    // Two more strings that arrive from a caller and are decoded before use.
    let _ = ridm_api::util::cursor::Cursor::decode(token);
    let _ = ridm_api::services::password::legacy::verify(b"pw", token);
    let (key, _) = &*KEY;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    assert!(
        jsonwebtoken::decode::<Value>(token, key, &validation).is_err(),
        "arbitrary input verified as a token"
    );

    let Ok(header) = jsonwebtoken::decode_header(token) else {
        return;
    };
    // A header may carry the key that signed the token (DPoP proofs do): it is
    // turned into a thumbprint and a decoding key before anything is verified.
    if let Some(jwk) = header.jwk {
        if let Ok(value) = serde_json::to_value(&jwk) {
            let _ = keys::thumbprint(&value);
        }
        if let Ok(embedded) = DecodingKey::from_jwk(&jwk) {
            let mut validation = Validation::new(header.alg);
            validation.validate_exp = false;
            validation.validate_nbf = false;
            validation.validate_aud = false;
            validation.required_spec_claims.clear();
            let _ = jsonwebtoken::decode::<Value>(token, &embedded, &validation);
        }
    }
});
