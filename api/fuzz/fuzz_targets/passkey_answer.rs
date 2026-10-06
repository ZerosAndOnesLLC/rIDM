//! A passkey answer's untrusted parts: the attestation object (CBOR),
//! authenticator data (with an attested credential's COSE key, and
//! extensions) and client data JSON, as a browser hands them to rIDM.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Three parts, split where the first two bytes say.
    let (a, b) = match data {
        [a, b, ..] => (usize::from(*a), usize::from(*b)),
        _ => return,
    };
    let rest = &data[2..];
    let first = a.min(rest.len());
    let (attestation, rest) = rest.split_at(first);
    let second = b.min(rest.len());
    let (auth_data, client_data) = rest.split_at(second);
    let _ = ridm_api::webauthn::parse_untrusted(attestation, auth_data, client_data);
    // The whole input as each part, too.
    let _ = ridm_api::webauthn::parse_untrusted(data, data, data);
});
