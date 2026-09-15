#![no_main]
//! PKCE helpers must never panic; a verifier only ever matches its own challenge.
use libfuzzer_sys::fuzz_target;
use ridm_api::oidc::pkce;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let _ = pkce::is_valid_challenge(s);
    if pkce::is_valid_verifier(s) {
        assert!(pkce::verify_s256(s, &pkce::challenge_for(s)));
    }
    assert!(!pkce::verify_s256(s, s), "a verifier must not verify against itself as challenge: {s:?}");
});
