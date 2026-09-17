//! PKCE (RFC 7636): the grammar check, the challenge transform and the
//! constant-time comparison. A verifier must verify against its own
//! challenge, and only against that one.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ridm_api::oidc::pkce;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let valid = pkce::is_valid_verifier(s);
    assert_eq!(valid, pkce::is_valid_challenge(s));
    let challenge = pkce::challenge_for(s);
    // The transform always produces a well-formed challenge.
    assert!(pkce::is_valid_challenge(&challenge));
    // A verifier the grammar accepts verifies against its own challenge, and
    // an ill-formed one never verifies at all.
    assert_eq!(pkce::verify_s256(s, &challenge), valid);
    assert!(!pkce::verify_s256(s, ""));
    assert!(
        !pkce::verify_s256(s, s),
        "a verifier verified against itself as its own challenge: {s:?}"
    );
    if let Some((a, b)) = s.split_once('\n') {
        // Two different inputs must not verify against each other's challenge.
        if a != b {
            assert!(!pkce::verify_s256(a, &pkce::challenge_for(b)));
        }
    }
});
