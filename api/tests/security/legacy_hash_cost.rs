//! Fuzz finding (Phase 12.3 CI, `jwt_decode`): the legacy password verifier
//! took its iteration count from the stored hash and allowed up to ten
//! million rounds. PBKDF2-SHA512 at that count costs about 25 seconds of CPU,
//! so one account with such a hash — imported from a hostile export, or
//! crafted — turned every sign-in attempt against it into a worker held
//! hostage, with no password needed to trigger it. The count is now capped
//! and a hash above the cap is refused outright.

use std::time::Instant;

use ridm_api::services::password::legacy;

/// The exact input libFuzzer timed out on.
const REPRODUCER: &str = "pbkdf2_sha512$010000000$b2$pWF0IjoxNTbkdfk";

#[test]
fn an_absurd_iteration_count_is_refused_rather_than_computed() {
    let started = Instant::now();
    let outcome = legacy::verify(b"whatever", REPRODUCER);
    let elapsed = started.elapsed();
    assert!(
        outcome.is_err(),
        "a hash asking for ten million rounds must be refused, not computed"
    );
    assert!(
        elapsed.as_millis() < 500,
        "refusing took {elapsed:?}: the count was computed after all"
    );
}

#[test]
fn the_cap_applies_to_every_pbkdf2_spelling() {
    for stored in [
        "pbkdf2_sha256$2000000$salt$cGFzcw",
        "pbkdf2_sha512$2000000$salt$cGFzcw",
        "$pbkdf2-sha256$2000000$c2FsdA$cGFzcw",
        "$pbkdf2-sha512$2000000$c2FsdA$cGFzcw",
    ] {
        let started = Instant::now();
        assert!(
            legacy::verify(b"whatever", stored).is_err(),
            "{stored} was not refused"
        );
        assert!(started.elapsed().as_millis() < 500, "{stored} was computed");
    }
}

#[test]
fn a_realistic_count_still_verifies() {
    // Django's spelling, at a cost real exports use, hashed here so the
    // fixture cannot drift from what the verifier expects.
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(b"correct-horse", b"saltysalt", 120_000, &mut out);
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, out);
    let stored = format!("pbkdf2_sha256$120000$saltysalt${encoded}");
    assert!(
        legacy::verify(b"correct-horse", &stored).unwrap(),
        "a hash within the cap must still verify"
    );
    assert!(!legacy::verify(b"wrong", &stored).unwrap());
}
