//! rIDM's own relying party against webauthn-rs, which it replaced: a passkey
//! webauthn-rs registered (every passkey stored before) signs in through
//! rIDM, and a passkey rIDM registered signs in through webauthn-rs (a
//! rollback to a release that still used it), with the same software
//! authenticator throughout.

use ridm_api::webauthn::{RelyingParty, StoredPasskey};
use uuid::Uuid;
use webauthn_authenticator_rs::AuthenticatorBackend as _;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{Passkey, Url, WebauthnBuilder};

fn origin() -> Url {
    Url::parse("https://id.example.com").unwrap()
}

fn ours() -> RelyingParty {
    RelyingParty::new("id.example.com", &origin(), "Acme").unwrap()
}

fn theirs() -> webauthn_rs::Webauthn {
    WebauthnBuilder::new("id.example.com", &origin())
        .unwrap()
        .rp_name("Acme")
        .build()
        .unwrap()
}

#[test]
fn a_passkey_webauthn_rs_registered_signs_in_through_ridm() {
    let mut auth = SoftPasskey::new(true);
    let user = Uuid::now_v7();
    let (ccr, reg) = theirs()
        .start_passkey_registration(user, "alice", "Alice", None)
        .unwrap();
    let answer = auth
        .perform_register(origin(), ccr.public_key, 60_000)
        .unwrap();
    let theirs_key = theirs().finish_passkey_registration(&answer, &reg).unwrap();

    // As stored before: webauthn-rs's own JSON.
    let json = serde_json::to_value(&theirs_key).unwrap();
    let mut key: StoredPasskey = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(key.cred_id(), theirs_key.cred_id().as_ref());

    for _ in 0..2 {
        let (rcr, state) = ours().start_authentication(std::slice::from_ref(&key));
        let assertion = auth.perform_auth(origin(), rcr.public_key, 60_000).unwrap();
        let result = ours()
            .finish_authentication(&assertion, &state, &key)
            .unwrap();
        assert!(result.user_verified);
        key.update(&result);
    }

    // What rIDM writes back still reads as a webauthn-rs Passkey, with the
    // parts rIDM doesn't interpret unchanged.
    let back = serde_json::to_value(&key).unwrap();
    for field in [
        "extensions",
        "attestation",
        "attestation_format",
        "registration_policy",
    ] {
        assert_eq!(back["cred"][field], json["cred"][field], "{field}");
    }
    let _: Passkey = serde_json::from_value(back).unwrap();
}

#[test]
fn a_passkey_ridm_registered_signs_in_through_webauthn_rs() {
    let mut auth = SoftPasskey::new(true);
    let user = Uuid::now_v7();
    let (ccr, state) = ours()
        .start_registration(user, "alice", "Alice", &[])
        .unwrap();
    let answer = auth
        .perform_register(origin(), ccr.public_key, 60_000)
        .unwrap();
    let ours_key = ours().finish_registration(&answer, &state).unwrap();

    let json = serde_json::to_value(&ours_key).unwrap();
    let theirs_key: Passkey = serde_json::from_value(json).expect("webauthn-rs reads it");
    let (rcr, ast) = theirs()
        .start_passkey_authentication(std::slice::from_ref(&theirs_key))
        .unwrap();
    let assertion = auth.perform_auth(origin(), rcr.public_key, 60_000).unwrap();
    let result = theirs()
        .finish_passkey_authentication(&assertion, &ast)
        .unwrap();
    assert!(result.user_verified());
}

#[test]
fn tampered_replayed_and_foreign_assertions_are_refused() {
    let mut auth = SoftPasskey::new(true);
    let (ccr, state) = ours()
        .start_registration(Uuid::now_v7(), "alice", "Alice", &[])
        .unwrap();
    let answer = auth
        .perform_register(origin(), ccr.public_key, 60_000)
        .unwrap();
    let mut key = ours().finish_registration(&answer, &state).unwrap();

    let (rcr, state) = ours().start_authentication(std::slice::from_ref(&key));
    let good = auth.perform_auth(origin(), rcr.public_key, 60_000).unwrap();

    // Another challenge.
    let (_, other_state) = ours().start_authentication(std::slice::from_ref(&key));
    assert!(
        ours()
            .finish_authentication(&good, &other_state, &key)
            .is_err()
    );
    // Another origin.
    let elsewhere = RelyingParty::new(
        "id.example.com",
        &Url::parse("https://login.id.example.com").unwrap(),
        "Acme",
    )
    .unwrap();
    assert!(
        elsewhere
            .finish_authentication(&good, &state, &key)
            .is_err()
    );
    // A changed client data (the signature covers its hash).
    let mut tampered = good.clone();
    let mut cdj = tampered.response.client_data_json.as_ref().to_vec();
    let last = cdj.len() - 2;
    cdj[last] = b' ';
    tampered.response.client_data_json = cdj.into();
    assert!(
        ours()
            .finish_authentication(&tampered, &state, &key)
            .is_err()
    );

    // The real one verifies once; replaying it (same counter) does not.
    let result = ours().finish_authentication(&good, &state, &key).unwrap();
    assert!(key.update(&result));
    assert!(ours().finish_authentication(&good, &state, &key).is_err());
}
