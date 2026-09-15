mod common;

use common::TestApp;
use ridm_api::error::AppError;
use ridm_api::models::{KeyStatus, RsaBits, SigningAlg};
use ridm_api::services::keys;
use ridm_core::events::Actor;

#[tokio::test]
async fn keys_are_generated_encrypted_and_recoverable_per_algorithm() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;

    for alg in [SigningAlg::RS256, SigningAlg::ES256, SigningAlg::EdDSA] {
        let key = keys::create(
            &app.state,
            tid,
            Actor::System,
            alg,
            RsaBits::B2048,
            KeyStatus::Active,
            None,
        )
        .await
        .unwrap();
        assert_eq!(key.alg, alg);
        assert_eq!(key.status, KeyStatus::Active);
        assert_eq!(key.key_version, 1);
        assert_eq!(key.public_jwk["kid"], key.kid);
        assert_eq!(key.public_jwk["kty"], alg.kty());

        // Stored blob is ciphertext, and decrypts back to PKCS#8 DER.
        assert!(!key.private_key_enc.is_empty());
        let der = keys::private_der(&app.state, &key).await.unwrap();
        assert!(der.len() > 32);
        assert_eq!(der[0], 0x30, "PKCS#8 DER starts with a SEQUENCE");
        assert!(
            !key.private_key_enc.windows(der.len()).any(|w| w == &*der),
            "private key must not be stored in the clear"
        );

        let active = keys::active(&app.state, tid, alg)
            .await
            .unwrap()
            .expect("active key");
        assert_eq!(active.id, key.id);
    }

    let all = keys::list(&app.state, tid, None).await.unwrap();
    assert_eq!(all.len(), 3);
    let jwks = keys::published_jwks(&app.state, tid).await.unwrap();
    assert_eq!(jwks.len(), 3);
    assert!(
        jwks.iter()
            .all(|j| j.get("d").is_none() && j["use"] == "sig")
    );

    // Serialized keys never expose the ciphertext either.
    let json = serde_json::to_value(&all[0]).unwrap();
    assert!(json.get("private_key_enc").is_none());
}

#[tokio::test]
async fn tampered_or_moved_ciphertext_does_not_decrypt() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let a = keys::create(
        &app.state,
        tid,
        Actor::System,
        SigningAlg::EdDSA,
        RsaBits::B2048,
        KeyStatus::Active,
        None,
    )
    .await
    .unwrap();
    let b = keys::create(
        &app.state,
        tid,
        Actor::System,
        SigningAlg::EdDSA,
        RsaBits::B2048,
        KeyStatus::Pending,
        None,
    )
    .await
    .unwrap();

    // Moving a's ciphertext onto b's row (different AAD) must fail.
    let mut moved = b.clone();
    moved.private_key_enc = a.private_key_enc.clone();
    assert!(matches!(
        keys::private_der(&app.state, &moved).await,
        Err(AppError::Internal(_))
    ));

    let mut tampered = a.clone();
    let last = tampered.private_key_enc.len() - 1;
    tampered.private_key_enc[last] ^= 0xff;
    assert!(keys::private_der(&app.state, &tampered).await.is_err());

    let mut garbage = a.clone();
    garbage.private_key_enc = vec![1, 2, 3];
    assert!(keys::private_der(&app.state, &garbage).await.is_err());
}

#[tokio::test]
async fn keys_are_tenant_isolated() {
    let app = TestApp::spawn().await;
    let other = common::create_tenant(&app.state.db).await;
    let key = keys::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        SigningAlg::ES256,
        RsaBits::B2048,
        KeyStatus::Active,
        None,
    )
    .await
    .unwrap();

    assert!(matches!(
        keys::get(&app.state, other.id, key.id).await,
        Err(AppError::NotFound(_))
    ));
    assert!(
        keys::list(&app.state, other.id, None)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        keys::active(&app.state, other.id, SigningAlg::ES256)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        keys::published_jwks(&app.state, other.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        keys::get(&app.state, app.tenant.id, key.id)
            .await
            .unwrap()
            .kid,
        key.kid
    );
}
