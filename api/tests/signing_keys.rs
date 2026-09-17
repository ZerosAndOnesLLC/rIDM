mod common;

use base64::Engine as _;
use common::TestApp;
use ridm_api::error::AppError;
use ridm_api::models::{ClientType, KeyStatus, NewClient, RsaBits, SigningAlg};
use ridm_api::services::{clients, keys, tenants};
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
            !key.private_key_enc.windows(der.len()).any(|w| w == *der),
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

/// The tenant's first key is made once, however many callers ask at the same
/// moment, and the JWKS document names the key tokens are signed with.
///
/// Every request path that signs something calls `ensure_active`. Before the
/// unique index and the creation lock, concurrent first contact left several
/// active keys behind: tokens carried the newest while a JWKS document built
/// moments earlier named another, so a relying party that had fetched the
/// document could not verify the token it was given. What is pinned here is
/// that outcome — one key, and the signed-with key published; the lock is what
/// keeps reaching it from costing one key generation per caller.
#[tokio::test]
async fn one_key_is_made_for_concurrent_first_contact_and_it_is_the_published_one() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    let policy = tenant.settings.keys.clone();
    assert!(
        keys::list(&app.state, tid, None).await.unwrap().is_empty(),
        "a fresh tenant starts without keys"
    );

    // Eight callers reach for the first key at once.
    let asks = (0..8).map(|_| {
        let state = app.state.clone();
        let policy = policy.clone();
        async move { keys::ensure_active(&state, tid, &policy).await.unwrap() }
    });
    let got: Vec<_> = futures::future::join_all(asks).await;
    let first = got[0].kid.clone();
    assert!(
        got.iter().all(|k| k.kid == first),
        "callers were handed different keys: {:?}",
        got.iter().map(|k| &k.kid).collect::<Vec<_>>()
    );
    let all = keys::list(&app.state, tid, None).await.unwrap();
    assert_eq!(
        all.len(),
        1,
        "each caller made its own key: {:?}",
        all.iter().map(|k| (&k.kid, k.status)).collect::<Vec<_>>()
    );
    assert_eq!(all[0].status, KeyStatus::Active);

    // A second active key of the same algorithm is refused outright.
    let again = keys::create(
        &app.state,
        tid,
        Actor::System,
        policy.default_alg,
        policy.rsa_bits,
        KeyStatus::Active,
        None,
    )
    .await;
    assert!(
        matches!(again, Err(AppError::Conflict(_))),
        "a second active key was accepted: {again:?}"
    );

    // What the token endpoint signs with is in the document the server serves.
    let client = clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("svc".into()),
            name: "svc".into(),
            client_type: Some(ClientType::Machine),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let secret = client.client_secret.as_deref().unwrap().to_string();
    let res = app
        .http
        .post(app.tenant_url("/token"))
        .basic_auth("svc", Some(&secret))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    let token = body["access_token"].as_str().unwrap();
    let header: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    let signed_with = header["kid"].as_str().unwrap();

    let jwks: serde_json::Value = app
        .http
        .get(app.tenant_url("/.well-known/jwks.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let published: Vec<&str> = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap())
        .collect();
    assert!(
        published.contains(&signed_with),
        "token signed with {signed_with}, JWKS publishes {published:?}"
    );

    // A rotation moves the document on at once, old key still published.
    let rotated = keys::rotate(&app.state, tid, &policy, Actor::System)
        .await
        .unwrap();
    let jwks: serde_json::Value = app
        .http
        .get(app.tenant_url("/.well-known/jwks.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let published: Vec<&str> = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap())
        .collect();
    assert!(
        published.contains(&rotated.kid.as_str()) && published.contains(&signed_with),
        "after rotation JWKS publishes {published:?}, wanted the new key and {signed_with}"
    );
}
