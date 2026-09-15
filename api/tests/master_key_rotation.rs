mod common;

use common::{TestApp, test_config};
use ridm_api::models::{KeyStatus, RsaBits, SigningAlg};
use ridm_api::services::{keys, master_key};
use ridm_api::state::AppState;
use ridm_api::util::secret::SecretBytes;
use ridm_core::events::Actor;
use uuid::Uuid;

/// A second "deployment" of the same database with a newer master key.
async fn state_with_key(
    app: &TestApp,
    version: u32,
    key: u8,
    previous: Vec<(u32, u8)>,
) -> AppState {
    let infra = common::infra().await;
    let mut config = test_config(&infra.database_url, &infra.redis_url, &app.base_url);
    config.master_key = SecretBytes::new(vec![key; 32]);
    config.master_key_version = version;
    config.master_key_previous = previous
        .into_iter()
        .map(|(v, k)| (v, SecretBytes::new(vec![k; 32])))
        .collect();
    let db = ridm_api::db::connect(&config).await.unwrap();
    let redis = ridm_api::cache::connect(&config).unwrap();
    AppState::new(config, db, redis)
}

#[tokio::test]
async fn rotation_reencrypts_every_row_and_is_idempotent() {
    let app = TestApp::spawn().await; // master key: 0x07.., version 1
    let tid = app.tenant.id;
    let k1 = keys::create(
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
    let k2 = keys::create(
        &app.state,
        tid,
        Actor::System,
        SigningAlg::ES256,
        RsaBits::B2048,
        KeyStatus::Pending,
        None,
    )
    .await
    .unwrap();
    // A credential row encrypted under generation 1 (the MFA service arrives in Phase 7).
    let user = ridm_api::services::users::create(
        &app.state,
        tid,
        Actor::System,
        ridm_api::models::NewUser {
            username: "u".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let cred_id = Uuid::now_v7();
    let blob = app
        .state
        .key_encryptor
        .encrypt(
            b"totp-secret",
            format!("credentials:{tid}:{cred_id}").as_bytes(),
        )
        .await
        .unwrap()
        .to_bytes();
    let mut tx = ridm_api::db::tenant_tx(&app.state.db, tid).await.unwrap();
    sqlx::query("INSERT INTO credentials (id, tenant_id, user_id, type, data_enc, key_version) VALUES ($1, $2, $3, 'totp', $4, 1)")
        .bind(cred_id).bind(tid).bind(user.id).bind(&blob).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let der_before = keys::private_der(&app.state, &k1).await.unwrap();

    // A node with only generation 2 cannot read generation-1 rows.
    let v2_only = state_with_key(&app, 2, 0x42, vec![]).await;
    assert!(keys::private_der(&v2_only, &k1).await.is_err());

    // A node with generation 2 + previous generation 1 reads everything and rotates.
    let v2 = state_with_key(&app, 2, 0x42, vec![(1, 0x07)]).await;
    assert_eq!(&*keys::private_der(&v2, &k1).await.unwrap(), &*der_before);
    let before = master_key::status(&v2).await.unwrap();
    assert_eq!(before.current_version, 2);
    assert_eq!(before.known_versions, vec![1, 2]);
    assert!(before.pending() >= 3, "{before:?}");

    let report = master_key::rotate_all(&v2).await.unwrap();
    assert_eq!(report.target_version, 2);
    assert!(report.rewritten["signing_keys"] >= 2, "{report:?}");
    assert!(report.rewritten["credentials"] >= 1, "{report:?}");
    assert_eq!(report.failed.values().sum::<u64>(), 0);

    let after = master_key::status(&v2).await.unwrap();
    assert_eq!(after.pending(), 0, "{after:?}");

    // Now the generation-2-only node can read everything, with identical plaintext.
    let k1_now = keys::get(&v2_only, tid, k1.id).await.unwrap();
    assert_eq!(k1_now.key_version, 2);
    assert_eq!(
        &*keys::private_der(&v2_only, &k1_now).await.unwrap(),
        &*der_before
    );
    let k2_now = keys::get(&v2_only, tid, k2.id).await.unwrap();
    assert!(keys::private_der(&v2_only, &k2_now).await.is_ok());
    let mut tx = ridm_api::db::tenant_tx(&v2_only.db, tid).await.unwrap();
    let (cred_blob, cred_ver): (Vec<u8>, i32) =
        sqlx::query_as("SELECT data_enc, key_version FROM credentials WHERE id = $1")
            .bind(cred_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(cred_ver, 2);
    let enc = ridm_core::providers::Encrypted::from_bytes(&cred_blob).unwrap();
    assert_eq!(
        &*v2_only
            .key_encryptor
            .decrypt(&enc, format!("credentials:{tid}:{cred_id}").as_bytes())
            .await
            .unwrap(),
        b"totp-secret"
    );

    // The old node (generation 1 only) can no longer read rotated rows.
    assert!(keys::private_der(&app.state, &k1_now).await.is_err());

    // Idempotent: a second pass rewrites nothing.
    let again = master_key::rotate_all(&v2).await.unwrap();
    assert_eq!(again.rewritten.values().sum::<u64>(), 0);

    // Rotation is database-wide, so it also rewrote rows of every other
    // tenant (including `master`, whose keys later test binaries sign with).
    // Leave the shared database under generation 1 again.
    let back = state_with_key(&app, 1, 0x07, vec![(2, 0x42)]).await;
    let restored = master_key::rotate_all(&back).await.unwrap();
    assert_eq!(restored.target_version, 1);
    assert!(restored.rewritten["signing_keys"] >= 2, "{restored:?}");
    let k1_back = keys::get(&app.state, tid, k1.id).await.unwrap();
    assert_eq!(k1_back.key_version, 1);
    assert_eq!(
        &*keys::private_der(&app.state, &k1_back).await.unwrap(),
        &*der_before
    );
}

#[tokio::test]
async fn rows_under_an_unknown_generation_are_reported_not_destroyed() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let k = keys::create(
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
    // Pretend generation 1 is unknown to the rotating node (misconfiguration).
    let v3 = state_with_key(&app, 3, 0x33, vec![(2, 0x22)]).await;
    let report = master_key::rotate_all(&v3).await.unwrap();
    assert!(report.failed["signing_keys"] >= 1, "{report:?}");
    let still = keys::get(&app.state, tid, k.id).await.unwrap();
    assert_eq!(still.key_version, 1, "failed rows are left untouched");
    assert!(keys::private_der(&app.state, &still).await.is_ok());
}
