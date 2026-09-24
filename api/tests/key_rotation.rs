mod common;

use std::time::Duration;

use common::TestApp;
use ridm_api::error::AppError;
use ridm_api::jobs::{key_rotation, leader};
use ridm_api::models::{KeyPolicy, KeyStatus, RsaBits, SigningAlg};
use ridm_api::services::keys;
use ridm_core::events::Actor;

fn policy() -> KeyPolicy {
    KeyPolicy {
        default_alg: SigningAlg::EdDSA,
        rsa_bits: RsaBits::B2048,
        rotation_interval_days: 30,
        retire_overlap_hours: 24,
    }
}

#[tokio::test]
async fn lifecycle_create_activate_retire_revoke_with_overlap() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let p = policy();

    let first = keys::ensure_active(&app.state, tid, &p).await.unwrap();
    assert_eq!(first.status, KeyStatus::Active);
    // Idempotent: same key comes back.
    assert_eq!(
        keys::ensure_active(&app.state, tid, &p).await.unwrap().id,
        first.id
    );

    let pending = keys::create(
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
    // Pending keys are published (RPs can pre-fetch) but not used for signing.
    assert_eq!(
        keys::published_jwks(&app.state, tid).await.unwrap().len(),
        2
    );
    assert_eq!(
        keys::active(&app.state, tid, SigningAlg::EdDSA)
            .await
            .unwrap()
            .unwrap()
            .id,
        first.id
    );

    let activated = keys::activate(&app.state, tid, &p, Actor::System, pending.id)
        .await
        .unwrap();
    assert_eq!(activated.status, KeyStatus::Active);
    assert_eq!(
        keys::active(&app.state, tid, SigningAlg::EdDSA)
            .await
            .unwrap()
            .unwrap()
            .id,
        pending.id
    );
    let old = keys::get(&app.state, tid, first.id).await.unwrap();
    assert_eq!(old.status, KeyStatus::Retiring);
    let overlap = old.expires_at.expect("retiring key has an expiry");
    let hours = (overlap - chrono::Utc::now()).num_minutes() as f64 / 60.0;
    assert!((23.9..=24.1).contains(&hours), "overlap ≈ 24h, got {hours}");
    // Still published while retiring.
    let jwks = keys::published_jwks(&app.state, tid).await.unwrap();
    assert!(jwks.iter().any(|j| j["kid"] == old.kid));

    let revoked = keys::revoke(&app.state, tid, Actor::System, first.id)
        .await
        .unwrap();
    assert_eq!(revoked.status, KeyStatus::Revoked);
    let jwks = keys::published_jwks(&app.state, tid).await.unwrap();
    assert!(!jwks.iter().any(|j| j["kid"] == old.kid));
    assert!(matches!(
        keys::activate(&app.state, tid, &p, Actor::System, first.id).await,
        Err(AppError::BadRequest(_))
    ));

    // rotate(): new key active, previous retiring.
    let rotated = keys::rotate(&app.state, tid, &p, Actor::System)
        .await
        .unwrap();
    assert_eq!(rotated.status, KeyStatus::Active);
    assert_ne!(rotated.id, pending.id);
    assert_eq!(
        keys::get(&app.state, tid, pending.id).await.unwrap().status,
        KeyStatus::Retiring
    );
    assert_eq!(
        keys::list(&app.state, tid, Some(KeyStatus::Active))
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn maintenance_revokes_expired_and_rotates_old_keys() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let p = policy();
    let key = keys::ensure_active(&app.state, tid, &p).await.unwrap();

    // Nothing to do yet.
    assert_eq!(
        keys::maintain(&app.state, tid, &p).await.unwrap(),
        (0, false)
    );

    // Age the active key past the rotation interval and expire a retiring key.
    let retiring = keys::create(
        &app.state,
        tid,
        Actor::System,
        SigningAlg::EdDSA,
        RsaBits::B2048,
        KeyStatus::Retiring,
        None,
    )
    .await
    .unwrap();
    let mut tx = ridm_api::db::tenant_tx(&app.state.db, tid).await.unwrap();
    sqlx::query("UPDATE signing_keys SET not_before = now() - interval '31 days' WHERE id = $1")
        .bind(key.id)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE signing_keys SET expires_at = now() - interval '1 minute' WHERE id = $1")
        .bind(retiring.id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    assert_eq!(
        keys::maintain(&app.state, tid, &p).await.unwrap(),
        (1, true)
    );
    assert_eq!(
        keys::get(&app.state, tid, retiring.id)
            .await
            .unwrap()
            .status,
        KeyStatus::Revoked
    );
    assert_eq!(
        keys::get(&app.state, tid, key.id).await.unwrap().status,
        KeyStatus::Retiring
    );
    let fresh = keys::active(&app.state, tid, SigningAlg::EdDSA)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(fresh.id, key.id);

    // rotation disabled → never rotates.
    let no_rotate = KeyPolicy {
        rotation_interval_days: 0,
        ..p
    };
    let mut tx = ridm_api::db::tenant_tx(&app.state.db, tid).await.unwrap();
    sqlx::query("UPDATE signing_keys SET not_before = now() - interval '900 days' WHERE id = $1")
        .bind(fresh.id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        keys::maintain(&app.state, tid, &no_rotate).await.unwrap(),
        (0, false)
    );
}

#[tokio::test]
async fn rotation_job_runs_on_one_node_at_a_time() {
    let app = TestApp::spawn().await;
    // Hold the lock as "another node": run_once must yield.
    let lock = leader::try_acquire(
        &app.state.redis,
        key_rotation::JOB_NAME,
        Duration::from_secs(30),
    )
    .await
    .unwrap()
    .expect("lock free");
    assert!(key_rotation::run_once(&app.state).await.unwrap().is_none());
    lock.release().await.unwrap();

    // Lock released: this node visits the tenants whose keys are due. Ours
    // has an active key past the rotation interval (90 days by default);
    // another tenant's fresh key is left alone.
    let tid = app.tenant.id;
    let defaults = KeyPolicy::default();
    let old = keys::ensure_active(&app.state, tid, &defaults)
        .await
        .unwrap();
    let other = common::create_tenant(&app.state.db).await;
    let fresh = keys::ensure_active(&app.state, other.id, &defaults)
        .await
        .unwrap();
    let mut tx = ridm_api::db::tenant_tx(&app.state.db, tid).await.unwrap();
    sqlx::query("UPDATE signing_keys SET not_before = now() - interval '91 days' WHERE id = $1")
        .bind(old.id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let processed = key_rotation::run_once(&app.state)
        .await
        .unwrap()
        .expect("ran");
    assert!(processed >= 1, "processed {processed}");
    assert_eq!(
        keys::get(&app.state, tid, old.id).await.unwrap().status,
        KeyStatus::Retiring,
        "the due key was rotated"
    );
    assert_eq!(
        keys::get(&app.state, other.id, fresh.id)
            .await
            .unwrap()
            .status,
        KeyStatus::Active,
        "a key that is not due stays"
    );
    // Releasing a lock we no longer own must not delete someone else's.
    let a = leader::try_acquire(&app.state.redis, "t", Duration::from_millis(200))
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let b = leader::try_acquire(&app.state.redis, "t", Duration::from_secs(10))
        .await
        .unwrap()
        .expect("expired lock re-acquirable");
    a.release().await.unwrap();
    assert!(
        leader::try_acquire(&app.state.redis, "t", Duration::from_secs(10))
            .await
            .unwrap()
            .is_none(),
        "b still holds it"
    );
    b.release().await.unwrap();
}
