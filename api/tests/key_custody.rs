//! Key custody (13.6) end to end against Postgres, with the mock wrapper
//! standing in for an HSM or KMS: a deployment moves from the environment's
//! master key to wrapped generations online and back, nodes adopt a
//! generation another process created, and what cannot be unwrapped is
//! reported rather than silently used.
//!
//! The generations table and the rotation are deployment-wide, so every test
//! runs on a database of its own: a test that failed half way through a
//! rotation must not leave the shared one under a generation nobody can
//! unwrap.

mod common;

use std::sync::Arc;

use common::test_config;
use common::throwaway::ThrowawayDb;
use ridm_api::models::{KeyStatus, RsaBits, SigningAlg, SigningKey};
use ridm_api::services::{keys, master_key};
use ridm_api::state::AppState;
use ridm_api::util::secret::SecretBytes;
use ridm_core::events::Actor;
use ridm_core::providers::{Encrypted, KeyWrapper, ProviderError};
use ridm_core::test_support::MockKeyWrapper;
use uuid::Uuid;

/// A backend name of the test's own.
fn fresh_backend() -> &'static str {
    Box::leak(format!("mock-{}", &Uuid::new_v4().simple().to_string()[..12]).into_boxed_str())
}

/// A migrated database of the test's own, with one tenant.
struct Deployment {
    db: ThrowawayDb,
    tenant: Uuid,
}

impl Deployment {
    async fn new() -> Self {
        let db = ThrowawayDb::new(true).await;
        let pool = sqlx::PgPool::connect(&db.url).await.unwrap();
        let tenant = common::create_tenant(&pool.clone().into()).await.id;
        pool.close().await;
        Self { db, tenant }
    }

    /// A node: `env` is its `MASTER_KEY` (version, key byte), or none when
    /// the custody backend is its only source.
    async fn node(&self, env: Option<(u32, u8)>) -> AppState {
        let infra = common::infra().await;
        let mut config = test_config(&self.db.url, &infra.redis_url, "http://127.0.0.1:1");
        config.master_key = env.map(|(_, k)| SecretBytes::new(vec![k; 32]));
        config.master_key_version = env.map(|(v, _)| v).unwrap_or(1);
        let db = ridm_api::db::connect(&config).await.unwrap();
        let redis = ridm_api::cache::connect(&config).unwrap();
        AppState::new(config, db, redis)
    }

    async fn signing_key(&self, state: &AppState) -> SigningKey {
        keys::create(
            state,
            self.tenant,
            Actor::System,
            SigningAlg::EdDSA,
            RsaBits::B2048,
            KeyStatus::Active,
            None,
        )
        .await
        .unwrap()
    }
}

fn wrappers(w: &Arc<MockKeyWrapper>) -> Vec<Arc<dyn KeyWrapper>> {
    vec![w.clone() as Arc<dyn KeyWrapper>]
}

#[tokio::test]
async fn a_deployment_moves_from_the_environment_key_to_a_wrapped_generation_and_back() {
    let dep = Deployment::new().await;
    let before = dep.node(Some((1, 0x07))).await; // MASTER_KEY only, as before 13.6
    let k1 = dep.signing_key(&before).await;
    let der = keys::private_der(&before, &k1).await.unwrap();

    // KEY_WRAPPER set beside the old MASTER_KEY: the first generation is
    // created, becomes current, and the environment's stays readable.
    let backend = fresh_backend();
    let wrapper = Arc::new(MockKeyWrapper::new(backend, "key-a", 0x5a));
    let b = dep.node(Some((1, 0x07))).await;
    let report = b
        .master_keys
        .attach(b.db.clone(), wrappers(&wrapper), Some(backend))
        .await
        .unwrap();
    assert_eq!(report.created, Some(2), "numbered above the environment's");
    assert_eq!(b.key_encryptor.current_version(), 2);
    assert_eq!(&*keys::private_der(&b, &k1).await.unwrap(), &*der);

    let status = master_key::status(&b).await.unwrap();
    assert_eq!(status.key_wrapper.as_deref(), Some(backend));
    let env = status.generations.iter().find(|g| g.version == 1).unwrap();
    assert_eq!(env.backend, "env");
    let wrapped = status.generations.iter().find(|g| g.version == 2).unwrap();
    assert_eq!(wrapped.backend, backend);
    assert_eq!(wrapped.key_ref.as_deref(), Some("key-a"));
    assert!(wrapped.loaded);
    assert_eq!(status.pending(), 1, "{status:?}");

    // Only the wrapped form is stored.
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT wrapped_key FROM master_key_generations WHERE version = 2")
            .fetch_one(b.db.home())
            .await
            .unwrap();
    assert_eq!(stored.len(), 33);

    let rotated = master_key::rotate_all(&b).await.unwrap();
    assert_eq!(rotated.target_version, 2);
    assert_eq!(rotated.rewritten["signing_keys"], 1, "{rotated:?}");
    assert_eq!(rotated.failed.values().sum::<u64>(), 0, "{rotated:?}");
    let k1_now = keys::get(&b, dep.tenant, k1.id).await.unwrap();
    assert_eq!(k1_now.key_version, 2);

    // A node with no MASTER_KEY at all reads everything through the backend,
    // having asked it once per generation at start-up.
    let c = dep.node(None).await;
    let unwraps = wrapper.unwraps();
    c.master_keys
        .attach(c.db.clone(), wrappers(&wrapper), Some(backend))
        .await
        .unwrap();
    assert_eq!(c.key_encryptor.current_version(), 2);
    assert_eq!(&*keys::private_der(&c, &k1_now).await.unwrap(), &*der);
    let after_start = wrapper.unwraps();
    assert_eq!(after_start, unwraps + 1);
    for _ in 0..5 {
        keys::private_der(&c, &k1_now).await.unwrap();
    }
    assert_eq!(
        wrapper.unwraps(),
        after_start,
        "rows never call the backend"
    );

    // The backend going down after start-up does not stop a running node...
    wrapper.set_down(true);
    assert_eq!(&*keys::private_der(&c, &k1_now).await.unwrap(), &*der);
    let fresh = c.key_encryptor.encrypt(b"x", b"aad").await.unwrap();
    assert_eq!(fresh.key_version, 2);
    // ...but a node cannot start without it.
    let d = dep.node(None).await;
    let err = d
        .master_keys
        .attach(d.db.clone(), wrappers(&wrapper), Some(backend))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("cannot be unwrapped"), "{err}");
    wrapper.set_down(false);

    // A node on the environment key alone no longer reads the rotated rows.
    assert!(keys::private_der(&before, &k1_now).await.is_err());

    // And back: the environment's generation current, the backend only
    // read (KEY_WRAPPER_PREVIOUS).
    let back = dep.node(Some((1, 0x07))).await;
    back.master_keys
        .attach(back.db.clone(), wrappers(&wrapper), None)
        .await
        .unwrap();
    assert_eq!(back.key_encryptor.current_version(), 1);
    let report = master_key::rotate_all(&back).await.unwrap();
    assert_eq!(report.target_version, 1);
    assert_eq!(report.failed.values().sum::<u64>(), 0, "{report:?}");
    let k1_back = keys::get(&before, dep.tenant, k1.id).await.unwrap();
    assert_eq!(k1_back.key_version, 1);
    assert_eq!(&*keys::private_der(&before, &k1_back).await.unwrap(), &*der);
}

#[tokio::test]
async fn nodes_adopt_a_generation_created_elsewhere() {
    let dep = Deployment::new().await;
    let backend = fresh_backend();
    let wrapper = Arc::new(MockKeyWrapper::new(backend, "key-b", 0x3c));
    let a = dep.node(None).await;
    let first = a
        .master_keys
        .attach(a.db.clone(), wrappers(&wrapper), Some(backend))
        .await
        .unwrap()
        .created
        .unwrap();
    assert_eq!(first, 1, "a new deployment starts at 1");
    let b = dep.node(None).await;
    let report = b
        .master_keys
        .attach(b.db.clone(), wrappers(&wrapper), Some(backend))
        .await
        .unwrap();
    assert_eq!(report.created, None, "the second node finds the first's");
    assert_eq!(b.key_encryptor.current_version(), first);

    // `rotate-master-key --new-generation` on node a.
    let second = master_key::new_generation(&a).await.unwrap();
    assert_eq!(second, first + 1);
    assert_eq!(a.key_encryptor.current_version(), second);
    let blob = a.key_encryptor.encrypt(b"secret", b"aad").await.unwrap();
    assert_eq!(blob.key_version, second);

    // Node b still writes under the one it knows, and reads a row under the
    // new one by loading it on first sight.
    assert_eq!(b.key_encryptor.current_version(), first);
    assert_eq!(
        &*b.key_encryptor.decrypt(&blob, b"aad").await.unwrap(),
        b"secret"
    );
    assert_eq!(b.key_encryptor.current_version(), second, "adopted on load");

    // A node without the backend cannot.
    let c = dep.node(None).await;
    c.master_keys
        .attach(c.db.clone(), vec![], None)
        .await
        .unwrap();
    assert!(c.key_encryptor.decrypt(&blob, b"aad").await.is_err());

    // A node that only refreshes moves on too.
    let d = dep.node(None).await;
    d.master_keys
        .attach(d.db.clone(), wrappers(&wrapper), Some(backend))
        .await
        .unwrap();
    assert_eq!(d.key_encryptor.current_version(), second);
    let third = master_key::new_generation(&a).await.unwrap();
    d.master_keys.refresh().await.unwrap();
    assert_eq!(d.key_encryptor.current_version(), third);
}

#[tokio::test]
async fn what_cannot_be_unwrapped_is_reported_and_fails_fast() {
    let dep = Deployment::new().await;
    let backend = fresh_backend();
    let wrapper = Arc::new(MockKeyWrapper::new(backend, "key-c", 0x11));
    let a = dep.node(None).await;
    let v = a
        .master_keys
        .attach(a.db.clone(), wrappers(&wrapper), Some(backend))
        .await
        .unwrap()
        .created
        .unwrap();
    let blob = a.key_encryptor.encrypt(b"secret", b"aad").await.unwrap();

    // The backend is not configured on this node: listed, not loaded, and
    // its rows refuse to decrypt.
    let env_only = dep.node(Some((9, 0x07))).await;
    let report = env_only
        .master_keys
        .attach(env_only.db.clone(), vec![], None)
        .await
        .unwrap();
    let why = &report.unreadable.iter().find(|(g, _)| *g == v).unwrap().1;
    assert!(why.contains(backend), "{why}");
    let listed = env_only.master_keys.describe().await.unwrap();
    assert!(!listed.iter().find(|g| g.version == v).unwrap().loaded);
    assert!(env_only.key_encryptor.decrypt(&blob, b"aad").await.is_err());

    // The same backend name answering with another key (a restore pointed
    // at the wrong KMS key): the current generation cannot be unwrapped, so
    // the node refuses to start rather than encrypt under something else.
    let impostor = Arc::new(MockKeyWrapper::new(backend, "key-c", 0x99));
    let wrong = dep.node(None).await;
    let err = wrong
        .master_keys
        .attach(wrong.db.clone(), wrappers(&impostor), Some(backend))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("cannot be unwrapped"), "{err}");

    // A generation that failed to load is not asked for again right away.
    let flaky = dep.node(None).await;
    let other = fresh_backend();
    let other_wrapper = Arc::new(MockKeyWrapper::new(other, "key-d", 0x22));
    flaky
        .master_keys
        .attach(
            flaky.db.clone(),
            vec![
                other_wrapper as Arc<dyn KeyWrapper>,
                wrapper.clone() as Arc<dyn KeyWrapper>,
            ],
            Some(other),
        )
        .await
        .unwrap();
    let newer = master_key::new_generation(&a).await.unwrap();
    let late = a.key_encryptor.encrypt(b"later", b"aad").await.unwrap();
    assert_eq!(late.key_version, newer);
    wrapper.set_down(true);
    let first = flaky
        .key_encryptor
        .decrypt(&late, b"aad")
        .await
        .unwrap_err();
    assert!(matches!(first, ProviderError::Unavailable(_)), "{first}");
    wrapper.set_down(false);
    let second = flaky
        .key_encryptor
        .decrypt(&late, b"aad")
        .await
        .unwrap_err();
    assert!(
        second.to_string().contains("unknown master key version"),
        "remembered for a while: {second}"
    );
}

#[tokio::test]
async fn generations_never_shadow_one_another() {
    let dep = Deployment::new().await;
    // Rows under the environment's generation 3, then a node that has
    // KEY_WRAPPER but was started without that MASTER_KEY: its first
    // generation must not be numbered 1, 2 or 3.
    let old = dep.node(Some((3, 0x07))).await;
    dep.signing_key(&old).await;
    let backend = fresh_backend();
    let wrapper = Arc::new(MockKeyWrapper::new(backend, "key-e", 0x44));
    let a = dep.node(None).await;
    let v = a
        .master_keys
        .attach(a.db.clone(), wrappers(&wrapper), Some(backend))
        .await
        .unwrap()
        .created
        .unwrap();
    assert_eq!(v, 4, "above every version a stored row carries");

    // An environment key given a wrapped generation's number is refused.
    let clash = dep.node(Some((v, 0x07))).await;
    let err = clash
        .master_keys
        .attach(clash.db.clone(), vec![], None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("defined both"), "{err}");

    // An unattached encryptor is exactly the environment's, as before 13.6.
    let plain = dep.node(Some((3, 0x07))).await;
    let blob = plain.key_encryptor.encrypt(b"x", b"a").await.unwrap();
    let back = Encrypted::from_bytes(&blob.to_bytes()).unwrap();
    assert_eq!(
        &*old.key_encryptor.decrypt(&back, b"a").await.unwrap(),
        b"x"
    );
}
