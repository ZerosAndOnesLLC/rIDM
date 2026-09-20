mod common;

use common::TestApp;
use ridm_api::error::AppError;
use ridm_api::models::MASTER_TENANT_ID;
use ridm_api::services::bootstrap::{self, BootstrapOutcome, BootstrapRequest, GLOBAL_OWNER_ROLE};
use ridm_api::services::password::{self, VerifyOutcome};
use ridm_api::services::{roles, startup, users};
use zeroize::Zeroizing;

fn req(password: &str) -> BootstrapRequest {
    BootstrapRequest {
        admin_email: "Root@Example.com".into(),
        admin_username: "root".into(),
        admin_password: Zeroizing::new(password.to_string()),
        must_change_password: true,
    }
}

// Several threads, so the concurrent start-up at the end really overlaps.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bootstrap_is_idempotent_and_creates_a_global_owner() {
    let app = TestApp::spawn().await;
    // Other test binaries may have bootstrapped the shared master tenant already;
    // make sure we start from a clean state for this database.
    let mut tx = ridm_api::db::bypass_tx(&app.state.db).await.unwrap();
    sqlx::query("DELETE FROM users WHERE tenant_id = $1")
        .bind(MASTER_TENANT_ID)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(!bootstrap::is_bootstrapped(&app.state).await.unwrap());

    // Weak password is rejected by the master tenant's policy (min 12).
    let weak = bootstrap::run(&app.state, req("short")).await;
    assert!(matches!(weak, Err(AppError::Validation(_))), "{weak:?}");
    assert!(!bootstrap::is_bootstrapped(&app.state).await.unwrap());
    assert!(
        users::find_by_identifier(&app.state, MASTER_TENANT_ID, "root")
            .await
            .unwrap()
            .is_none(),
        "a rejected password must not leave a partial admin user"
    );

    let first = bootstrap::run(&app.state, req("correct-horse-battery"))
        .await
        .unwrap();
    let BootstrapOutcome::Created { admin_user_id } = first else {
        panic!("expected Created, got {first:?}");
    };
    assert!(bootstrap::is_bootstrapped(&app.state).await.unwrap());

    let admin = users::get(&app.state, MASTER_TENANT_ID, admin_user_id)
        .await
        .unwrap();
    assert_eq!(admin.username, "root");
    assert_eq!(admin.email.as_deref(), Some("root@example.com"));
    assert!(admin.email_verified);
    assert!(admin.must_change_password);
    let names = roles::effective_role_names(&app.state, MASTER_TENANT_ID, admin.id, None)
        .await
        .unwrap();
    assert_eq!(names, vec![GLOBAL_OWNER_ROLE]);
    let master = ridm_api::services::tenants::get(&app.state, MASTER_TENANT_ID)
        .await
        .unwrap();
    assert_eq!(
        password::verify_and_upgrade(
            &app.state,
            MASTER_TENANT_ID,
            &master.settings.password,
            &admin,
            Zeroizing::new("correct-horse-battery".into())
        )
        .await
        .unwrap(),
        VerifyOutcome::Valid { must_change: true }
    );

    // Second run: no changes, even with a different password.
    let second = bootstrap::run(&app.state, req("another-long-password"))
        .await
        .unwrap();
    assert_eq!(second, BootstrapOutcome::AlreadyBootstrapped);
    let admin2 = users::get(&app.state, MASTER_TENANT_ID, admin_user_id)
        .await
        .unwrap();
    assert_eq!(admin2.password_hash, admin.password_hash);

    // Nodes of a fresh deployment start together. Under the start-up lock
    // they take turns: one creates the administrator, the rest find it (the
    // same race without the lock made the losers fail on the unique username).
    let mut tx = ridm_api::db::bypass_tx(&app.state.db).await.unwrap();
    sqlx::query("DELETE FROM users WHERE tenant_id = $1")
        .bind(MASTER_TENANT_ID)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // A password made at run time: nothing here needs to know it.
    let password = uuid::Uuid::new_v4().to_string();
    let nodes = (0..4).map(|_| {
        let state = app.state.clone();
        let password = password.clone();
        tokio::spawn(async move {
            startup::serialized(&state, bootstrap::run(&state, req(&password))).await
        })
    });
    let outcomes: Vec<_> = futures::future::join_all(nodes)
        .await
        .into_iter()
        .map(|r| r.unwrap().expect("every node starts"))
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, BootstrapOutcome::Created { .. }))
            .count(),
        1,
        "{outcomes:?}"
    );
    assert!(bootstrap::is_bootstrapped(&app.state).await.unwrap());
}

/// `BOOTSTRAP_SAMPLE_CLIENT=true` seeds a public SPA client in `master`, once.
#[tokio::test]
async fn the_sample_client_is_seeded_idempotently() {
    use ridm_api::models::ClientType;
    use ridm_api::services::clients;
    let app = TestApp::spawn().await;
    // The shared master tenant may have it from an earlier run already.
    bootstrap::ensure_sample_client(&app.state).await.unwrap();
    assert!(
        !bootstrap::ensure_sample_client(&app.state).await.unwrap(),
        "a second run creates nothing"
    );
    let client = clients::find_by_client_id(&app.state, MASTER_TENANT_ID, "sample-spa")
        .await
        .unwrap()
        .expect("sample client");
    assert_eq!(client.client_type, ClientType::Spa);
    assert_eq!(client.redirect_uris, ["http://localhost:3000/callback"]);
    assert!(client.require_pkce);
}
