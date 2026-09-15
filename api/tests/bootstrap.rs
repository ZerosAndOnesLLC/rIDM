mod common;

use common::TestApp;
use ridm_api::error::AppError;
use ridm_api::models::MASTER_TENANT_ID;
use ridm_api::services::bootstrap::{self, BootstrapOutcome, BootstrapRequest, GLOBAL_OWNER_ROLE};
use ridm_api::services::password::{self, VerifyOutcome};
use ridm_api::services::{roles, users};
use zeroize::Zeroizing;

fn req(password: &str) -> BootstrapRequest {
    BootstrapRequest {
        admin_email: "Root@Example.com".into(),
        admin_username: "root".into(),
        admin_password: Zeroizing::new(password.to_string()),
        must_change_password: true,
    }
}

#[tokio::test]
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
    let names = roles::effective_role_names(&app.state, MASTER_TENANT_ID, admin.id)
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
}
