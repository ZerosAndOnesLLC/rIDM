mod common;

use common::TestApp;
use ridm_api::error::AppError;
use ridm_api::models::{NewUser, PasswordPolicy};
use ridm_api::services::password::{self, SetPasswordOptions, VerifyOutcome};
use ridm_api::services::users;
use ridm_core::events::Actor;
use zeroize::Zeroizing;

fn pw(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_string())
}

#[tokio::test]
async fn set_verify_policy_and_history() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let user = users::create(
        &app.state,
        tid,
        Actor::System,
        NewUser {
            username: "alice".into(),
            email: Some("alice@example.com".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let policy = PasswordPolicy {
        min_length: 8,
        history: 2,
        ..Default::default()
    };

    // Policy violations are reported as field errors.
    let short = password::set_password(
        &app.state,
        tid,
        &policy,
        Actor::System,
        user.id,
        pw("short"),
        SetPasswordOptions::default(),
    )
    .await;
    assert!(matches!(short, Err(AppError::Validation(_))), "{short:?}");
    let contains_name = password::set_password(
        &app.state,
        tid,
        &policy,
        Actor::System,
        user.id,
        pw("xx-alice-xx"),
        SetPasswordOptions::default(),
    )
    .await;
    assert!(matches!(contains_name, Err(AppError::Validation(_))));

    password::set_password(
        &app.state,
        tid,
        &policy,
        Actor::System,
        user.id,
        pw("first-password"),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();
    let u = users::get(&app.state, tid, user.id).await.unwrap();
    assert!(u.has_password());
    assert_eq!(u.password_algo.as_deref(), Some("argon2id"));
    assert!(u.password_changed_at.is_some());

    assert_eq!(
        password::verify_and_upgrade(&app.state, tid, &policy, &u, pw("first-password"))
            .await
            .unwrap(),
        VerifyOutcome::Valid { must_change: false }
    );
    assert_eq!(
        password::verify_and_upgrade(&app.state, tid, &policy, &u, pw("wrong"))
            .await
            .unwrap(),
        VerifyOutcome::Invalid
    );

    // History: the current and the previous N are rejected; older ones become allowed.
    password::set_password(
        &app.state,
        tid,
        &policy,
        Actor::System,
        user.id,
        pw("second-password"),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();
    for reused in ["first-password", "second-password"] {
        let r = password::set_password(
            &app.state,
            tid,
            &policy,
            Actor::System,
            user.id,
            pw(reused),
            SetPasswordOptions::default(),
        )
        .await;
        assert!(
            matches!(r, Err(AppError::Validation(_))),
            "{reused} should be rejected: {r:?}"
        );
    }
    password::set_password(
        &app.state,
        tid,
        &policy,
        Actor::System,
        user.id,
        pw("third-password"),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();
    // History keeps 2: first-password has aged out.
    password::set_password(
        &app.state,
        tid,
        &policy,
        Actor::System,
        user.id,
        pw("first-password"),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();

    // Temporary password forces a change; skip_policy bypasses checks.
    password::set_password(
        &app.state,
        tid,
        &policy,
        Actor::System,
        user.id,
        pw("x"),
        SetPasswordOptions {
            must_change: true,
            skip_policy: true,
            by_user: false,
            notify: false,
        },
    )
    .await
    .unwrap();
    let u = users::get(&app.state, tid, user.id).await.unwrap();
    assert!(u.must_change_password);
    assert_eq!(
        password::verify_and_upgrade(&app.state, tid, &policy, &u, pw("x"))
            .await
            .unwrap(),
        VerifyOutcome::Valid { must_change: true }
    );

    // A user without a password never verifies.
    let nopw = users::create(
        &app.state,
        tid,
        Actor::System,
        NewUser {
            username: "nopw".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        password::verify_and_upgrade(&app.state, tid, &policy, &nopw, pw("anything"))
            .await
            .unwrap(),
        VerifyOutcome::Invalid
    );
}

#[tokio::test]
async fn legacy_hash_is_upgraded_on_successful_login() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let policy = PasswordPolicy::default();
    let user = users::create(
        &app.state,
        tid,
        Actor::System,
        NewUser {
            username: "legacy".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let bcrypt_hash = bcrypt::hash("imported-secret", 4).unwrap();
    password::import_hash(&app.state, tid, user.id, &bcrypt_hash)
        .await
        .unwrap();
    let u = users::get(&app.state, tid, user.id).await.unwrap();
    assert_eq!(u.password_algo.as_deref(), Some("bcrypt"));

    // Wrong password: nothing changes.
    assert_eq!(
        password::verify_and_upgrade(&app.state, tid, &policy, &u, pw("nope"))
            .await
            .unwrap(),
        VerifyOutcome::Invalid
    );
    assert_eq!(
        users::get(&app.state, tid, user.id)
            .await
            .unwrap()
            .password_algo
            .as_deref(),
        Some("bcrypt")
    );

    // Right password: hash is transparently replaced with argon2id.
    assert_eq!(
        password::verify_and_upgrade(&app.state, tid, &policy, &u, pw("imported-secret"))
            .await
            .unwrap(),
        VerifyOutcome::Valid { must_change: false }
    );
    let u2 = users::get(&app.state, tid, user.id).await.unwrap();
    assert_eq!(u2.password_algo.as_deref(), Some("argon2id"));
    assert!(
        u2.password_hash
            .as_deref()
            .unwrap()
            .starts_with("$argon2id$")
    );
    assert_eq!(
        password::verify_and_upgrade(&app.state, tid, &policy, &u2, pw("imported-secret"))
            .await
            .unwrap(),
        VerifyOutcome::Valid { must_change: false }
    );

    assert!(matches!(
        password::import_hash(&app.state, tid, user.id, "plaintext").await,
        Err(AppError::BadRequest(_))
    ));
}

#[tokio::test]
async fn expired_password_requires_change() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let user = users::create(
        &app.state,
        tid,
        Actor::System,
        NewUser {
            username: "aging".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let policy = PasswordPolicy {
        max_age_days: Some(30),
        history: 0,
        ..Default::default()
    };
    password::set_password(
        &app.state,
        tid,
        &policy,
        Actor::System,
        user.id,
        pw("valid-password-1"),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();
    let u = users::get(&app.state, tid, user.id).await.unwrap();
    assert!(u.password_expires_at.is_some());
    assert_eq!(
        password::verify_and_upgrade(&app.state, tid, &policy, &u, pw("valid-password-1"))
            .await
            .unwrap(),
        VerifyOutcome::Valid { must_change: false }
    );
    // Age the password artificially.
    let mut tx = ridm_api::db::tenant_tx(&app.state.db, tid).await.unwrap();
    sqlx::query("UPDATE users SET password_changed_at = now() - interval '31 days', password_expires_at = now() - interval '1 day' WHERE id = $1")
        .bind(user.id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let u = users::get(&app.state, tid, user.id).await.unwrap();
    assert_eq!(
        password::verify_and_upgrade(&app.state, tid, &policy, &u, pw("valid-password-1"))
            .await
            .unwrap(),
        VerifyOutcome::Valid { must_change: true }
    );
}
