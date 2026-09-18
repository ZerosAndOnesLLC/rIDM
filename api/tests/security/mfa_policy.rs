//! Review finding (Phase 10): the password step opens the SSO session (and
//! sets its cookie) before the second factor. `/authorize` enforced only a
//! second factor the client asked for (`acr_values`), not the tenant's MFA
//! policy, so abandoning the MFA page and starting a fresh authorization
//! returned a code backed by a password alone. A session now owes whatever
//! step its sign-in skipped, judged from the policy as it stands.

use ridm_api::models::{MfaPolicy, NewClient, TenantSettings, UserUpdate};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::{totp, users};
use ridm_core::events::Actor;
use totp_rs::{Algorithm, Builder, Secret};
use uuid::Uuid;

use crate::common::TestApp;
use crate::support::{self, browser, param};

async fn set_policy(app: &TestApp, mfa: MfaPolicy) {
    let current = tenants::get(&app.state, app.tenant.id).await.unwrap();
    tenants::update(
        &app.state,
        Actor::System,
        app.tenant.id,
        TenantUpdate {
            settings: Some(TenantSettings {
                mfa,
                ..current.settings.0.clone()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
}

fn totp_now(secret_b32: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(Secret::try_from_base32(secret_b32).unwrap())
        .with_issuer(Some("x"))
        .with_account_name("y")
        .build()
        .unwrap()
        .generate(now)
        .to_string()
}

async fn enrol_totp(app: &TestApp, user_id: Uuid) {
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let user = users::get(&app.state, app.tenant.id, user_id)
        .await
        .unwrap();
    let scope = Uuid::now_v7();
    let e = totp::begin_enrolment(&app.state, &tenant, scope, &user)
        .await
        .unwrap();
    totp::confirm_enrolment(
        &app.state,
        &tenant,
        scope,
        &user,
        &totp_now(&e.secret),
        None,
    )
    .await
    .unwrap()
    .unwrap();
}

/// `/authorize` on a session that skipped its step must not issue a code:
/// `prompt=none` reports `login_required`, otherwise the browser is sent to
/// a flow at that step for the same session.
async fn assert_owes(app: &TestApp, jar: &reqwest::Client, stage: &str, page: &str) {
    let slug = app.tenant.slug.clone();
    let loc = support::authorize(jar, app, &slug, None, &[]).await;
    assert!(param(&loc, "code").is_none(), "a code was issued: {loc}");
    assert!(loc.path().ends_with(&format!("/{page}/")), "{loc}");
    let flow = param(&loc, "flow").expect("a flow for the owed step");
    let state: serde_json::Value = jar
        .get(app.tenant_url(&format!("/flows/{flow}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(state["stage"], stage, "{state}");

    let loc = support::authorize(jar, app, &slug, None, &[("prompt", "none")]).await;
    assert!(param(&loc, "code").is_none(), "a code was issued: {loc}");
    assert_eq!(param(&loc, "error").as_deref(), Some("login_required"));
}

#[tokio::test]
async fn an_abandoned_second_factor_leaves_no_usable_session() {
    let app = TestApp::spawn().await;
    set_policy(&app, MfaPolicy::Required).await;
    support::spa(&app, app.tenant.id, NewClient::default()).await;
    let alice = support::user_with_password(&app, app.tenant.id, "alice").await;
    enrol_totp(&app, alice).await;

    // The password passes, the MFA page is shown... and abandoned.
    let jar = browser();
    let (_, after) = support::password_login(&jar, &app, &app.tenant.slug, "alice").await;
    assert!(after["stage"] == "mfa", "the flow is not at `mfa`");

    // A fresh authorization, without acr_values, from the same browser.
    assert_owes(&app, &jar, "mfa", "mfa").await;
}

#[tokio::test]
async fn a_policy_tightened_after_sign_in_applies_to_the_live_session() {
    let app = TestApp::spawn().await;
    set_policy(&app, MfaPolicy::Off).await;
    support::spa(&app, app.tenant.id, NewClient::default()).await;
    support::user_with_password(&app, app.tenant.id, "alice").await;
    let jar = browser();
    let (_, after) = support::password_login(&jar, &app, &app.tenant.slug, "alice").await;
    assert!(after["stage"] == "done", "the flow is not at `done`");
    let code = support::finish(&jar, &after).await;
    assert!(!code.is_empty());

    // The administrator now requires a second factor of everyone.
    set_policy(&app, MfaPolicy::Required).await;
    assert_owes(&app, &jar, "mfa", "mfa").await;
}

#[tokio::test]
async fn an_abandoned_password_change_leaves_no_usable_session() {
    let app = TestApp::spawn().await;
    support::spa(&app, app.tenant.id, NewClient::default()).await;
    let alice = support::user_with_password(&app, app.tenant.id, "alice").await;
    users::update(
        &app.state,
        app.tenant.id,
        Actor::System,
        alice,
        UserUpdate {
            must_change_password: Some(true),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let jar = browser();
    let (_, after) = support::password_login(&jar, &app, &app.tenant.slug, "alice").await;
    assert!(
        after["stage"] == "password_change",
        "the flow is not at `password_change`"
    );
    assert_owes(&app, &jar, "password_change", "login").await;
}
