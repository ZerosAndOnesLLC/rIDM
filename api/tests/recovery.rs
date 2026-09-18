mod common;

use std::sync::Arc;

use async_trait::async_trait;
use common::TestApp;
use ridm_api::messaging::SenderFactory;
use ridm_api::models::{
    ClientType, NewClient, NewUser, PasswordPolicy, TenantSettings, UserStatus,
};
use ridm_api::services::password::{self, SetPasswordOptions, VerifyOutcome};
use ridm_api::services::refresh_tokens::{self, IssueRequest};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::{clients, users};
use ridm_api::state::AppState;
use ridm_core::events::Actor;
use ridm_core::providers::{EmailSender, SmsSender};
use ridm_core::test_support::{MockEmailSender, MockSmsSender};
use serde_json::{Value, json};
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Mocks(Arc<MockEmailSender>);
#[async_trait]
impl SenderFactory for Mocks {
    async fn email(
        &self,
        _: &AppState,
        _: Uuid,
    ) -> ridm_api::error::AppResult<Option<Arc<dyn EmailSender>>> {
        Ok(Some(self.0.clone()))
    }
    async fn sms(
        &self,
        _: &AppState,
        _: Uuid,
    ) -> ridm_api::error::AppResult<Option<Arc<dyn SmsSender>>> {
        Ok(Some(Arc::new(MockSmsSender::new())))
    }
}

async fn fixture() -> (TestApp, Arc<MockEmailSender>, Uuid) {
    let email = Arc::new(MockEmailSender::new());
    let e2 = email.clone();
    let app = TestApp::spawn_configured(axum::Router::new(), move |st| {
        st.senders = Arc::new(Mocks(e2))
    })
    .await;
    let tid = app.tenant.id;
    tenants::update(
        &app.state,
        Actor::System,
        tid,
        TenantUpdate {
            settings: Some(TenantSettings {
                password: PasswordPolicy {
                    min_length: 10,
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
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
    password::set_password(
        &app.state,
        tid,
        &PasswordPolicy {
            min_length: 10,
            ..Default::default()
        },
        Actor::System,
        user.id,
        "old-password-1".to_string().into(),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();
    clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("spa".into()),
            name: "spa".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://app.example/cb".into()],
            require_consent: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    (app, email, user.id)
}

fn token_from(text: &str) -> String {
    let line = text.lines().find(|l| l.contains("token=")).unwrap().trim();
    url::Url::parse(line)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "token")
        .unwrap()
        .1
        .into_owned()
}

#[tokio::test]
async fn password_reset_by_email_token() {
    let (app, email, uid) = fixture().await;
    let tid = app.tenant.id;
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    // A live refresh token that must die with the reset.
    let rt = refresh_tokens::issue(
        &app.state,
        tid,
        IssueRequest {
            client_id: "spa",
            user_id: Some(uid),
            session_id: None,
            scopes: &[],
            audiences: &[],
            ttl: chrono::Duration::days(1),
            dpop_jkt: None,
            auth_time: None,
            amr: &[],
            acr: None,
        },
    )
    .await
    .unwrap();

    // Unknown identifiers get the same 202 and no email.
    let res = app
        .http
        .post(app.tenant_url("/recovery/password"))
        .json(&json!({"identifier": "nobody"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 202);
    assert!(email.sent().is_empty());
    let res = app
        .http
        .post(app.tenant_url("/recovery/password"))
        .json(&json!({"identifier": "Alice"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 202);
    let mail = email.last().unwrap();
    assert!(mail.subject.contains("Reset"));
    let token = token_from(&mail.text);
    assert!(mail.text.contains("/recover/?"));

    // Policy failure keeps the token usable; then a good password resets.
    let res = app
        .http
        .post(app.tenant_url("/recovery/password/confirm"))
        .json(&json!({"token": token, "new_password": "short"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let res = app
        .http
        .post(app.tenant_url("/recovery/password/confirm"))
        .json(&json!({"token": "bogus", "new_password": "brand-new-password"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let res = app
        .http
        .post(app.tenant_url("/recovery/password/confirm"))
        .json(&json!({"token": token, "new_password": "brand-new-password"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    assert_eq!(res.json::<Value>().await.unwrap()["reset"], true);
    // Single use.
    let res = app
        .http
        .post(app.tenant_url("/recovery/password/confirm"))
        .json(&json!({"token": token, "new_password": "another-new-password"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    let user = users::get(&app.state, tid, uid).await.unwrap();
    assert!(user.email_verified, "reset via email proves the address");
    assert_eq!(
        password::verify_and_upgrade(
            &app.state,
            tid,
            &tenant.settings.password,
            &user,
            "brand-new-password".to_string().into()
        )
        .await
        .unwrap(),
        VerifyOutcome::Valid { must_change: false }
    );
    assert_eq!(
        password::verify_and_upgrade(
            &app.state,
            tid,
            &tenant.settings.password,
            &user,
            "old-password-1".to_string().into()
        )
        .await
        .unwrap(),
        VerifyOutcome::Invalid
    );
    assert!(
        refresh_tokens::rotate(&app.state, tid, "spa", &rt.token, None, &[], None)
            .await
            .is_err(),
        "refresh tokens revoked by the reset"
    );

    // Rate limit: at most 3 requests per identifier in the window.
    for _ in 0..2 {
        assert_eq!(
            app.http
                .post(app.tenant_url("/recovery/password"))
                .json(&json!({"identifier": "alice"}))
                .send()
                .await
                .unwrap()
                .status(),
            202
        );
    }
    assert_eq!(
        app.http
            .post(app.tenant_url("/recovery/password"))
            .json(&json!({"identifier": "alice"}))
            .send()
            .await
            .unwrap()
            .status(),
        429
    );
}

#[tokio::test]
async fn resend_verification_and_temporary_password_flow() {
    let (app, email, uid) = fixture().await;
    let tid = app.tenant.id;
    // Verified users get nothing; a pending, unverified user gets a fresh link.
    let res = app
        .http
        .post(app.tenant_url("/verification/email/resend"))
        .json(&json!({"identifier": "alice"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 202);
    users::update(
        &app.state,
        tid,
        Actor::System,
        uid,
        ridm_api::models::UserUpdate {
            email_verified: Some(false),
            status: Some(UserStatus::Pending),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let res = app
        .http
        .post(app.tenant_url("/verification/email/resend"))
        .json(&json!({"identifier": "alice@example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 202);
    let mail = email.last().expect("verification email");
    assert!(mail.text.contains("/verify/?"));
    let token = token_from(&mail.text);
    let res = app
        .http
        .post(app.tenant_url("/verification/email/confirm"))
        .json(&json!({"token": token}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let user = users::get(&app.state, tid, uid).await.unwrap();
    assert!(user.email_verified);
    assert_eq!(user.status, UserStatus::Active);

    // Temporary password: admin gets it once; login forces a change.
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    let temp = password::set_temporary_password(
        &app.state,
        tid,
        &tenant.settings.password,
        Actor::System,
        uid,
    )
    .await
    .unwrap();
    assert!(temp.len() >= 24);
    let res = app
        .http
        .get(app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "openid"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let id: Uuid = loc
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .unwrap()
        .1
        .parse()
        .unwrap();
    let st: Value = app
        .http
        .get(app.tenant_url(&format!("/flows/{id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let csrf = st["csrf"].as_str().unwrap().to_string();
    let body: Value = app
        .http
        .post(app.tenant_url(&format!("/flows/{id}/password")))
        .json(&json!({"csrf": csrf, "identifier": "alice", "password": &*temp}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["stage"], "password_change", "{body}");
    let body: Value = app
        .http
        .post(app.tenant_url(&format!("/flows/{id}/password-change")))
        .json(&json!({"csrf": csrf, "new_password": "my-own-new-password"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["stage"], "done");
    let user = users::get(&app.state, tid, uid).await.unwrap();
    assert!(!user.must_change_password);
}
