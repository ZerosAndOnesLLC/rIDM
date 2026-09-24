mod common;

use std::sync::Arc;

use async_trait::async_trait;
use common::TestApp;
use ridm_api::messaging::SenderFactory;
use ridm_api::models::{
    AuthMethods, ClientType, NewClient, NewUser, NotificationPolicy, TenantSettings, UserUpdate,
};
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::{clients, notifications, recovery, users};
use ridm_api::state::AppState;
use ridm_core::events::Actor;
use ridm_core::providers::{EmailSender, SmsSender};
use ridm_core::test_support::{MockEmailSender, MockSmsSender};
use serde_json::{Value, json};
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Mocks {
    email: Arc<MockEmailSender>,
    sms: Arc<MockSmsSender>,
}

#[async_trait]
impl SenderFactory for Mocks {
    async fn email(
        &self,
        _: &AppState,
        _: Uuid,
    ) -> ridm_api::error::AppResult<Option<Arc<dyn EmailSender>>> {
        Ok(Some(self.email.clone()))
    }
    async fn sms(
        &self,
        _: &AppState,
        _: Uuid,
    ) -> ridm_api::error::AppResult<Option<Arc<dyn SmsSender>>> {
        Ok(Some(self.sms.clone()))
    }
}

struct Fx {
    app: TestApp,
    email: Arc<MockEmailSender>,
    sms: Arc<MockSmsSender>,
    tenant: ridm_api::models::Tenant,
    user_id: Uuid,
}

async fn fixture(notifications: NotificationPolicy) -> Fx {
    let email = Arc::new(MockEmailSender::new());
    let sms = Arc::new(MockSmsSender::new());
    let (e2, s2) = (email.clone(), sms.clone());
    let app = TestApp::spawn_configured(axum::Router::new(), move |st| {
        st.senders = Arc::new(Mocks { email: e2, sms: s2 });
    })
    .await;
    let tid = app.tenant.id;
    let tenant = tenants::update(
        &app.state,
        Actor::System,
        tid,
        TenantUpdate {
            settings: Some(TenantSettings {
                notifications,
                auth: AuthMethods {
                    password: true,
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
            email_verified: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // Initial password: no notice.
    password::set_password(
        &app.state,
        tid,
        &tenant.settings.password,
        Actor::System,
        user.id,
        "correct-horse-battery".to_string().into(),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();
    common::settle(&app.state).await;
    assert!(email.sent().is_empty(), "initial password must not notify");
    clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("spa".into()),
            name: "My App".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://app.example/cb".into()],
            require_consent: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    Fx {
        app,
        email,
        sms,
        tenant,
        user_id: user.id,
    }
}

/// Full password login through the flow API with a given User-Agent.
async fn login(fx: &Fx, user_agent: &str) {
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "openid"),
            ("state", "st"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("prompt", "login"),
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
    let state: Value = fx
        .app
        .http
        .get(fx.app.tenant_url(&format!("/flows/{id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // A fresh client each time: no cookie jar, so every login is a new browser session.
    let bare = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let res = bare
        .post(fx.app.tenant_url(&format!("/flows/{id}/password")))
        .header("user-agent", user_agent)
        .json(&json!({"csrf": state["csrf"], "identifier": "alice", "password": "correct-horse-battery"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
}

#[tokio::test]
async fn new_device_notice_only_for_returning_users_on_unseen_browsers() {
    let fx = fixture(NotificationPolicy::default()).await;
    login(&fx, "Browser/A").await;
    common::settle(&fx.app.state).await;
    assert!(
        fx.email.sent().is_empty(),
        "first ever login is not a new device"
    );
    login(&fx, "Browser/A").await;
    common::settle(&fx.app.state).await;
    assert!(fx.email.sent().is_empty(), "same browser again");
    login(&fx, "Browser/B").await;
    common::settle(&fx.app.state).await;
    let sent = fx.email.sent();
    assert_eq!(sent.len(), 1, "unseen browser notifies");
    let mail = &sent[0];
    assert_eq!(mail.to[0].email, "alice@example.com");
    assert!(mail.subject.contains("New sign-in"), "{}", mail.subject);
    assert!(mail.text.contains("Browser/B"), "{}", mail.text);
    assert!(mail.text.contains("127.0.0.1"), "{}", mail.text);
    login(&fx, "Browser/B").await;
    common::settle(&fx.app.state).await;
    assert_eq!(fx.email.sent().len(), 1, "now known");

    // Users without email but with a verified phone get a text instead.
    users::update(
        &fx.app.state,
        fx.tenant.id,
        Actor::System,
        fx.user_id,
        UserUpdate {
            email: Some(None),
            phone: Some(Some("+15550000001".into())),
            phone_verified: Some(true),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    common::settle(&fx.app.state).await;
    fx.email.clear();
    login(&fx, "Browser/C").await;
    common::settle(&fx.app.state).await;
    assert!(fx.email.sent().is_empty());
    common::settle(&fx.app.state).await;
    let texts = fx.sms.sent();
    assert_eq!(texts.len(), 1);
    assert!(texts[0].body.contains("Browser/C"), "{}", texts[0].body);
}

#[tokio::test]
async fn password_and_email_changes_notify_and_policy_can_silence_them() {
    let fx = fixture(NotificationPolicy::default()).await;

    // Password reset through the recovery flow.
    recovery::request_password_reset(&fx.app.state, &fx.tenant, "alice", &[])
        .await
        .unwrap();
    common::settle(&fx.app.state).await;
    let link = fx.email.last().unwrap().text;
    let token = link
        .split("token=")
        .nth(1)
        .unwrap()
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .next()
        .unwrap()
        .to_string();
    common::settle(&fx.app.state).await;
    fx.email.clear();
    recovery::complete_password_reset(
        &fx.app.state,
        &fx.tenant,
        &token,
        "another-strong-passphrase".to_string().into(),
    )
    .await
    .unwrap();
    common::settle(&fx.app.state).await;
    let sent = fx.email.sent();
    assert_eq!(sent.len(), 1);
    assert!(
        sent[0].subject.contains("password was changed"),
        "{}",
        sent[0].subject
    );
    assert!(sent[0].text.contains("UTC"), "{}", sent[0].text);

    // Email change: the old address is told where it moved.
    common::settle(&fx.app.state).await;
    fx.email.clear();
    users::update(
        &fx.app.state,
        fx.tenant.id,
        Actor::User { id: fx.user_id },
        fx.user_id,
        UserUpdate {
            email: Some(Some("new@example.com".into())),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    common::settle(&fx.app.state).await;
    let sent = fx.email.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to[0].email, "alice@example.com");
    assert!(sent[0].text.contains("new@example.com"), "{}", sent[0].text);
    // Unchanged email: nothing.
    common::settle(&fx.app.state).await;
    fx.email.clear();
    users::update(
        &fx.app.state,
        fx.tenant.id,
        Actor::System,
        fx.user_id,
        UserUpdate {
            email: Some(Some("NEW@example.com".into())),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    common::settle(&fx.app.state).await;
    assert!(fx.email.sent().is_empty(), "normalized same address");

    // MFA change hook (Phase 7 calls it).
    notifications::mfa_changed(&fx.app.state, fx.tenant.id, fx.user_id, "TOTP enrolled").await;
    common::settle(&fx.app.state).await;
    let sent = fx.email.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to[0].email, "new@example.com");
    assert!(sent[0].text.contains("TOTP enrolled"));

    // Policy off: silence.
    let quiet = fixture(NotificationPolicy {
        new_device: false,
        password_changed: false,
        mfa_changed: false,
        email_changed: false,
    })
    .await;
    login(&quiet, "A").await;
    login(&quiet, "B").await;
    password::set_password(
        &quiet.app.state,
        quiet.tenant.id,
        &quiet.tenant.settings.password,
        Actor::User { id: quiet.user_id },
        quiet.user_id,
        "another-strong-passphrase".to_string().into(),
        SetPasswordOptions {
            notify: true,
            by_user: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    notifications::mfa_changed(&quiet.app.state, quiet.tenant.id, quiet.user_id, "x").await;
    common::settle(&quiet.app.state).await;
    assert!(quiet.email.sent().is_empty());
}
