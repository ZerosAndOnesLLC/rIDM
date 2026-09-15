mod common;

use std::sync::Arc;

use async_trait::async_trait;
use common::TestApp;
use ridm_api::messaging::SenderFactory;
use ridm_api::models::{
    AuthMethods, ClientType, LocaleSettings, MessageChannel, NewClient, NewUser,
    RegistrationPolicy, TenantSettings,
};
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::registration::{self, RegistrationInput};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::{clients, recovery, users};
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
    tenant: ridm_api::models::Tenant,
}

/// Tenant offering en/de/ar with German overrides for the emails under test;
/// alice (locale de) and bob (no locale) both with passwords.
async fn fixture() -> Fx {
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
                locale: LocaleSettings {
                    default: "en".into(),
                    supported: vec!["en".into(), "de".into(), "ar".into()],
                },
                auth: AuthMethods {
                    password: true,
                    magic_link: true,
                    ..Default::default()
                },
                registration: RegistrationPolicy {
                    enabled: true,
                    require_email_verification: false,
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    for (name, locale) in [("alice", Some("de")), ("bob", None)] {
        let u = users::create(
            &app.state,
            tid,
            Actor::System,
            NewUser {
                username: name.into(),
                email: Some(format!("{name}@example.com")),
                email_verified: true,
                locale: locale.map(String::from),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        password::set_password(
            &app.state,
            tid,
            &tenant.settings.password,
            Actor::System,
            u.id,
            "correct-horse-battery".to_string().into(),
            SetPasswordOptions::default(),
        )
        .await
        .unwrap();
    }
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
    let mut tx = ridm_api::db::tenant_tx(&app.state.db, tid).await.unwrap();
    for event in ["magic_link", "password_reset"] {
        ridm_api::repos::messages::upsert_template(
            &mut *tx,
            tid,
            MessageChannel::Email,
            event,
            "de",
            Some("DE {{tenant.display_name}}"),
            "Link: {{link}}",
            None,
        )
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    Fx { app, email, tenant }
}

async fn start(fx: &Fx, extra: &[(&str, &str)]) -> (Uuid, Value) {
    let mut q = vec![
        ("response_type", "code"),
        ("client_id", "spa"),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", "openid"),
        ("state", "st"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];
    q.extend_from_slice(extra);
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&q)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let id: Uuid = loc
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .unwrap()
        .1
        .parse()
        .unwrap();
    (id, flow_state(fx, id).await)
}

async fn flow_state(fx: &Fx, id: Uuid) -> Value {
    fx.app
        .http
        .get(fx.app.tenant_url(&format!("/flows/{id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn step(fx: &Fx, id: Uuid, name: &str, body: Value) -> reqwest::Response {
    fx.app
        .http
        .post(fx.app.tenant_url(&format!("/flows/{id}/{name}")))
        .json(&body)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn flow_state_negotiates_locale_and_direction() {
    let fx = fixture().await;

    // ui_locales in order, matched by language; unsupported entries skipped.
    let (_, state) = start(&fx, &[("ui_locales", "fr ar-EG de")]).await;
    assert_eq!(state["locale"], "ar");
    assert_eq!(state["dir"], "rtl");
    assert_eq!(state["locales"], json!(["en", "de", "ar"]));
    assert_eq!(state["ui_locales"], json!(["fr", "ar-EG", "de"]));

    // Nothing requested: tenant default until a user is known...
    let (id, state) = start(&fx, &[]).await;
    assert_eq!(state["locale"], "en");
    assert_eq!(state["dir"], "ltr");
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let res = step(
        &fx,
        id,
        "password",
        json!({"csrf": csrf, "identifier": "alice", "password": "correct-horse-battery"}),
    )
    .await;
    assert_eq!(res.status(), 200);
    // ...then the user's stored locale.
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["stage"], "done");
    assert_eq!(body["locale"], "de");

    // ui_locales beats the user's locale.
    let (id, state) = start(&fx, &[("ui_locales", "en-GB"), ("prompt", "login")]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let body: Value = step(
        &fx,
        id,
        "password",
        json!({"csrf": csrf, "identifier": "alice", "password": "correct-horse-battery"}),
    )
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(body["locale"], "en");
}

#[tokio::test]
async fn emails_follow_the_negotiated_locale() {
    let fx = fixture().await;

    // Magic link for bob (no locale) in a German flow → German override.
    let (id, state) = start(&fx, &[("ui_locales", "de-AT")]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let res = step(
        &fx,
        id,
        "magic-link",
        json!({"csrf": csrf, "identifier": "bob@example.com"}),
    )
    .await;
    assert_eq!(res.status(), 202, "{}", res.text().await.unwrap());
    let mail = fx.email.last().unwrap();
    assert_eq!(mail.to[0].email, "bob@example.com");
    assert!(mail.subject.starts_with("DE "), "{}", mail.subject);

    // Same user, English flow → built-in English.
    let (id, state) = start(&fx, &[("ui_locales", "en")]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    step(
        &fx,
        id,
        "magic-link",
        json!({"csrf": csrf, "identifier": "bob@example.com"}),
    )
    .await;
    assert!(!fx.email.last().unwrap().subject.starts_with("DE "));

    // Password reset: page locale → user locale → tenant default.
    recovery::request_password_reset(&fx.app.state, &fx.tenant, "bob@example.com", &["de".into()])
        .await
        .unwrap();
    assert!(fx.email.last().unwrap().subject.starts_with("DE "));
    recovery::request_password_reset(&fx.app.state, &fx.tenant, "alice@example.com", &[])
        .await
        .unwrap();
    assert!(
        fx.email.last().unwrap().subject.starts_with("DE "),
        "user locale"
    );
    recovery::request_password_reset(&fx.app.state, &fx.tenant, "bob@example.com", &["fr".into()])
        .await
        .unwrap();
    assert!(
        !fx.email.last().unwrap().subject.starts_with("DE "),
        "tenant default"
    );
}

#[tokio::test]
async fn registration_stores_the_negotiated_locale() {
    let fx = fixture().await;
    let reg = |email: &str, locale: Option<&str>| RegistrationInput {
        email: email.into(),
        password: Some("correct-horse-battery".into()),
        locale: locale.map(String::from),
        ..Default::default()
    };
    let (u, _) = registration::register(
        &fx.app.state,
        &fx.tenant,
        reg("carol@example.com", None),
        None,
        &["de-CH".into()],
    )
    .await
    .unwrap();
    assert_eq!(u.locale.as_deref(), Some("de"), "from ui_locales");
    let (u, _) = registration::register(
        &fx.app.state,
        &fx.tenant,
        reg("dave@example.com", Some("AR")),
        None,
        &["de".into()],
    )
    .await
    .unwrap();
    assert_eq!(
        u.locale.as_deref(),
        Some("ar"),
        "form choice wins, normalized"
    );
    let (u, _) = registration::register(
        &fx.app.state,
        &fx.tenant,
        reg("erin@example.com", Some("xx")),
        None,
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        u.locale.as_deref(),
        Some("en"),
        "unsupported → tenant default"
    );
}

#[tokio::test]
async fn tenant_locale_settings_are_validated_and_normalized() {
    let fx = fixture().await;
    let update = |locale: LocaleSettings| TenantUpdate {
        settings: Some(TenantSettings {
            locale,
            ..Default::default()
        }),
        ..Default::default()
    };
    let err = tenants::update(
        &fx.app.state,
        Actor::System,
        fx.tenant.id,
        update(LocaleSettings {
            default: "fr".into(),
            supported: vec!["en".into()],
        }),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, ridm_api::error::AppError::BadRequest(_)),
        "{err:?}"
    );
    let t = tenants::update(
        &fx.app.state,
        Actor::System,
        fx.tenant.id,
        update(LocaleSettings {
            default: "pt_br".into(),
            supported: vec!["EN".into(), "PT-BR".into(), "pt-br".into()],
        }),
    )
    .await
    .unwrap();
    assert_eq!(t.settings.locale.default, "pt-BR");
    assert_eq!(t.settings.locale.supported, vec!["en", "pt-BR"]);
}
