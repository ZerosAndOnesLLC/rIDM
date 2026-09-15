//! Flow step matrix: every step refuses a wrong CSRF token, every step refuses
//! a flow at the wrong stage, and every single-use secret really is single use.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use common::TestApp;
use ridm_api::messaging::SenderFactory;
use ridm_api::models::{
    AuthMethods, ClientType, NewClient, NewUser, RegistrationPolicy, TenantSettings,
};
use ridm_api::services::password::{self, SetPasswordOptions};
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
                auth: AuthMethods {
                    password: true,
                    magic_link: true,
                    email_otp: true,
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
    clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("spa".into()),
            name: "My App".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://app.example/cb".into()],
            require_consent: Some(true),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    Fx { app, email, tenant }
}

/// Start a flow with a cookie-less client; returns (id, csrf).
async fn start(fx: &Fx, http: &reqwest::Client, extra: &[(&str, &str)]) -> (Uuid, String) {
    let mut q = vec![
        ("response_type", "code"),
        ("client_id", "spa"),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", "openid profile"),
        ("state", "st"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("prompt", "login"),
    ];
    q.extend_from_slice(extra);
    let res = http
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
    let state: Value = http
        .get(fx.app.tenant_url(&format!("/flows/{id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (id, state["csrf"].as_str().unwrap().to_string())
}

fn bare() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap()
}

/// Every POST step with a plausible body (csrf filled in by the caller).
fn steps() -> Vec<(&'static str, Value)> {
    vec![
        (
            "password",
            json!({"identifier": "alice", "password": "correct-horse-battery"}),
        ),
        (
            "password-change",
            json!({"new_password": "another-strong-passphrase"}),
        ),
        (
            "register",
            json!({"email": "new@example.com", "password": "another-strong-passphrase"}),
        ),
        ("magic-link", json!({"identifier": "alice@example.com"})),
        ("magic-link/verify", json!({"token": "x"})),
        ("email-otp", json!({"identifier": "alice@example.com"})),
        ("email-otp/verify", json!({"code": "000000"})),
        ("sms-otp", json!({"identifier": "+15550000001"})),
        ("sms-otp/verify", json!({"code": "000000"})),
        ("mfa/totp/enroll", json!({})),
        ("mfa/totp/confirm", json!({"code": "000000"})),
        ("mfa/verify", json!({"code": "000000"})),
        ("profile", json!({"attributes": {}})),
        ("terms", json!({"accepted": true})),
        ("consent", json!({"approve": true})),
        ("cancel", json!({})),
    ]
}

#[tokio::test]
async fn every_step_rejects_a_wrong_csrf_token_before_doing_anything() {
    let fx = fixture().await;
    let http = bare();
    let (id, _csrf) = start(&fx, &http, &[]).await;
    for (step, mut body) in steps() {
        body["csrf"] = json!("nope");
        let res = http
            .post(fx.app.tenant_url(&format!("/flows/{id}/{step}")))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403, "{step}: {}", res.text().await.unwrap());
    }
    // Missing csrf is a malformed body, never accepted either.
    let res = http
        .post(fx.app.tenant_url(&format!("/flows/{id}/password")))
        .json(&json!({"identifier": "alice", "password": "correct-horse-battery"}))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_client_error());
    // The flow is untouched: a correct attempt still works afterwards.
    assert!(fx.email.sent().is_empty());
    let state: Value = http
        .get(fx.app.tenant_url(&format!("/flows/{id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(state["stage"], "authenticate");
    assert_eq!(state["attempts"], 0);
}

#[tokio::test]
async fn every_step_refuses_the_wrong_stage_and_unknown_flows() {
    let fx = fixture().await;
    let http = bare();
    let (id, csrf) = start(&fx, &http, &[]).await;
    let post = |step: &'static str, mut body: Value, csrf: String| {
        let http = http.clone();
        let url = fx.app.tenant_url(&format!("/flows/{id}/{step}"));
        async move {
            body["csrf"] = json!(csrf);
            http.post(url).json(&body).send().await.unwrap()
        }
    };

    // At `authenticate`, the later stages are not reachable.
    for step in [
        "password-change",
        "mfa/totp/enroll",
        "mfa/totp/confirm",
        "mfa/verify",
        "profile",
        "terms",
        "consent",
    ] {
        let body = steps().into_iter().find(|(s, _)| *s == step).unwrap().1;
        let res = post(step, body, csrf.clone()).await;
        assert_eq!(res.status(), 400, "{step} at authenticate");
    }
    let res = http
        .get(fx.app.tenant_url(&format!("/flows/{id}/finish")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400, "finish before done");

    // Authenticate → consent: the first-factor steps are now refused.
    let res = post(
        "password",
        json!({"identifier": "alice", "password": "correct-horse-battery"}),
        csrf.clone(),
    )
    .await;
    assert_eq!(res.status(), 200);
    let state: Value = res.json().await.unwrap();
    assert_eq!(state["stage"], "consent");
    for step in [
        "password",
        "register",
        "magic-link",
        "magic-link/verify",
        "email-otp",
        "email-otp/verify",
        "sms-otp",
        "sms-otp/verify",
        "password-change",
        "mfa/totp/enroll",
        "mfa/totp/confirm",
        "mfa/verify",
        "profile",
        "terms",
    ] {
        let body = steps().into_iter().find(|(s, _)| *s == step).unwrap().1;
        let res = post(step, body, csrf.clone()).await;
        assert_eq!(res.status(), 400, "{step} at consent");
    }
    assert!(fx.email.sent().is_empty(), "refused steps send nothing");

    // Unknown and malformed flow ids.
    let res = http
        .post(
            fx.app
                .tenant_url(&format!("/flows/{}/password", Uuid::now_v7())),
        )
        .json(&json!({"csrf": "x", "identifier": "alice", "password": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let res = http
        .get(fx.app.tenant_url("/flows/not-a-uuid"))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_client_error());

    // Cancel ends the flow; nothing works on it afterwards.
    let res = post("cancel", json!({}), csrf.clone()).await;
    assert_eq!(res.status(), 200);
    let res = post("consent", json!({"approve": true}), csrf).await;
    assert_eq!(res.status(), 404, "cancelled flow is gone");
}

fn link_param(text: &str, name: &str) -> String {
    text.split_whitespace()
        .find(|w| w.contains(&format!("{name}=")))
        .and_then(|w| {
            url::Url::parse(w)
                .ok()?
                .query_pairs()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
        })
        .unwrap_or_else(|| panic!("no {name}= link in message"))
}

#[tokio::test]
async fn magic_links_codes_and_reset_tokens_are_single_use() {
    let fx = fixture().await;

    // Magic link: redeemed once; a second redemption on any flow fails.
    let http = bare();
    let (id, csrf) = start(&fx, &http, &[]).await;
    let res = http
        .post(fx.app.tenant_url(&format!("/flows/{id}/magic-link")))
        .json(&json!({"csrf": csrf, "identifier": "alice@example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 202);
    let token = link_param(&fx.email.last().unwrap().text, "magic");
    let res = http
        .post(fx.app.tenant_url(&format!("/flows/{id}/magic-link/verify")))
        .json(&json!({"csrf": csrf, "token": token}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let http2 = bare();
    let (id2, csrf2) = start(&fx, &http2, &[]).await;
    let res = http2
        .post(
            fx.app
                .tenant_url(&format!("/flows/{id2}/magic-link/verify")),
        )
        .json(&json!({"csrf": csrf2, "token": token}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "magic link reused");

    // Email code: consumed by the successful check.
    fx.email.clear();
    let http3 = bare();
    let (id3, csrf3) = start(&fx, &http3, &[]).await;
    let res = http3
        .post(fx.app.tenant_url(&format!("/flows/{id3}/email-otp")))
        .json(&json!({"csrf": csrf3, "identifier": "alice@example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 202);
    let text = fx.email.last().unwrap().text;
    let code: String = text
        .split(|c: char| !c.is_ascii_digit())
        .find(|s| s.len() == 6)
        .unwrap()
        .to_string();
    let res = http3
        .post(fx.app.tenant_url(&format!("/flows/{id3}/email-otp/verify")))
        .json(&json!({"csrf": csrf3, "code": code}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    // Same code on a fresh flow of the same user: not accepted.
    let http4 = bare();
    let (id4, csrf4) = start(&fx, &http4, &[]).await;
    let res = http4
        .post(fx.app.tenant_url(&format!("/flows/{id4}/email-otp/verify")))
        .json(&json!({"csrf": csrf4, "code": code}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "code reused on another flow");

    // Reset token: the second redemption fails and changes nothing.
    fx.email.clear();
    recovery::request_password_reset(&fx.app.state, &fx.tenant, "alice", &[])
        .await
        .unwrap();
    let token = link_param(&fx.email.last().unwrap().text, "token");
    recovery::complete_password_reset(
        &fx.app.state,
        &fx.tenant,
        &token,
        "another-strong-passphrase".to_string().into(),
    )
    .await
    .unwrap();
    let err = recovery::complete_password_reset(
        &fx.app.state,
        &fx.tenant,
        &token,
        "yet-another-passphrase-3".to_string().into(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, ridm_api::error::AppError::NotFound(_)),
        "{err:?}"
    );
    let http5 = bare();
    let (id5, csrf5) = start(&fx, &http5, &[]).await;
    let res = http5
        .post(fx.app.tenant_url(&format!("/flows/{id5}/password")))
        .json(
            &json!({"csrf": csrf5, "identifier": "alice", "password": "another-strong-passphrase"}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "first reset stuck");
}
