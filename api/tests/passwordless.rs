mod common;

use std::sync::Arc;

use async_trait::async_trait;
use common::TestApp;
use ridm_api::messaging::SenderFactory;
use ridm_api::models::{AuthMethods, ClientType, NewClient, NewUser, TenantSettings};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::{clients, users};
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
    user_id: Uuid,
}

async fn fixture(auth: AuthMethods) -> Fx {
    let email = Arc::new(MockEmailSender::new());
    let sms = Arc::new(MockSmsSender::new());
    let (e2, s2) = (email.clone(), sms.clone());
    let app = TestApp::spawn_configured(axum::Router::new(), move |st| {
        st.senders = Arc::new(Mocks { email: e2, sms: s2 });
    })
    .await;
    let tid = app.tenant.id;
    tenants::update(
        &app.state,
        Actor::System,
        tid,
        TenantUpdate {
            settings: Some(TenantSettings {
                auth,
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
            phone: Some("+15550001111".into()),
            phone_verified: true,
            ..Default::default()
        },
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
    Fx {
        app,
        email,
        sms,
        user_id: user.id,
    }
}

async fn start(fx: &Fx) -> (Uuid, String, Value) {
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "openid"),
            ("prompt", "login"),
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
    let csrf = state["csrf"].as_str().unwrap().to_string();
    (id, csrf, state)
}

async fn post(fx: &Fx, id: Uuid, step: &str, body: Value) -> reqwest::Response {
    fx.app
        .http
        .post(fx.app.tenant_url(&format!("/flows/{id}/{step}")))
        .json(&body)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn email_otp_login() {
    let fx = fixture(AuthMethods {
        email_otp: true,
        ..Default::default()
    })
    .await;
    let (id, csrf, state) = start(&fx).await;
    assert_eq!(state["methods"], json!(["password", "email_otp"]));

    // Unknown identifier: same 202, nothing sent.
    let res = post(
        &fx,
        id,
        "email-otp",
        json!({"csrf": csrf, "identifier": "nobody@example.com"}),
    )
    .await;
    assert_eq!(res.status(), 202);
    assert!(fx.email.sent().is_empty());
    let res = post(
        &fx,
        id,
        "email-otp",
        json!({"csrf": csrf, "identifier": "Alice@Example.com"}),
    )
    .await;
    assert_eq!(res.status(), 202);
    let mail = fx.email.last().expect("otp email");
    assert_eq!(mail.to[0].email, "alice@example.com");
    let code: String = mail
        .text
        .chars()
        .filter(|c| c.is_ascii_digit())
        .take(6)
        .collect();
    assert_eq!(code.len(), 6);

    // Wrong codes count attempts; a right code authenticates and verifies the email.
    let res = post(
        &fx,
        id,
        "email-otp/verify",
        json!({"csrf": csrf, "code": "000000"}),
    )
    .await;
    assert_eq!(res.status(), 401);
    assert_eq!(res.json::<Value>().await.unwrap()["error"], "invalid_code");
    let res = post(
        &fx,
        id,
        "email-otp/verify",
        json!({"csrf": csrf, "code": code}),
    )
    .await;
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    assert!(res.headers().get("set-cookie").is_some());
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["stage"], "done");
    let user = users::get(&fx.app.state, fx.app.tenant.id, fx.user_id)
        .await
        .unwrap();
    assert!(user.email_verified);
    // Single use.
    let (id2, csrf2, _) = start(&fx).await;
    assert_eq!(
        post(
            &fx,
            id2,
            "email-otp/verify",
            json!({"csrf": csrf2, "code": code})
        )
        .await
        .status(),
        401
    );
    // Disabled method is refused; send rate limit after 3 sends.
    assert_eq!(
        post(
            &fx,
            id2,
            "sms-otp",
            json!({"csrf": csrf2, "identifier": "alice"})
        )
        .await
        .status(),
        400
    );
    for _ in 0..2 {
        assert_eq!(
            post(
                &fx,
                id2,
                "email-otp",
                json!({"csrf": csrf2, "identifier": "alice"})
            )
            .await
            .status(),
            202
        );
    }
    // 1 send earlier + 2 here = 3 → the next is throttled.
    assert_eq!(
        post(
            &fx,
            id2,
            "email-otp",
            json!({"csrf": csrf2, "identifier": "alice"})
        )
        .await
        .status(),
        429
    );
}

#[tokio::test]
async fn otp_attempt_limit_invalidates_the_code() {
    let fx = fixture(AuthMethods {
        email_otp: true,
        ..Default::default()
    })
    .await;
    let (id, csrf, _) = start(&fx).await;
    post(
        &fx,
        id,
        "email-otp",
        json!({"csrf": csrf, "identifier": "alice"}),
    )
    .await;
    let code: String = fx
        .email
        .last()
        .unwrap()
        .text
        .chars()
        .filter(|c| c.is_ascii_digit())
        .take(6)
        .collect();
    for _ in 0..5 {
        post(
            &fx,
            id,
            "email-otp/verify",
            json!({"csrf": csrf, "code": "111111"}),
        )
        .await;
    }
    assert_eq!(
        post(
            &fx,
            id,
            "email-otp/verify",
            json!({"csrf": csrf, "code": code})
        )
        .await
        .status(),
        401,
        "code destroyed after 5 wrong attempts"
    );
}

#[tokio::test]
async fn magic_link_login_bound_to_the_flow() {
    let fx = fixture(AuthMethods {
        magic_link: true,
        password: false,
        ..Default::default()
    })
    .await;
    let (id, csrf, state) = start(&fx).await;
    assert_eq!(
        state["methods"],
        json!(["magic_link"]),
        "passwordless-only tenant"
    );
    // Password login is refused on a passwordless-only tenant.
    assert_eq!(
        post(
            &fx,
            id,
            "password",
            json!({"csrf": csrf, "identifier": "alice", "password": "x"})
        )
        .await
        .status(),
        400
    );

    assert_eq!(
        post(
            &fx,
            id,
            "magic-link",
            json!({"csrf": csrf, "identifier": "alice"})
        )
        .await
        .status(),
        202
    );
    let mail = fx.email.last().expect("magic link email");
    let link = mail
        .text
        .lines()
        .find(|l| l.contains("magic="))
        .unwrap()
        .trim();
    let url = url::Url::parse(link).unwrap();
    assert!(url.path().ends_with("/login/"));
    assert_eq!(
        url.query_pairs().find(|(k, _)| k == "flow").unwrap().1,
        id.to_string()
    );
    let token = url
        .query_pairs()
        .find(|(k, _)| k == "magic")
        .unwrap()
        .1
        .into_owned();

    // The token only works for its own flow.
    let (other, other_csrf, _) = start(&fx).await;
    assert_eq!(
        post(
            &fx,
            other,
            "magic-link/verify",
            json!({"csrf": other_csrf, "token": token})
        )
        .await
        .status(),
        401
    );
    // A wrong-flow attempt consumed it? No: GETDEL consumed the record. Request a fresh link.
    assert_eq!(
        post(
            &fx,
            id,
            "magic-link",
            json!({"csrf": csrf, "identifier": "alice"})
        )
        .await
        .status(),
        202
    );
    let link = fx
        .email
        .last()
        .unwrap()
        .text
        .lines()
        .find(|l| l.contains("magic="))
        .unwrap()
        .trim()
        .to_string();
    let token = url::Url::parse(&link)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "magic")
        .unwrap()
        .1
        .into_owned();
    let res = post(
        &fx,
        id,
        "magic-link/verify",
        json!({"csrf": csrf, "token": token}),
    )
    .await;
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["stage"], "done");
    // Second use fails.
    let (id3, csrf3, _) = start(&fx).await;
    assert_eq!(
        post(
            &fx,
            id3,
            "magic-link/verify",
            json!({"csrf": csrf3, "token": token})
        )
        .await
        .status(),
        401
    );
}

#[tokio::test]
async fn sms_otp_requires_a_verified_phone() {
    let fx = fixture(AuthMethods {
        sms_otp: true,
        ..Default::default()
    })
    .await;
    let bob = users::create(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        NewUser {
            username: "bob".into(),
            phone: Some("+15550002222".into()),
            phone_verified: false,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let _ = bob;
    let (id, csrf, _) = start(&fx).await;
    assert_eq!(
        post(
            &fx,
            id,
            "sms-otp",
            json!({"csrf": csrf, "identifier": "bob"})
        )
        .await
        .status(),
        202
    );
    assert!(fx.sms.sent().is_empty(), "unverified phone: nothing sent");
    assert_eq!(
        post(
            &fx,
            id,
            "sms-otp",
            json!({"csrf": csrf, "identifier": "alice"})
        )
        .await
        .status(),
        202
    );
    let text = fx.sms.last().unwrap().body;
    let code: String = text
        .split("code: ")
        .nth(1)
        .unwrap()
        .chars()
        .take(6)
        .collect();
    let res = post(
        &fx,
        id,
        "sms-otp/verify",
        json!({"csrf": csrf, "code": code}),
    )
    .await;
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["stage"], "done");
}
