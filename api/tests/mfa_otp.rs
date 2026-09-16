//! Phase 7.3: email and SMS one-time codes as second factors — enrolment
//! (a code proves the address or number), verification on later sign-ins,
//! the resend cooldown, the tenant's method toggles, and how the factors
//! count towards the MFA policy.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use common::TestApp;
use ridm_api::messaging::SenderFactory;
use ridm_api::models::{ClientType, MfaMethods, MfaPolicy, NewClient, NewUser, TenantSettings};
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::{clients, login_flows, sessions, totp, users};
use ridm_api::state::AppState;
use ridm_core::events::Actor;
use ridm_core::providers::{EmailSender, SmsSender};
use ridm_core::test_support::{MockEmailSender, MockSmsSender};
use serde_json::{Value, json};
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const PASSWORD: &str = "correct-horse-battery";

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
    settings: TenantSettings,
    email: Arc<MockEmailSender>,
    sms: Arc<MockSmsSender>,
    user_id: Uuid,
}

fn otp_methods() -> MfaMethods {
    MfaMethods {
        totp: false,
        email_otp: true,
        sms_otp: true,
    }
}

async fn fixture(mfa: MfaPolicy, mfa_methods: MfaMethods) -> Fx {
    let email = Arc::new(MockEmailSender::new());
    let sms = Arc::new(MockSmsSender::new());
    let (e2, s2) = (email.clone(), sms.clone());
    let app = TestApp::spawn_configured(axum::Router::new(), move |st| {
        st.senders = Arc::new(Mocks { email: e2, sms: s2 });
    })
    .await;
    let tid = app.tenant.id;
    let settings = TenantSettings {
        mfa,
        mfa_methods,
        ..Default::default()
    };
    tenants::update(
        &app.state,
        Actor::System,
        tid,
        TenantUpdate {
            settings: Some(settings.clone()),
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
        &settings.password,
        Actor::System,
        user.id,
        PASSWORD.to_string().into(),
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
            require_consent: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    Fx {
        app,
        settings,
        email,
        sms,
        user_id: user.id,
    }
}

/// Start a flow (`prompt=login`, so an SSO session never short-circuits it).
async fn start(fx: &Fx, extra: &[(&str, &str)]) -> (Uuid, String) {
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
    (id, state["csrf"].as_str().unwrap().to_string())
}

async fn step(fx: &Fx, id: Uuid, name: &str, mut body: Value, csrf: &str) -> reqwest::Response {
    body["csrf"] = json!(csrf);
    fx.app
        .http
        .post(fx.app.tenant_url(&format!("/flows/{id}/{name}")))
        .json(&body)
        .send()
        .await
        .unwrap()
}

/// Password step; returns the flow state after it.
async fn sign_in(fx: &Fx, id: Uuid, csrf: &str) -> Value {
    let res = step(
        fx,
        id,
        "password",
        json!({"identifier": "alice", "password": PASSWORD}),
        csrf,
    )
    .await;
    assert_eq!(res.status(), 200);
    res.json().await.unwrap()
}

fn six_digits(text: &str) -> String {
    let code: String = text
        .split("code")
        .nth(1)
        .unwrap_or(text)
        .chars()
        .filter(|c| c.is_ascii_digit())
        .take(6)
        .collect();
    assert_eq!(code.len(), 6, "no code in {text:?}");
    code
}

/// Emails carrying a code (the MFA-changed security notice is not one).
fn code_emails(fx: &Fx) -> usize {
    fx.email
        .sent()
        .iter()
        .filter(|m| m.subject.contains("code:"))
        .count()
}

fn last_email_code(fx: &Fx) -> String {
    let mail = fx.email.last().expect("an email");
    assert_eq!(mail.to[0].email, "alice@example.com");
    six_digits(&mail.text)
}

fn last_sms_code(fx: &Fx) -> (String, String) {
    let sms = fx.sms.last().expect("an sms");
    (sms.to.clone(), six_digits(&sms.body))
}

/// `(amr, acr)` of the session a finished flow opened.
async fn session_of(fx: &Fx, id: Uuid) -> (Vec<String>, Option<String>) {
    let flow = login_flows::get(&fx.app.state, fx.app.tenant.id, id)
        .await
        .unwrap()
        .unwrap();
    let s = sessions::get(
        &fx.app.state,
        fx.app.tenant.id,
        flow.session_id.unwrap(),
        &fx.settings.session,
    )
    .await
    .unwrap()
    .unwrap();
    (s.amr, s.acr)
}

#[tokio::test]
async fn email_codes_enrol_on_first_sign_in_and_verify_the_next_ones() {
    let fx = fixture(MfaPolicy::Required, otp_methods()).await;
    let (id, csrf) = start(&fx, &[]).await;
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["stage"], "mfa");
    assert_eq!(after["mfa"]["enroll"], true);
    assert_eq!(after["mfa"]["factors"], json!([]));
    assert_eq!(after["mfa"]["methods"], json!(["email_otp", "sms_otp"]));
    assert_eq!(after["mfa"]["phone"], Value::Null);

    // Authenticator apps are switched off for this tenant.
    let res = step(&fx, id, "mfa/totp/enroll", json!({}), &csrf).await;
    assert_eq!(res.status(), 400);
    // Nothing pending to confirm, nothing enrolled to send to.
    let res = step(
        &fx,
        id,
        "mfa/email/confirm",
        json!({"code": "000000"}),
        &csrf,
    )
    .await;
    assert_eq!(res.status(), 400);
    let res = step(&fx, id, "mfa/email/send", json!({}), &csrf).await;
    assert_eq!(res.status(), 400);

    let res = step(&fx, id, "mfa/email/enroll", json!({}), &csrf).await;
    assert_eq!(res.status(), 202, "{}", res.text().await.unwrap());
    let sent: Value = res.json().await.unwrap();
    assert_eq!(sent["sent"], true);
    assert_eq!(sent["destination"], "a•••@example.com");
    let code = last_email_code(&fx);
    assert_eq!(fx.email.sent().len(), 1);
    // Asking again right away (a re-rendered page) reuses the pending code.
    let res = step(&fx, id, "mfa/email/enroll", json!({}), &csrf).await;
    assert_eq!(res.status(), 202);
    assert_eq!(
        fx.email.sent().len(),
        1,
        "no second email inside the cooldown"
    );

    let wrong = format!("{:06}", (code.parse::<u32>().unwrap() + 1) % 1_000_000);
    let res = step(&fx, id, "mfa/email/confirm", json!({"code": wrong}), &csrf).await;
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_code");
    assert_eq!(body["attempts"], 1);

    let res = step(
        &fx,
        id,
        "mfa/email/confirm",
        json!({"code": code, "remember_device": false}),
        &csrf,
    )
    .await;
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["recovery_codes"].as_array().unwrap().len(),
        totp::RECOVERY_CODE_COUNT
    );
    assert_eq!(body["flow"]["stage"], "done");
    let (amr, acr) = session_of(&fx, id).await;
    assert_eq!(amr, vec!["pwd", "otp", "mfa"]);
    assert_eq!(acr.as_deref(), Some(ridm_api::services::flows::ACR_MFA));
    let user = users::get(&fx.app.state, fx.app.tenant.id, fx.user_id)
        .await
        .unwrap();
    assert!(user.email_verified, "the code proved the address");
    let factors = totp::factors_of(&fx.app.state, fx.app.tenant.id, fx.user_id)
        .await
        .unwrap();
    assert!(factors.email_otp && !factors.sms_otp && !factors.totp);
    // Enrolling the same channel twice is refused.
    let (id2, csrf2) = start(&fx, &[]).await;
    let after = sign_in(&fx, id2, &csrf2).await;
    assert_eq!(after["mfa"]["enroll"], false);
    assert_eq!(after["mfa"]["factors"], json!(["email_otp"]));
    assert_eq!(after["mfa"]["recovery_codes"], true);
    let res = step(&fx, id2, "mfa/email/enroll", json!({}), &csrf2).await;
    assert_eq!(res.status(), 400);

    // The next sign-in: a code must be sent before it can be verified.
    let res = step(
        &fx,
        id2,
        "mfa/email/verify",
        json!({"code": "000000"}),
        &csrf2,
    )
    .await;
    assert_eq!(res.status(), 401);
    let res = step(&fx, id2, "mfa/email/send", json!({}), &csrf2).await;
    assert_eq!(res.status(), 202);
    assert_eq!(code_emails(&fx), 2);
    let code = last_email_code(&fx);
    let res = step(&fx, id2, "mfa/email/verify", json!({"code": code}), &csrf2).await;
    assert_eq!(res.status(), 200);
    assert_eq!(res.json::<Value>().await.unwrap()["stage"], "done");
    assert_eq!(session_of(&fx, id2).await.0, vec!["pwd", "otp", "mfa"]);

    // A spent code does not work for another flow, and the recovery code
    // path still does.
    let (id3, csrf3) = start(&fx, &[]).await;
    sign_in(&fx, id3, &csrf3).await;
    let res = step(&fx, id3, "mfa/email/verify", json!({"code": code}), &csrf3).await;
    assert_eq!(res.status(), 401);
    let recovery = body["recovery_codes"][0].as_str().unwrap();
    let res = step(&fx, id3, "mfa/verify", json!({"code": recovery}), &csrf3).await;
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn sms_enrolment_proves_a_new_number_and_saves_it_verified() {
    let fx = fixture(MfaPolicy::Required, otp_methods()).await;
    let (id, csrf) = start(&fx, &[]).await;
    sign_in(&fx, id, &csrf).await;

    // No phone on the account: one is required, in E.164.
    let res = step(&fx, id, "mfa/sms/enroll", json!({}), &csrf).await;
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["errors"][0]["field"], "phone");
    let res = step(
        &fx,
        id,
        "mfa/sms/enroll",
        json!({"phone": "5550002222"}),
        &csrf,
    )
    .await;
    assert_eq!(res.status(), 400);
    assert!(fx.sms.sent().is_empty());

    let res = step(
        &fx,
        id,
        "mfa/sms/enroll",
        json!({"phone": "+1 555 000 2222"}),
        &csrf,
    )
    .await;
    assert_eq!(res.status(), 202, "{}", res.text().await.unwrap());
    assert_eq!(
        res.json::<Value>().await.unwrap()["destination"],
        "•••••••••22"
    );
    let (to, first) = last_sms_code(&fx);
    assert_eq!(to, "+15550002222");

    // Switching numbers discards the earlier code: it must not prove the new one.
    let res = step(
        &fx,
        id,
        "mfa/sms/enroll",
        json!({"phone": "+15550003333"}),
        &csrf,
    )
    .await;
    assert_eq!(res.status(), 202);
    let (to, second) = last_sms_code(&fx);
    assert_eq!(to, "+15550003333");
    assert_eq!(fx.sms.sent().len(), 2);
    let res = step(&fx, id, "mfa/sms/confirm", json!({"code": first}), &csrf).await;
    assert_eq!(res.status(), 401);
    let res = step(&fx, id, "mfa/sms/confirm", json!({"code": second}), &csrf).await;
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["flow"]["stage"], "done");
    assert_eq!(body["recovery_codes"].as_array().unwrap().len(), 10);
    assert_eq!(
        session_of(&fx, id).await.0,
        vec!["pwd", "otp", "sms", "mfa"]
    );
    let user = users::get(&fx.app.state, fx.app.tenant.id, fx.user_id)
        .await
        .unwrap();
    assert_eq!(user.phone.as_deref(), Some("+15550003333"));
    assert!(user.phone_verified);

    // Later sign-ins text the saved number.
    let (id2, csrf2) = start(&fx, &[]).await;
    let after = sign_in(&fx, id2, &csrf2).await;
    assert_eq!(after["mfa"]["factors"], json!(["sms_otp"]));
    assert_eq!(after["mfa"]["phone"], "•••••••••33");
    let res = step(&fx, id2, "mfa/sms/send", json!({}), &csrf2).await;
    assert_eq!(res.status(), 202);
    let (to, code) = last_sms_code(&fx);
    assert_eq!(to, "+15550003333");
    let res = step(&fx, id2, "mfa/sms/verify", json!({"code": code}), &csrf2).await;
    assert_eq!(res.status(), 200);
    assert_eq!(res.json::<Value>().await.unwrap()["stage"], "done");
    assert!(
        fx.email
            .sent()
            .iter()
            .all(|m| m.subject.contains("security")),
        "only the MFA-changed notice went by email: {:?}",
        fx.email
            .sent()
            .iter()
            .map(|m| m.subject.clone())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn the_tenant_decides_which_second_steps_are_offered() {
    let fx = fixture(MfaPolicy::Required, MfaMethods::default()).await;
    let (id, csrf) = start(&fx, &[]).await;
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["mfa"]["methods"], json!(["totp"]));
    for channel in ["email", "sms"] {
        let res = step(
            &fx,
            id,
            &format!("mfa/{channel}/enroll"),
            json!({"phone": "+15550002222"}),
            &csrf,
        )
        .await;
        assert_eq!(res.status(), 400, "{channel} is off");
    }
    assert!(fx.email.sent().is_empty() && fx.sms.sent().is_empty());
    // Nothing else changed: the authenticator app still enrols.
    let res = step(&fx, id, "mfa/totp/enroll", json!({}), &csrf).await;
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn an_otp_factor_counts_for_the_optional_policy() {
    let fx = fixture(MfaPolicy::Optional, otp_methods()).await;
    // Nobody asks a user without a factor...
    let (id, csrf) = start(&fx, &[]).await;
    assert_eq!(sign_in(&fx, id, &csrf).await["stage"], "done");
    // ...but a client step-up lets them enrol one.
    let (id, csrf) = start(&fx, &[("acr_values", "urn:ridm:acr:mfa")]).await;
    assert_eq!(sign_in(&fx, id, &csrf).await["stage"], "mfa");
    let res = step(&fx, id, "mfa/email/enroll", json!({}), &csrf).await;
    assert_eq!(res.status(), 202);
    let code = last_email_code(&fx);
    let res = step(&fx, id, "mfa/email/confirm", json!({"code": code}), &csrf).await;
    assert_eq!(res.status(), 200);
    // From then on every sign-in asks.
    let (id, csrf) = start(&fx, &[]).await;
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["stage"], "mfa");
    assert_eq!(after["mfa"]["enroll"], false);
    assert_eq!(after["mfa"]["factors"], json!(["email_otp"]));
}
