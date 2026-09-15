//! Phase 7.1: TOTP enrolment and verification in the login flow, recovery
//! codes, replay and attempt limits, and the tenant policy modes that decide
//! whether the second factor is asked for.

mod common;

use common::TestApp;
use ridm_api::models::{ClientType, MfaPolicy, NewClient, NewUser, TenantSettings};
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::{clients, login_flows, sessions, totp, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use totp_rs::{Algorithm, Builder, Secret};
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const PASSWORD: &str = "correct-horse-battery";

struct Fx {
    app: TestApp,
    settings: TenantSettings,
    user_id: Uuid,
}

async fn fixture(mfa: MfaPolicy) -> Fx {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let settings = TenantSettings {
        mfa,
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
        user_id: user.id,
    }
}

/// Start a flow (`prompt=login`, so an SSO session never short-circuits it).
async fn start(fx: &Fx, extra: &[(&str, &str)]) -> (Uuid, Value) {
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
    (id, get_flow(fx, id).await)
}

async fn get_flow(fx: &Fx, id: Uuid) -> Value {
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

/// Password step; returns the flow state after it.
async fn sign_in(fx: &Fx, id: Uuid, csrf: &str) -> Value {
    let res = step(
        fx,
        id,
        "password",
        json!({"csrf": csrf, "identifier": "alice", "password": PASSWORD}),
    )
    .await;
    assert_eq!(res.status(), 200);
    res.json().await.unwrap()
}

fn code_for(secret_b32: &str, at: u64) -> String {
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
        .generate(at)
        .to_string()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Sign in and enrol through the flow; returns the secret, the time the
/// proof code was computed for, and the recovery codes.
async fn enrol(fx: &Fx) -> (String, u64, Vec<String>) {
    let (id, state) = start(fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let after = sign_in(fx, id, &csrf).await;
    assert_eq!(after["stage"], "mfa");
    assert_eq!(after["mfa"]["enroll"], true);
    let res = step(fx, id, "mfa/totp/enroll", json!({"csrf": csrf})).await;
    assert_eq!(res.status(), 200);
    let enrolment: Value = res.json().await.unwrap();
    let secret = enrolment["secret"].as_str().unwrap().to_string();
    let at = now();
    let code = code_for(&secret, at);
    let res = step(
        fx,
        id,
        "mfa/totp/confirm",
        json!({"csrf": csrf, "code": code, "label": "Phone"}),
    )
    .await;
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let body: Value = res.json().await.unwrap();
    let codes: Vec<String> = body["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert_eq!(body["flow"]["stage"], "done");
    (secret, at, codes)
}

#[tokio::test]
async fn required_policy_enrols_on_first_sign_in_and_marks_the_session() {
    let fx = fixture(MfaPolicy::Required).await;
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["stage"], "mfa");
    assert_eq!(after["mfa"]["enroll"], true);
    assert_eq!(after["mfa"]["factors"], json!([]));
    assert_eq!(after["mfa"]["recovery_codes"], false);
    assert_eq!(after["user"]["username"], "alice");

    // Nothing to verify against yet, and no enrolment to confirm.
    let res = step(
        &fx,
        id,
        "mfa/totp/confirm",
        json!({"csrf": csrf, "code": "000000"}),
    )
    .await;
    assert_eq!(res.status(), 400);

    let res = step(&fx, id, "mfa/totp/enroll", json!({"csrf": csrf})).await;
    assert_eq!(res.status(), 200);
    let enrolment: Value = res.json().await.unwrap();
    let secret = enrolment["secret"].as_str().unwrap().to_string();
    let uri = enrolment["otpauth_uri"].as_str().unwrap();
    assert!(uri.starts_with("otpauth://totp/"), "{uri}");
    assert!(uri.contains("alice%40example.com"), "{uri}");
    assert!(uri.contains(&format!("secret={secret}")), "{uri}");
    assert_eq!(enrolment["digits"], 6);
    assert_eq!(enrolment["period"], 30);
    // Asking again keeps the same secret while the enrolment is pending.
    let res = step(&fx, id, "mfa/totp/enroll", json!({"csrf": csrf})).await;
    assert_eq!(res.json::<Value>().await.unwrap()["secret"], secret);

    // A wrong proof keeps the enrolment pending and counts an attempt.
    let good = code_for(&secret, now());
    let wrong = format!("{:06}", (good.parse::<u32>().unwrap() + 1) % 1_000_000);
    let res = step(
        &fx,
        id,
        "mfa/totp/confirm",
        json!({"csrf": csrf, "code": wrong}),
    )
    .await;
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_code");
    assert_eq!(body["attempts"], 1);
    assert_eq!(get_flow(&fx, id).await["stage"], "mfa");

    let res = step(
        &fx,
        id,
        "mfa/totp/confirm",
        json!({"csrf": csrf, "code": good, "remember_device": false}),
    )
    .await;
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let codes = body["recovery_codes"].as_array().unwrap();
    assert_eq!(codes.len(), totp::RECOVERY_CODE_COUNT);
    for c in codes {
        let c = c.as_str().unwrap();
        assert_eq!(c.len(), 11);
        assert_eq!(&c[5..6], "-");
    }
    assert_eq!(body["flow"]["stage"], "done");
    assert!(
        body["flow"]["finish_url"]
            .as_str()
            .unwrap()
            .ends_with("/finish")
    );

    // The session now carries the second factor.
    let flow = login_flows::get(&fx.app.state, fx.app.tenant.id, id)
        .await
        .unwrap()
        .unwrap();
    let session = sessions::get(
        &fx.app.state,
        fx.app.tenant.id,
        flow.session_id.unwrap(),
        &fx.settings.session,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(session.amr, vec!["pwd", "otp", "mfa"]);
    assert_eq!(
        session.acr.as_deref(),
        Some(ridm_api::services::flows::ACR_MFA)
    );
    let factors = totp::factors_of(&fx.app.state, fx.app.tenant.id, fx.user_id)
        .await
        .unwrap();
    assert!(factors.totp);
    assert_eq!(factors.recovery_codes, totp::RECOVERY_CODE_COUNT);

    // Enrolling again is refused once a factor exists.
    let (id2, state) = start(&fx, &[]).await;
    let csrf2 = state["csrf"].as_str().unwrap().to_string();
    let after = sign_in(&fx, id2, &csrf2).await;
    assert_eq!(after["stage"], "mfa");
    assert_eq!(after["mfa"]["enroll"], false);
    assert_eq!(after["mfa"]["factors"], json!(["totp"]));
    assert_eq!(after["mfa"]["recovery_codes"], true);
    let res = step(&fx, id2, "mfa/totp/enroll", json!({"csrf": csrf2})).await;
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn later_sign_ins_verify_with_the_app_within_the_drift_window_and_never_twice() {
    let fx = fixture(MfaPolicy::Required).await;
    let (secret, at, _) = enrol(&fx).await;

    // The code that proved the enrolment is spent; the next step's is fine
    // (one step of drift is accepted either side).
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    assert_eq!(sign_in(&fx, id, &csrf).await["stage"], "mfa");
    let spent = code_for(&secret, at);
    let res = step(&fx, id, "mfa/verify", json!({"csrf": csrf, "code": spent})).await;
    assert_eq!(res.status(), 401);
    let next = code_for(&secret, at + 30);
    let res = step(
        &fx,
        id,
        "mfa/verify",
        json!({"csrf": csrf, "code": next, "remember_device": true}),
    )
    .await;
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["stage"], "done");
    assert!(body.get("recovery_codes").is_none());
    let flow = login_flows::get(&fx.app.state, fx.app.tenant.id, id)
        .await
        .unwrap()
        .unwrap();
    assert!(flow.remember_device, "device trust is registered at finish");
    assert_eq!(flow.amr, vec!["pwd", "otp", "mfa"]);

    // Replaying that code in another sign-in fails; two steps out is too far.
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    sign_in(&fx, id, &csrf).await;
    let res = step(&fx, id, "mfa/verify", json!({"csrf": csrf, "code": next})).await;
    assert_eq!(res.status(), 401);
    let far = code_for(&secret, at + 90);
    let res = step(&fx, id, "mfa/verify", json!({"csrf": csrf, "code": far})).await;
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["attempts"], 2);
}

#[tokio::test]
async fn recovery_codes_work_once_each_in_any_spelling() {
    let fx = fixture(MfaPolicy::Required).await;
    let (_, _, codes) = enrol(&fx).await;

    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    sign_in(&fx, id, &csrf).await;
    let spelled = format!(" {} ", codes[0].to_uppercase().replace('-', ""));
    let res = step(
        &fx,
        id,
        "mfa/verify",
        json!({"csrf": csrf, "code": spelled}),
    )
    .await;
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["stage"], "done");
    let flow = login_flows::get(&fx.app.state, fx.app.tenant.id, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(flow.amr, vec!["pwd", "mfa"], "a recovery code is not `otp`");

    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["mfa"]["recovery_codes"], true);
    let res = step(
        &fx,
        id,
        "mfa/verify",
        json!({"csrf": csrf, "code": codes[0]}),
    )
    .await;
    assert_eq!(res.status(), 401, "a used code is dead");
    let res = step(
        &fx,
        id,
        "mfa/verify",
        json!({"csrf": csrf, "code": "nope-nope"}),
    )
    .await;
    assert_eq!(res.status(), 401);
    let res = step(
        &fx,
        id,
        "mfa/verify",
        json!({"csrf": csrf, "code": codes[1]}),
    )
    .await;
    assert_eq!(res.status(), 200);
    let factors = totp::factors_of(&fx.app.state, fx.app.tenant.id, fx.user_id)
        .await
        .unwrap();
    assert_eq!(factors.recovery_codes, totp::RECOVERY_CODE_COUNT - 2);

    // A fresh set replaces the old one entirely.
    let fresh = totp::regenerate_recovery_codes(&fx.app.state, fx.app.tenant.id, fx.user_id)
        .await
        .unwrap();
    assert_eq!(fresh.len(), totp::RECOVERY_CODE_COUNT);
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    sign_in(&fx, id, &csrf).await;
    let res = step(
        &fx,
        id,
        "mfa/verify",
        json!({"csrf": csrf, "code": codes[2]}),
    )
    .await;
    assert_eq!(res.status(), 401);
    let res = step(
        &fx,
        id,
        "mfa/verify",
        json!({"csrf": csrf, "code": fresh[0]}),
    )
    .await;
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn too_many_wrong_codes_discard_the_flow() {
    let fx = fixture(MfaPolicy::Required).await;
    enrol(&fx).await;
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    sign_in(&fx, id, &csrf).await;
    for n in 1..=ridm_api::services::flows::MFA_MAX_ATTEMPTS {
        let res = step(
            &fx,
            id,
            "mfa/verify",
            json!({"csrf": csrf, "code": "bad-code-99"}),
        )
        .await;
        assert_eq!(res.status(), 401);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["attempts"], n);
    }
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url(&format!("/flows/{id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404, "the flow is gone");
}

#[tokio::test]
async fn optional_policy_asks_only_users_who_enrolled() {
    let fx = fixture(MfaPolicy::Optional).await;
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["stage"], "done", "nothing enrolled: no second factor");
    assert!(after["mfa"].is_null());

    // Enrol out of band (the account API arrives with Phase 8; the service
    // is what it will call), then the next sign-in asks.
    let tenant = tenants::get(&fx.app.state, fx.app.tenant.id).await.unwrap();
    let user = users::get(&fx.app.state, fx.app.tenant.id, fx.user_id)
        .await
        .unwrap();
    let scope = Uuid::now_v7();
    let e = totp::begin_enrolment(&fx.app.state, &tenant, scope, &user)
        .await
        .unwrap();
    let codes = totp::confirm_enrolment(
        &fx.app.state,
        &tenant,
        scope,
        &user,
        &code_for(&e.secret, now()),
        None,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(codes.len(), totp::RECOVERY_CODE_COUNT);

    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["stage"], "mfa");
    assert_eq!(after["mfa"]["factors"], json!(["totp"]));
    let res = step(
        &fx,
        id,
        "mfa/verify",
        json!({"csrf": csrf, "code": code_for(&e.secret, now() + 30)}),
    )
    .await;
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn a_client_step_up_asks_even_when_the_policy_is_off() {
    let fx = fixture(MfaPolicy::Off).await;
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    assert_eq!(sign_in(&fx, id, &csrf).await["stage"], "done");

    let (id, state) = start(&fx, &[("acr_values", "urn:example:acr:mfa")]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["stage"], "mfa");
    assert_eq!(after["mfa"]["enroll"], true);
    let res = step(&fx, id, "mfa/totp/enroll", json!({"csrf": csrf})).await;
    let secret = res.json::<Value>().await.unwrap()["secret"]
        .as_str()
        .unwrap()
        .to_string();
    let res = step(
        &fx,
        id,
        "mfa/totp/confirm",
        json!({"csrf": csrf, "code": code_for(&secret, now())}),
    )
    .await;
    assert_eq!(res.status(), 200);
    let flow = login_flows::get(&fx.app.state, fx.app.tenant.id, id)
        .await
        .unwrap()
        .unwrap();
    let session = sessions::get(
        &fx.app.state,
        fx.app.tenant.id,
        flow.session_id.unwrap(),
        &fx.settings.session,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        session.acr.as_deref(),
        Some("urn:example:acr:mfa"),
        "the requested class is what the session asserts"
    );

    // The next plain sign-in does not ask: the policy is off.
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    assert_eq!(sign_in(&fx, id, &csrf).await["stage"], "done");
}
