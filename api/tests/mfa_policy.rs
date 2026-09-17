//! Phase 7.4: the tenant MFA policy modes (`required_for_roles`,
//! `required_for_admins`), step-up by `acr_values` on a live session, and
//! the `amr`/`acr` claims tokens carry.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::TestApp;
use common::admin;
use ridm_api::models::{
    ClientType, MfaPolicy, NewClient, NewRole, NewUser, Principal, TenantSettings,
};
use ridm_api::services::admin_access::ADMIN_ROLE;
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::{clients, flows, roles, totp, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use totp_rs::{Algorithm, Builder, Secret};
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PASSWORD: &str = "correct-horse-battery";

struct Fx {
    app: TestApp,
    settings: TenantSettings,
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
    Fx { app, settings }
}

async fn user(fx: &Fx, username: &str) -> Uuid {
    let tid = fx.app.tenant.id;
    let user = users::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewUser {
            username: username.into(),
            email: Some(format!("{username}@example.com")),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    password::set_password(
        &fx.app.state,
        tid,
        &fx.settings.password,
        Actor::System,
        user.id,
        PASSWORD.to_string().into(),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();
    user.id
}

/// `GET /authorize` with a fresh cookie jar; returns the redirect target.
async fn authorize(http: &reqwest::Client, fx: &Fx, extra: &[(&str, &str)]) -> url::Url {
    let mut q = vec![
        ("response_type", "code"),
        ("client_id", "spa"),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", "openid profile"),
        ("state", "st"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];
    q.extend_from_slice(extra);
    let res = http
        .get(fx.app.tenant_url("/authorize"))
        .query(&q)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap()
}

fn param(u: &url::Url, k: &str) -> Option<String> {
    u.query_pairs()
        .find(|(a, _)| a == k)
        .map(|(_, v)| v.into_owned())
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap()
}

async fn get_flow(http: &reqwest::Client, fx: &Fx, id: Uuid) -> Value {
    http.get(fx.app.tenant_url(&format!("/flows/{id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn step(
    http: &reqwest::Client,
    fx: &Fx,
    id: Uuid,
    name: &str,
    mut body: Value,
    csrf: &str,
) -> Value {
    body["csrf"] = json!(csrf);
    let res = http
        .post(fx.app.tenant_url(&format!("/flows/{id}/{name}")))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{name}: {}", res.text().await.unwrap());
    res.json().await.unwrap()
}

/// Start a login flow and pass the password step; returns the flow id and state.
async fn password_login(
    http: &reqwest::Client,
    fx: &Fx,
    username: &str,
    extra: &[(&str, &str)],
) -> (Uuid, Value) {
    let loc = authorize(http, fx, extra).await;
    let id: Uuid = param(&loc, "flow").expect("a login flow").parse().unwrap();
    assert!(loc.path().ends_with("/login/"), "{loc}");
    let state = get_flow(http, fx, id).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let after = step(
        http,
        fx,
        id,
        "password",
        json!({"identifier": username, "password": PASSWORD}),
        &csrf,
    )
    .await;
    (id, after)
}

/// Follow a done flow's finish URL to the client's callback; returns the code.
async fn finish(http: &reqwest::Client, state: &Value) -> String {
    let res = http
        .get(state["finish_url"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    param(&loc, "code").expect("code on the callback")
}

/// Exchange a code; returns the ID token's claims.
async fn id_claims(fx: &Fx, code: &str) -> Value {
    let tokens: Value = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", "spa"),
            ("code", code),
            ("redirect_uri", "https://app.example/cb"),
            ("code_verifier", VERIFIER),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let idt = tokens["id_token"].as_str().expect("id_token");
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(idt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

fn code_for(secret_b32: &str) -> String {
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

/// Enrol an authenticator app in a flow waiting at the `mfa` stage; returns the state after.
async fn enrol_totp(http: &reqwest::Client, fx: &Fx, id: Uuid, csrf: &str) -> Value {
    let e = step(http, fx, id, "mfa/totp/enroll", json!({}), csrf).await;
    let secret = e["secret"].as_str().unwrap();
    let body = step(
        http,
        fx,
        id,
        "mfa/totp/confirm",
        json!({"code": code_for(secret)}),
        csrf,
    )
    .await;
    body["flow"].clone()
}

#[tokio::test]
async fn required_for_roles_asks_holders_of_a_listed_role_and_others_only_once_enrolled() {
    let fx = fixture(MfaPolicy::RequiredForRoles {
        roles: vec!["finance".into()],
    })
    .await;
    let tid = fx.app.tenant.id;
    let alice = user(&fx, "alice").await;
    let bob = user(&fx, "bob").await;
    let finance = roles::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewRole {
            name: "finance".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    roles::assign(
        &fx.app.state,
        tid,
        Actor::System,
        finance.id,
        Principal::User { id: alice },
    )
    .await
    .unwrap();

    let (_, after) = password_login(&client(), &fx, "alice", &[]).await;
    assert_eq!(after["stage"], "mfa", "role holder must enrol");
    assert_eq!(after["mfa"]["enroll"], true);

    let (_, after) = password_login(&client(), &fx, "bob", &[]).await;
    assert_eq!(after["stage"], "done", "not in the role, nothing enrolled");

    // A user outside the role who enrolled a factor is asked, as under `optional`.
    let tenant = tenants::get(&fx.app.state, tid).await.unwrap();
    let bob_user = users::get(&fx.app.state, tid, bob).await.unwrap();
    let scope = Uuid::now_v7();
    let e = totp::begin_enrolment(&fx.app.state, &tenant, scope, &bob_user)
        .await
        .unwrap();
    totp::confirm_enrolment(
        &fx.app.state,
        &tenant,
        scope,
        &bob_user,
        &code_for(&e.secret),
        None,
    )
    .await
    .unwrap()
    .unwrap();
    let (_, after) = password_login(&client(), &fx, "bob", &[]).await;
    assert_eq!(after["stage"], "mfa");
    assert_eq!(after["mfa"]["enroll"], false);
}

#[tokio::test]
async fn required_for_admins_asks_anyone_with_an_admin_permission() {
    let fx = fixture(MfaPolicy::RequiredForAdmins).await;
    let tid = fx.app.tenant.id;
    let alice = user(&fx, "alice").await;
    user(&fx, "bob").await;
    admin::assign(&fx.app, tid, alice, ADMIN_ROLE).await;

    let (_, after) = password_login(&client(), &fx, "alice", &[]).await;
    assert_eq!(after["stage"], "mfa", "an administrator must enrol");
    assert_eq!(after["mfa"]["enroll"], true);
    let (_, after) = password_login(&client(), &fx, "bob", &[]).await;
    assert_eq!(after["stage"], "done");
}

#[tokio::test]
async fn a_step_up_on_a_live_session_skips_the_password_and_tokens_say_how_the_user_signed_in() {
    let fx = fixture(MfaPolicy::Off).await;
    user(&fx, "alice").await;
    let http = client();

    // Plain sign-in: one factor, and the session says so.
    let (_, after) = password_login(&http, &fx, "alice", &[]).await;
    assert_eq!(after["stage"], "done");
    let claims = id_claims(&fx, &finish(&http, &after).await).await;
    assert_eq!(claims["amr"], json!(["pwd"]));
    assert_eq!(claims["acr"], flows::ACR_SINGLE, "{claims}");

    // The client asks for an MFA class: the live session goes straight to
    // the second factor (no password again), enrolling first.
    let loc = authorize(&http, &fx, &[("acr_values", "urn:ridm:acr:mfa")]).await;
    assert!(loc.path().ends_with("/mfa/"), "{loc}");
    let id: Uuid = param(&loc, "flow").unwrap().parse().unwrap();
    let state = get_flow(&http, &fx, id).await;
    assert_eq!(state["stage"], "mfa");
    assert_eq!(state["user"]["username"], "alice");
    assert_eq!(state["mfa"]["enroll"], true);
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let done = enrol_totp(&http, &fx, id, &csrf).await;
    assert_eq!(done["stage"], "done");
    let claims = id_claims(&fx, &finish(&http, &done).await).await;
    assert_eq!(claims["amr"], json!(["pwd", "otp", "mfa"]));
    assert_eq!(claims["acr"], "urn:ridm:acr:mfa");
    let auth_time = claims["auth_time"].as_i64().unwrap();

    // The session now satisfies that class: a code is issued at once.
    let loc = authorize(&http, &fx, &[("acr_values", "urn:ridm:acr:mfa")]).await;
    assert_eq!(loc.host_str(), Some("app.example"), "{loc}");
    let claims = id_claims(&fx, &param(&loc, "code").unwrap()).await;
    assert_eq!(claims["acr"], "urn:ridm:acr:mfa");
    assert_eq!(claims["auth_time"], auth_time, "no new authentication");

    // A class that is not an MFA class is voluntary: the session's own
    // class is what the token says, and nothing is asked.
    let loc = authorize(&http, &fx, &[("acr_values", "urn:example:acr:gold")]).await;
    assert_eq!(loc.host_str(), Some("app.example"), "{loc}");
    let claims = id_claims(&fx, &param(&loc, "code").unwrap()).await;
    assert_eq!(claims["acr"], "urn:ridm:acr:mfa");

    // Another MFA class is a new step-up; with `prompt=none` that is
    // `login_required`, otherwise the factor is verified again and the
    // session asserts the class the client named.
    let loc = authorize(
        &http,
        &fx,
        &[("acr_values", "urn:example:acr:mfa"), ("prompt", "none")],
    )
    .await;
    assert_eq!(param(&loc, "error").as_deref(), Some("login_required"));
    let loc = authorize(&http, &fx, &[("acr_values", "urn:example:acr:mfa")]).await;
    assert!(loc.path().ends_with("/mfa/"), "{loc}");
    let id: Uuid = param(&loc, "flow").unwrap().parse().unwrap();
    let state = get_flow(&http, &fx, id).await;
    assert_eq!(state["mfa"]["enroll"], false);
    assert_eq!(state["mfa"]["factors"], json!(["totp"]));

    // A session that is too old for `max_age` re-authenticates in full.
    let loc = authorize(
        &http,
        &fx,
        &[("acr_values", "urn:ridm:acr:mfa"), ("max_age", "0")],
    )
    .await;
    assert!(loc.path().ends_with("/login/"), "{loc}");
}

#[tokio::test]
async fn a_trusted_device_skips_the_policy_but_never_a_requested_step_up() {
    let fx = fixture(MfaPolicy::Required).await;
    user(&fx, "alice").await;
    let http = client();
    let (id, after) = password_login(&http, &fx, "alice", &[]).await;
    assert_eq!(after["stage"], "mfa");
    let csrf = after["csrf"].as_str().unwrap().to_string();
    let e = step(&http, &fx, id, "mfa/totp/enroll", json!({}), &csrf).await;
    let body = step(
        &http,
        &fx,
        id,
        "mfa/totp/confirm",
        json!({"code": code_for(e["secret"].as_str().unwrap()), "remember_device": true}),
        &csrf,
    )
    .await;
    // The device cookie is set by the finish step.
    finish(&http, &body["flow"]).await;

    // Trusted browser: the policy no longer asks, and the token says so.
    let (_, after) = password_login(&http, &fx, "alice", &[("prompt", "login")]).await;
    assert_eq!(after["stage"], "done");
    let claims = id_claims(&fx, &finish(&http, &after).await).await;
    assert_eq!(claims["amr"], json!(["pwd"]));
    assert_eq!(claims["acr"], flows::ACR_SINGLE, "{claims}");

    // A client step-up is still honoured on the trusted browser.
    let (_, after) = password_login(
        &http,
        &fx,
        "alice",
        &[("prompt", "login"), ("acr_values", "urn:ridm:acr:mfa")],
    )
    .await;
    assert_eq!(after["stage"], "mfa");
    assert_eq!(after["mfa"]["enroll"], false);
}

/// Enrol an authenticator app for `user_id` outside any flow (the account
/// API's path), so the next sign-in has a factor to verify.
async fn enrol_out_of_band(fx: &Fx, user_id: Uuid) {
    let tenant = tenants::get(&fx.app.state, fx.app.tenant.id).await.unwrap();
    let user = users::get(&fx.app.state, fx.app.tenant.id, user_id)
        .await
        .unwrap();
    let scope = Uuid::now_v7();
    let e = totp::begin_enrolment(&fx.app.state, &tenant, scope, &user)
        .await
        .unwrap();
    totp::confirm_enrolment(
        &fx.app.state,
        &tenant,
        scope,
        &user,
        &code_for(&e.secret),
        None,
    )
    .await
    .unwrap()
    .unwrap();
}

/// What the `mfa` stage looks like after the password step.
#[derive(Debug, PartialEq)]
enum Ask {
    Nothing,
    Enrol,
    Verify,
}

async fn asked(fx: &Fx, username: &str) -> Ask {
    let (_, after) = password_login(&client(), fx, username, &[]).await;
    match (after["stage"].as_str(), after["mfa"]["enroll"].as_bool()) {
        (Some("mfa"), Some(true)) => Ask::Enrol,
        (Some("mfa"), Some(false)) => Ask::Verify,
        _ => Ask::Nothing,
    }
}

/// Every policy mode against the same four users: nobody special, someone
/// who enrolled a factor, a role holder, an administrator.
#[tokio::test]
async fn the_policy_matrix() {
    use Ask::{Enrol, Nothing, Verify};
    let modes: Vec<(MfaPolicy, [Ask; 4])> = vec![
        (MfaPolicy::Off, [Nothing, Nothing, Nothing, Nothing]),
        (MfaPolicy::Optional, [Nothing, Verify, Nothing, Nothing]),
        (MfaPolicy::Required, [Enrol, Verify, Enrol, Enrol]),
        (
            MfaPolicy::RequiredForRoles {
                roles: vec!["finance".into()],
            },
            [Nothing, Verify, Enrol, Nothing],
        ),
        (
            MfaPolicy::RequiredForAdmins,
            [Nothing, Verify, Nothing, Enrol],
        ),
    ];
    for (mode, expected) in modes {
        let fx = fixture(mode.clone()).await;
        let tid = fx.app.tenant.id;
        let plain = user(&fx, "plain").await;
        let enrolled = user(&fx, "enrolled").await;
        let holder = user(&fx, "holder").await;
        let admin_user = user(&fx, "boss").await;
        let _ = plain;
        enrol_out_of_band(&fx, enrolled).await;
        let finance = roles::create(
            &fx.app.state,
            tid,
            Actor::System,
            NewRole {
                name: "finance".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        roles::assign(
            &fx.app.state,
            tid,
            Actor::System,
            finance.id,
            Principal::User { id: holder },
        )
        .await
        .unwrap();
        admin::assign(&fx.app, tid, admin_user, ADMIN_ROLE).await;
        let got = [
            asked(&fx, "plain").await,
            asked(&fx, "enrolled").await,
            asked(&fx, "holder").await,
            asked(&fx, "boss").await,
        ];
        assert_eq!(got, expected, "mode {mode:?}");
    }
}
