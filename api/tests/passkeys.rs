//! Phase 7.2: passkeys (WebAuthn) in the login flow, driven by a software
//! authenticator: enrolment as a second factor, assertion as a second factor,
//! and passwordless sign-in with a discoverable credential.

mod common;

use std::sync::Arc;

use common::TestApp;
use ridm_api::models::{ClientType, MfaPolicy, NewClient, NewUser, TenantSettings};
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::{clients, login_flows, passkeys, sessions, totp, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;
use webauthn_authenticator_rs::AuthenticatorBackend as _;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{
    Base64UrlSafeData, CreationChallengeResponse, PublicKeyCredential, RequestChallengeResponse,
    Url,
};

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const PASSWORD: &str = "correct-horse-battery";

struct Fx {
    app: TestApp,
    settings: TenantSettings,
    user_id: Uuid,
    /// The origin the browser would report: the UI host.
    origin: Url,
}

async fn fixture(mfa: MfaPolicy, passkey: bool) -> Fx {
    // WebAuthn needs a domain, not the harness's `127.0.0.1`: the UI is
    // served from `localhost` on the same port.
    let app = TestApp::spawn_configured(axum::Router::new(), |state| {
        let mut config = (*state.config).clone();
        let port = config.public_url.port().expect("port");
        config.ui_url = format!("http://localhost:{port}").parse().expect("ui url");
        state.config = Arc::new(config);
    })
    .await;
    let origin = app.state.config.ui_url.clone();
    let tid = app.tenant.id;
    let mut settings = TenantSettings {
        mfa,
        ..Default::default()
    };
    settings.auth.passkey = passkey;
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
        origin,
    }
}

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

async fn session_of(fx: &Fx, flow_id: Uuid) -> sessions::SsoSession {
    let flow = login_flows::get(&fx.app.state, fx.app.tenant.id, flow_id)
        .await
        .unwrap()
        .unwrap();
    sessions::get(
        &fx.app.state,
        fx.app.tenant.id,
        flow.session_id.unwrap(),
        &fx.settings.session,
    )
    .await
    .unwrap()
    .unwrap()
}

#[tokio::test]
async fn a_passkey_enrols_as_the_second_factor_and_verifies_later_sign_ins() {
    let fx = fixture(MfaPolicy::Required, true).await;
    let mut auth = SoftPasskey::new(true);

    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["stage"], "mfa");
    assert_eq!(after["mfa"]["enroll"], true);
    assert!(
        after["methods"]
            .as_array()
            .unwrap()
            .contains(&json!("passkey"))
    );

    // Nothing to assert against yet, and no ceremony to finish.
    let res = step(&fx, id, "mfa/passkey/start", json!({"csrf": csrf})).await;
    assert_eq!(res.status(), 400);
    let res = step(&fx, id, "mfa/passkey/register", json!({"csrf": csrf})).await;
    assert_eq!(res.status(), 200);
    let options: CreationChallengeResponse = res.json().await.unwrap();
    assert_eq!(options.public_key.rp.id, "localhost");
    assert_eq!(options.public_key.user.name, "alice@example.com");
    assert_eq!(
        Uuid::from_slice(options.public_key.user.id.as_ref()).unwrap(),
        fx.user_id,
        "the user handle is the user id"
    );
    assert!(options.public_key.exclude_credentials.is_none());
    let credential = auth
        .perform_register(fx.origin.clone(), options.public_key, 60_000)
        .unwrap();

    // An answer to a ceremony that was started again is refused: the
    // challenge it signed is gone.
    let res = step(&fx, id, "mfa/passkey/register", json!({"csrf": csrf})).await;
    assert_eq!(res.status(), 200);
    let res = step(
        &fx,
        id,
        "mfa/passkey/register/finish",
        json!({"csrf": csrf, "credential": credential, "label": "Old"}),
    )
    .await;
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_passkey");
    assert_eq!(body["attempts"], 1);
    // ... and a refused answer spends the ceremony.
    let res = step(
        &fx,
        id,
        "mfa/passkey/register/finish",
        json!({"csrf": csrf, "credential": credential}),
    )
    .await;
    assert_eq!(res.status(), 400);

    let res = step(&fx, id, "mfa/passkey/register", json!({"csrf": csrf})).await;
    let options: CreationChallengeResponse = res.json().await.unwrap();
    let credential = auth
        .perform_register(fx.origin.clone(), options.public_key, 60_000)
        .unwrap();
    let res = step(
        &fx,
        id,
        "mfa/passkey/register/finish",
        json!({"csrf": csrf, "credential": credential, "label": "Security key", "remember_device": true}),
    )
    .await;
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["recovery_codes"].as_array().unwrap().len(),
        totp::RECOVERY_CODE_COUNT,
        "the first second factor comes with recovery codes"
    );
    assert_eq!(body["flow"]["stage"], "done");
    let session = session_of(&fx, id).await;
    assert_eq!(session.amr, vec!["pwd", "hwk", "user", "mfa"]);
    assert_eq!(
        session.acr.as_deref(),
        Some(ridm_api::services::flows::ACR_MFA)
    );
    let factors = totp::factors_of(&fx.app.state, fx.app.tenant.id, fx.user_id)
        .await
        .unwrap();
    assert!(factors.webauthn && !factors.totp);
    assert!(
        passkeys::has_passkey(&fx.app.state, fx.app.tenant.id, fx.user_id)
            .await
            .unwrap()
    );

    // The next sign-in asserts with the passkey.
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["stage"], "mfa");
    assert_eq!(after["mfa"]["enroll"], false);
    assert_eq!(after["mfa"]["factors"], json!(["webauthn"]));
    assert_eq!(after["mfa"]["recovery_codes"], true);
    let res = step(&fx, id, "mfa/passkey/start", json!({"csrf": csrf})).await;
    assert_eq!(res.status(), 200);
    let options: RequestChallengeResponse = res.json().await.unwrap();
    assert_eq!(options.public_key.allow_credentials.len(), 1);
    assert_eq!(options.public_key.rp_id, "localhost");
    let assertion = auth
        .perform_auth(fx.origin.clone(), options.public_key, 60_000)
        .unwrap();
    let res = step(
        &fx,
        id,
        "mfa/passkey/finish",
        json!({"csrf": csrf, "credential": assertion}),
    )
    .await;
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["stage"], "done");
    assert!(body.get("recovery_codes").is_none(), "codes exist already");
    assert_eq!(
        session_of(&fx, id).await.amr,
        vec!["pwd", "hwk", "user", "mfa"]
    );

    // Replaying that assertion against a fresh challenge fails.
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    sign_in(&fx, id, &csrf).await;
    let res = step(&fx, id, "mfa/passkey/start", json!({"csrf": csrf})).await;
    assert_eq!(res.status(), 200);
    let res = step(
        &fx,
        id,
        "mfa/passkey/finish",
        json!({"csrf": csrf, "credential": assertion}),
    )
    .await;
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_passkey");
    assert_eq!(body["attempts"], 1);
    // A second passkey is offered with the first one excluded.
    let res = step(&fx, id, "mfa/passkey/register", json!({"csrf": csrf})).await;
    let options: CreationChallengeResponse = res.json().await.unwrap();
    assert_eq!(
        options
            .public_key
            .exclude_credentials
            .as_ref()
            .map(Vec::len),
        Some(1)
    );
    let credential = auth
        .perform_register(fx.origin.clone(), options.public_key, 60_000)
        .unwrap();
    let res = step(
        &fx,
        id,
        "mfa/passkey/register/finish",
        json!({"csrf": csrf, "credential": credential, "label": "Phone"}),
    )
    .await;
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["stage"], "done",
        "no wrapper: codes were issued before"
    );
    let creds = {
        let mut tx = ridm_api::db::tenant_tx(&fx.app.state.db, fx.app.tenant.id)
            .await
            .unwrap();
        let rows =
            ridm_api::repos::credentials::list_for_user(&mut *tx, fx.app.tenant.id, fx.user_id)
                .await
                .unwrap();
        tx.commit().await.unwrap();
        rows
    };
    let mut labels: Vec<_> = creds
        .iter()
        .filter(|c| c.kind == passkeys::KIND)
        .map(|c| c.label.clone().unwrap())
        .collect();
    labels.sort();
    assert_eq!(labels, vec!["Phone", "Security key"]);
    assert!(
        creds
            .iter()
            .find(|c| c.label.as_deref() == Some("Security key"))
            .unwrap()
            .last_used_at
            .is_some()
    );
}

#[tokio::test]
async fn a_discoverable_passkey_signs_in_without_a_password() {
    let fx = fixture(MfaPolicy::Off, true).await;
    let mut auth = SoftPasskey::new(true);
    let tenant = tenants::get(&fx.app.state, fx.app.tenant.id).await.unwrap();
    let user = users::get(&fx.app.state, fx.app.tenant.id, fx.user_id)
        .await
        .unwrap();

    // Enrol out of band (what the account API will call in Phase 8).
    let scope = Uuid::now_v7();
    let options = passkeys::begin_registration(&fx.app.state, &tenant, scope, &user)
        .await
        .unwrap();
    let credential = auth
        .perform_register(fx.origin.clone(), options.public_key, 60_000)
        .unwrap();
    let cred_id = credential.id.clone();
    let stored = passkeys::finish_registration(
        &fx.app.state,
        &tenant,
        scope,
        &user,
        &credential,
        Some("Laptop"),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(stored.kind, "webauthn");
    assert_eq!(stored.label.as_deref(), Some("Laptop"));

    // The software authenticator has no resident-key store: the test hands
    // it the credential id and adds the user handle a discoverable
    // credential would carry.
    let assert_with = |mut options: Value, handle: Uuid, auth: &mut SoftPasskey| {
        options["publicKey"]["allowCredentials"] = json!([{"type": "public-key", "id": cred_id}]);
        let options: RequestChallengeResponse = serde_json::from_value(options).unwrap();
        let mut assertion: PublicKeyCredential = auth
            .perform_auth(fx.origin.clone(), options.public_key, 60_000)
            .unwrap();
        assertion.response.user_handle = Some(Base64UrlSafeData::from(handle.as_bytes().to_vec()));
        assertion
    };

    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    assert!(
        state["methods"]
            .as_array()
            .unwrap()
            .contains(&json!("passkey"))
    );
    let res = step(&fx, id, "passkey/finish", json!({"csrf": csrf, "credential": {"id": "AA", "rawId": "AA", "type": "public-key", "response": {"authenticatorData": "AA", "clientDataJSON": "AA", "signature": "AA", "userHandle": null}}})).await;
    assert_eq!(res.status(), 400, "no ceremony pending");
    let res = step(&fx, id, "passkey/start", json!({"csrf": csrf})).await;
    assert_eq!(res.status(), 200);
    let options: Value = res.json().await.unwrap();
    assert_eq!(options["publicKey"]["allowCredentials"], json!([]));
    assert_eq!(options["publicKey"]["userVerification"], "required");
    assert!(options.get("mediation").is_none(), "a button, not autofill");

    // A user handle that is not the key's owner is refused.
    let assertion = assert_with(options.clone(), Uuid::now_v7(), &mut auth);
    let res = step(
        &fx,
        id,
        "passkey/finish",
        json!({"csrf": csrf, "credential": assertion, "remember_device": true}),
    )
    .await;
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_passkey");
    assert_eq!(body["attempts"], 1);
    assert_eq!(get_flow(&fx, id).await["stage"], "authenticate");

    let res = step(&fx, id, "passkey/start", json!({"csrf": csrf})).await;
    let options: Value = res.json().await.unwrap();
    let assertion = assert_with(options, fx.user_id, &mut auth);
    let res = step(
        &fx,
        id,
        "passkey/finish",
        json!({"csrf": csrf, "credential": assertion, "remember_device": true}),
    )
    .await;
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    assert!(
        res.headers()
            .get_all("set-cookie")
            .iter()
            .any(|c| c.to_str().unwrap().contains("ridm_")),
        "a session cookie is set"
    );
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["stage"], "done");
    assert_eq!(body["user"]["username"], "alice");
    let session = session_of(&fx, id).await;
    assert_eq!(session.amr, vec!["hwk", "user", "mfa"]);
    assert_eq!(
        session.acr.as_deref(),
        Some(ridm_api::services::flows::ACR_MFA)
    );
    let flow = login_flows::get(&fx.app.state, fx.app.tenant.id, id)
        .await
        .unwrap()
        .unwrap();
    assert!(flow.remember_device);

    // With MFA required, a verified passkey already is two factors: no
    // second step, and a client step-up is satisfied too.
    let mut settings = fx.settings.clone();
    settings.mfa = MfaPolicy::Required;
    tenants::update(
        &fx.app.state,
        Actor::System,
        fx.app.tenant.id,
        TenantUpdate {
            settings: Some(settings),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (id, state) = start(&fx, &[("acr_values", "urn:example:acr:mfa")]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let res = step(&fx, id, "passkey/start", json!({"csrf": csrf})).await;
    let options: Value = res.json().await.unwrap();
    let assertion = assert_with(options, fx.user_id, &mut auth);
    let res = step(
        &fx,
        id,
        "passkey/finish",
        json!({"csrf": csrf, "credential": assertion}),
    )
    .await;
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["stage"], "done");
    assert_eq!(
        session_of(&fx, id).await.acr.as_deref(),
        Some("urn:example:acr:mfa")
    );
    // The password path still asks for the second step, answered by the same key.
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["stage"], "mfa");
    assert_eq!(after["mfa"]["factors"], json!(["webauthn"]));
    assert_eq!(after["mfa"]["recovery_codes"], false, "none issued yet");
    let res = step(&fx, id, "mfa/passkey/start", json!({"csrf": csrf})).await;
    let options: RequestChallengeResponse = res.json().await.unwrap();
    let assertion = auth
        .perform_auth(fx.origin.clone(), options.public_key, 60_000)
        .unwrap();
    let res = step(
        &fx,
        id,
        "mfa/passkey/finish",
        json!({"csrf": csrf, "credential": assertion}),
    )
    .await;
    assert_eq!(res.status(), 200);
    assert_eq!(res.json::<Value>().await.unwrap()["stage"], "done");
}

#[tokio::test]
async fn passkeys_are_only_offered_when_the_tenant_enables_them() {
    let fx = fixture(MfaPolicy::Required, false).await;
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    assert!(
        !state["methods"]
            .as_array()
            .unwrap()
            .contains(&json!("passkey"))
    );
    let res = step(&fx, id, "passkey/start", json!({"csrf": csrf})).await;
    assert_eq!(res.status(), 400);
    let after = sign_in(&fx, id, &csrf).await;
    assert_eq!(after["stage"], "mfa");
    let res = step(&fx, id, "mfa/passkey/register", json!({"csrf": csrf})).await;
    assert_eq!(res.status(), 400);
    // A passkey enrolled while the option was on still verifies.
    let tenant = tenants::get(&fx.app.state, fx.app.tenant.id).await.unwrap();
    let user = users::get(&fx.app.state, fx.app.tenant.id, fx.user_id)
        .await
        .unwrap();
    let mut auth = SoftPasskey::new(true);
    let scope = Uuid::now_v7();
    let options = passkeys::begin_registration(&fx.app.state, &tenant, scope, &user)
        .await
        .unwrap();
    let credential = auth
        .perform_register(fx.origin.clone(), options.public_key, 60_000)
        .unwrap();
    passkeys::finish_registration(&fx.app.state, &tenant, scope, &user, &credential, None)
        .await
        .unwrap()
        .unwrap();
    let res = step(&fx, id, "mfa/passkey/start", json!({"csrf": csrf})).await;
    assert_eq!(res.status(), 200);
    let options: RequestChallengeResponse = res.json().await.unwrap();
    let assertion = auth
        .perform_auth(fx.origin.clone(), options.public_key, 60_000)
        .unwrap();
    let res = step(
        &fx,
        id,
        "mfa/passkey/finish",
        json!({"csrf": csrf, "credential": assertion}),
    )
    .await;
    assert_eq!(res.status(), 200);
    assert_eq!(res.json::<Value>().await.unwrap()["stage"], "done");
}
