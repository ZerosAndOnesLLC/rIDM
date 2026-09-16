//! Phase 8.4: the device authorization grant (RFC 8628). A device asks
//! `/device_authorization` for a code pair, the user enters the user code
//! on the `/device/` page (a login flow for the device's client, with
//! consent), and the device polls `/token` until the answer is tokens,
//! `authorization_pending`, `slow_down`, `access_denied` or `expired_token`.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::TestApp;
use ridm_api::models::{ClientType, NewClient, NewUser};
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::{clients, tenants, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const PASSWORD: &str = "Correct-Horse-Battery-9";
const USER_CODE_RE: &str = r"^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$";

struct Fx {
    app: TestApp,
    user_id: Uuid,
}

async fn fixture() -> Fx {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
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
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    password::set_password(
        &app.state,
        tid,
        &tenant.settings.password,
        Actor::System,
        user.id,
        PASSWORD.to_string().into(),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();
    for (id, name, consent) in [
        ("tv", "Living-room TV", true),
        ("kiosk", "Lobby kiosk", false),
    ] {
        clients::create(
            &app.state,
            tid,
            Actor::System,
            NewClient {
                client_id: Some(id.into()),
                name: name.into(),
                client_type: Some(ClientType::Device),
                allowed_scopes: Some(vec![
                    "openid".into(),
                    "profile".into(),
                    "email".into(),
                    "offline_access".into(),
                ]),
                require_consent: Some(consent),
                ..Default::default()
            },
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
            name: "SPA".into(),
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
        user_id: user.id,
    }
}

fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap()
}

/// `POST /device_authorization` as a public device client.
async fn device_authorization(fx: &Fx, client_id: &str, scope: &str) -> (u16, Value) {
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/device_authorization"))
        .form(&[("client_id", client_id), ("scope", scope)])
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

/// One poll of `/token` with the device code.
async fn poll(fx: &Fx, client_id: &str, device_code: &str) -> (u16, Value) {
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", client_id),
            ("device_code", device_code),
        ])
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

/// The user enters the code on the device page; returns the page the API
/// sends the browser to.
async fn verify(http: &reqwest::Client, fx: &Fx, user_code: &str) -> (u16, Value) {
    let res = http
        .post(fx.app.tenant_url("/device/verify"))
        .json(&json!({"user_code": user_code}))
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

fn flow_of(redirect_to: &Value) -> (String, Uuid) {
    let u = url::Url::parse(redirect_to.as_str().expect("redirect_to")).unwrap();
    let page = u.path().trim_matches('/').to_string();
    let flow = u
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .map(|(_, v)| v.parse().unwrap())
        .expect("flow id");
    (page, flow)
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
    let status = res.status();
    let v: Value = res.json().await.unwrap();
    assert!(status.is_success(), "{name}: {v}");
    v
}

/// The user approves in the browser: password, consent (when asked), finish.
/// Returns the finish redirect (the device page with `done=1`).
async fn approve_in_browser(http: &reqwest::Client, fx: &Fx, user_code: &str) -> url::Url {
    let (status, body) = verify(http, fx, user_code).await;
    assert_eq!(status, 200, "{body}");
    let (page, flow) = flow_of(&body["redirect_to"]);
    let mut state = get_flow(http, fx, flow).await;
    if page == "login" && state["stage"] == "authenticate" {
        let csrf = state["csrf"].as_str().unwrap().to_string();
        state = step(
            http,
            fx,
            flow,
            "password",
            json!({"identifier": "alice", "password": PASSWORD}),
            &csrf,
        )
        .await;
    }
    if state["stage"] == "consent" {
        let csrf = state["csrf"].as_str().unwrap().to_string();
        state = step(http, fx, flow, "consent", json!({"approve": true}), &csrf).await;
    }
    assert_eq!(state["stage"], "done", "{state}");
    let res = http
        .get(state["finish_url"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap()
}

fn claims(jwt: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn the_device_polls_until_the_user_approves() {
    let fx = fixture().await;
    let (status, auth) = device_authorization(&fx, "tv", "openid profile offline_access").await;
    assert_eq!(status, 200, "{auth}");
    let device_code = auth["device_code"].as_str().unwrap().to_string();
    let user_code = auth["user_code"].as_str().unwrap().to_string();
    assert!(
        regex::Regex::new(USER_CODE_RE)
            .unwrap()
            .is_match(&user_code),
        "{user_code}"
    );
    assert_eq!(auth["expires_in"], 600);
    assert_eq!(auth["interval"], 5);
    assert!(
        auth["verification_uri"]
            .as_str()
            .unwrap()
            .ends_with(&format!("/device/?tenant={}", fx.app.tenant.slug)),
        "{auth}"
    );
    assert!(
        auth["verification_uri_complete"]
            .as_str()
            .unwrap()
            .contains(&format!("user_code={user_code}")),
        "{auth}"
    );

    // Nobody has decided yet.
    let (status, body) = poll(&fx, "tv", &device_code).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "authorization_pending");
    // Polling again at once is too fast: the interval grows.
    let (_, body) = poll(&fx, "tv", &device_code).await;
    assert_eq!(body["error"], "slow_down");

    // The user approves on another device: sign-in, then consent for the TV.
    let http = browser();
    let (status, body) = verify(&http, &fx, &user_code.to_lowercase().replace('-', " ")).await;
    assert_eq!(
        status, 200,
        "user codes are forgiving about case and separators: {body}"
    );
    let (page, flow) = flow_of(&body["redirect_to"]);
    assert_eq!(page, "login");
    let state = get_flow(&http, &fx, flow).await;
    assert_eq!(state["stage"], "authenticate");
    assert_eq!(state["client"]["name"], "Living-room TV");
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let state = step(
        &http,
        &fx,
        flow,
        "password",
        json!({"identifier": "alice", "password": PASSWORD}),
        &csrf,
    )
    .await;
    assert_eq!(
        state["stage"], "consent",
        "a third-party device asks for consent: {state}"
    );
    let names: Vec<&str> = state["pending_scopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["openid", "profile", "offline_access"]);
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let state = step(&http, &fx, flow, "consent", json!({"approve": true}), &csrf).await;
    assert_eq!(state["stage"], "done");
    let res = http
        .get(state["finish_url"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let back = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    assert!(back.path().ends_with("/device/"), "{back}");
    assert!(
        back.query_pairs().any(|(k, v)| k == "done" && v == "1"),
        "{back}"
    );

    // The device waits out its (now longer) interval, then collects the tokens.
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    let (status, tokens) = poll(&fx, "tv", &device_code).await;
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["scope"], "openid profile offline_access");
    assert!(
        tokens["refresh_token"].is_string(),
        "the device client may refresh"
    );
    let id = claims(tokens["id_token"].as_str().expect("id_token with openid"));
    assert_eq!(id["aud"], "tv");
    assert_eq!(id["amr"], json!(["pwd"]));
    assert!(id["auth_time"].is_number());
    let at = claims(tokens["access_token"].as_str().unwrap());
    assert_eq!(at["client_id"], "tv");
    assert_eq!(at["sub"], fx.user_id.to_string());

    // A device code is spent by the poll that took it.
    let (status, body) = poll(&fx, "tv", &device_code).await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_grant");
    let mut tx = ridm_api::db::tenant_tx(&fx.app.state.db, fx.app.tenant.id)
        .await
        .unwrap();
    let (status, user): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status, user_id FROM device_codes WHERE tenant_id = $1 AND user_code = $2",
    )
    .bind(fx.app.tenant.id)
    .bind(&user_code)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(status, "consumed");
    assert_eq!(user, Some(fx.user_id));
    // The user code is gone with it.
    let (status, _) = verify(&browser(), &fx, &user_code).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn denial_expiry_and_refusals() {
    let fx = fixture().await;

    // Denied at the consent screen.
    let (_, auth) = device_authorization(&fx, "tv", "openid").await;
    let http = browser();
    let (_, body) = verify(&http, &fx, auth["user_code"].as_str().unwrap()).await;
    let (_, flow) = flow_of(&body["redirect_to"]);
    let state = get_flow(&http, &fx, flow).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let state = step(
        &http,
        &fx,
        flow,
        "password",
        json!({"identifier": "alice", "password": PASSWORD}),
        &csrf,
    )
    .await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let denied = step(
        &http,
        &fx,
        flow,
        "consent",
        json!({"approve": false}),
        &csrf,
    )
    .await;
    assert_eq!(denied["stage"], "denied");
    let back = url::Url::parse(denied["redirect_to"].as_str().unwrap()).unwrap();
    assert!(back.path().ends_with("/device/"), "{back}");
    assert!(
        back.query_pairs()
            .any(|(k, v)| k == "error" && v == "access_denied")
    );
    let (status, body) = poll(&fx, "tv", auth["device_code"].as_str().unwrap()).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "access_denied");
    let (_, body) = poll(&fx, "tv", auth["device_code"].as_str().unwrap()).await;
    assert_eq!(body["error"], "invalid_grant", "a denial is delivered once");

    // Cancelled at the sign-in.
    let (_, auth) = device_authorization(&fx, "tv", "openid").await;
    let http = browser();
    let (_, body) = verify(&http, &fx, auth["user_code"].as_str().unwrap()).await;
    let (_, flow) = flow_of(&body["redirect_to"]);
    let state = get_flow(&http, &fx, flow).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    step(&http, &fx, flow, "cancel", json!({}), &csrf).await;
    let (_, body) = poll(&fx, "tv", auth["device_code"].as_str().unwrap()).await;
    assert_eq!(body["error"], "access_denied");

    // Expired: the record's expiry is moved into the past.
    let (_, auth) = device_authorization(&fx, "tv", "openid").await;
    let device_code = auth["device_code"].as_str().unwrap();
    let key = ridm_api::cache::keys::device_code(
        fx.app.tenant.id,
        &URL_SAFE_NO_PAD.encode(Sha256::digest(device_code.as_bytes())),
    );
    {
        use redis::AsyncCommands as _;
        let mut conn = fx.app.state.redis.get().await.unwrap();
        let raw: String = conn.get(&key).await.unwrap();
        let mut rec: Value = serde_json::from_str(&raw).unwrap();
        rec["expires_at"] = json!(chrono::Utc::now() - chrono::Duration::seconds(1));
        let _: () = conn.set_ex(&key, rec.to_string(), 60).await.unwrap();
    }
    let (status, body) = poll(&fx, "tv", device_code).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "expired_token");
    let (status, _) = verify(&browser(), &fx, auth["user_code"].as_str().unwrap()).await;
    assert_eq!(status, 404, "an expired code cannot be approved");

    // Refusals at the authorization endpoint.
    let (status, body) = device_authorization(&fx, "spa", "openid").await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "unauthorized_client");
    let (status, body) = device_authorization(&fx, "nope", "openid").await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "invalid_client");
    let (status, body) = device_authorization(&fx, "tv", "").await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_scope");
    let (_, body) = device_authorization(&fx, "tv", "openid admin:everything").await;
    assert_eq!(body["error"], "invalid_scope");

    // Refusals at the token endpoint.
    let (_, body) = poll(&fx, "tv", "not-a-code").await;
    assert_eq!(body["error"], "invalid_grant");
    let (_, auth) = device_authorization(&fx, "tv", "openid").await;
    let (_, body) = poll(&fx, "kiosk", auth["device_code"].as_str().unwrap()).await;
    assert_eq!(body["error"], "invalid_grant", "another client's code");
    let (_, body) = poll(&fx, "spa", auth["device_code"].as_str().unwrap()).await;
    assert_eq!(body["error"], "unauthorized_client");

    // Guessing user codes is rate-limited per address.
    let http = browser();
    let (status, _) = verify(&http, &fx, "BCDF-GHJK").await;
    assert!(status == 404 || status == 429);
    let mut limited = false;
    for _ in 0..12 {
        let (status, _) = verify(&http, &fx, "BCDF-GHJK").await;
        if status == 429 {
            limited = true;
            break;
        }
    }
    assert!(limited, "twelve wrong guesses are too many");
    let (status, _) = verify(&http, &fx, "not a code").await;
    assert_eq!(status, 429);
}

#[tokio::test]
async fn a_signed_in_browser_goes_straight_to_consent_or_done() {
    let fx = fixture().await;
    // Sign in through the SPA first so the browser holds a session.
    let http = browser();
    let res = http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "openid"),
            ("state", "st"),
            (
                "code_challenge",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            ),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let flow: Uuid = loc
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .unwrap()
        .1
        .parse()
        .unwrap();
    let state = get_flow(&http, &fx, flow).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let state = step(
        &http,
        &fx,
        flow,
        "password",
        json!({"identifier": "alice", "password": PASSWORD}),
        &csrf,
    )
    .await;
    assert_eq!(state["stage"], "done");
    http.get(state["finish_url"].as_str().unwrap())
        .send()
        .await
        .unwrap();

    // Third-party device: consent is what is left.
    let (_, auth) = device_authorization(&fx, "tv", "openid email").await;
    let (status, body) = verify(&http, &fx, auth["user_code"].as_str().unwrap()).await;
    assert_eq!(status, 200, "{body}");
    let (page, flow) = flow_of(&body["redirect_to"]);
    assert_eq!(page, "consent");
    let state = get_flow(&http, &fx, flow).await;
    assert_eq!(state["stage"], "consent");
    assert_eq!(state["user"]["username"], "alice");
    let back = approve_in_browser(&browser(), &fx, auth["user_code"].as_str().unwrap()).await;
    assert!(
        back.query_pairs().any(|(k, v)| k == "done" && v == "1"),
        "{back}"
    );

    // First-party kiosk: nothing is left, the finish approves at once.
    let (_, auth) = device_authorization(&fx, "kiosk", "openid").await;
    let (status, body) = verify(&http, &fx, auth["user_code"].as_str().unwrap()).await;
    assert_eq!(status, 200, "{body}");
    let (page, flow) = flow_of(&body["redirect_to"]);
    assert_eq!(
        page, "login",
        "the login page forwards a done flow to its finish"
    );
    let state = get_flow(&http, &fx, flow).await;
    assert_eq!(state["stage"], "done");
    let res = http
        .get(state["finish_url"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let (status, tokens) = poll(&fx, "kiosk", auth["device_code"].as_str().unwrap()).await;
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(claims(tokens["id_token"].as_str().unwrap())["aud"], "kiosk");
}

#[tokio::test]
async fn discovery_advertises_the_grant() {
    let fx = fixture().await;
    let doc: Value = fx
        .app
        .http
        .get(fx.app.tenant_url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        doc["device_authorization_endpoint"],
        fx.app.tenant_url("/device_authorization")
    );
    assert!(
        doc["grant_types_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g == "urn:ietf:params:oauth:grant-type:device_code")
    );
}
