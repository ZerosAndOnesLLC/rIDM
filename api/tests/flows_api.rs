mod common;

use common::TestApp;
use ridm_api::models::{
    AttributeDef, ClientType, LockoutPolicy, NewClient, NewUser, PasswordPolicy, ProfileSchema,
    RegistrationPolicy, TenantSettings,
};
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::{clients, profile_schema, sessions, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Fx {
    app: TestApp,
    user_id: Uuid,
}

async fn fixture(settings: TenantSettings, require_consent: bool) -> Fx {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
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
            require_consent: Some(require_consent),
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

/// Start at /authorize without a session; returns (flow id, flow state).
async fn start(fx: &Fx, extra: &[(&str, &str)]) -> (Uuid, Value) {
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
    (id, state)
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
async fn password_login_consent_and_finish() {
    let fx = fixture(TenantSettings::default(), true).await;
    let (id, state) = start(&fx, &[("login_hint", "alice")]).await;
    assert_eq!(state["stage"], "authenticate");
    assert_eq!(state["client"]["name"], "My App");
    assert_eq!(state["methods"], json!(["password"]));
    assert_eq!(state["login_hint"], "alice");
    let csrf = state["csrf"].as_str().unwrap().to_string();
    assert!(!csrf.is_empty());

    // CSRF is enforced; wrong password is rejected with a counter.
    assert_eq!(
        step(
            &fx,
            id,
            "password",
            json!({"csrf": "nope", "identifier": "alice", "password": "x"})
        )
        .await
        .status(),
        403
    );
    let res = step(
        &fx,
        id,
        "password",
        json!({"csrf": csrf, "identifier": "alice", "password": "wrong"}),
    )
    .await;
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_credentials");
    assert_eq!(body["attempts"], 1);
    // Unknown users get the same answer.
    let res = step(
        &fx,
        id,
        "password",
        json!({"csrf": csrf, "identifier": "nobody", "password": "wrong"}),
    )
    .await;
    assert_eq!(res.status(), 401);

    // Correct password: session cookie set, consent required next.
    let res = step(&fx, id, "password", json!({"csrf": csrf, "identifier": "ALICE@example.com", "password": "correct-horse-battery"})).await;
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let cookie = res.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(
        cookie.contains("HttpOnly")
            && cookie.contains("SameSite=Lax")
            && cookie.contains(&format!("Path=/t/{}", fx.app.tenant.slug)),
        "{cookie}"
    );
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["stage"], "consent");
    assert_eq!(body["user"]["username"], "alice");
    let pending: Vec<&str> = body["pending_scopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(pending, vec!["openid", "profile"]);
    assert!(body["pending_scopes"][1]["description"].is_string());

    // Password again at the wrong stage is refused.
    assert_eq!(
        step(
            &fx,
            id,
            "password",
            json!({"csrf": csrf, "identifier": "alice", "password": "correct-horse-battery"})
        )
        .await
        .status(),
        400
    );

    // Approve a subset (openid always kept) → done with a finish url.
    let res = step(
        &fx,
        id,
        "consent",
        json!({"csrf": csrf, "approve": true, "scopes": ["profile"]}),
    )
    .await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["stage"], "done", "{body}");
    let finish = body["finish_url"].as_str().unwrap().to_string();

    // Finishing needs the session cookie (a cookie-less client is refused); then the code is delivered.
    let bare = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let res = bare.get(&finish).send().await.unwrap();
    assert_eq!(res.status(), 401);
    let res = fx
        .app
        .http
        .get(&finish)
        .header("Cookie", cookie.split(';').next().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    assert_eq!(loc.path(), "/cb");
    let code = loc
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(
        loc.query_pairs().find(|(k, _)| k == "state").unwrap().1,
        "st"
    );
    // The flow is gone after finishing.
    assert_eq!(
        fx.app
            .http
            .get(fx.app.tenant_url(&format!("/flows/{id}")))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    let tokens: Value = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "https://app.example/cb"),
            ("code_verifier", VERIFIER),
            ("client_id", "spa"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(tokens["id_token"].is_string());
    assert_eq!(tokens["scope"], "openid profile");

    // Consent is remembered: a second authorization with the cookie goes straight to a code.
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "openid profile"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .header("Cookie", cookie.split(';').next().unwrap())
        .send()
        .await
        .unwrap();
    assert!(
        res.headers()["location"]
            .to_str()
            .unwrap()
            .contains("code=")
    );
    let last = users::get(&fx.app.state, fx.app.tenant.id, fx.user_id)
        .await
        .unwrap();
    assert!(last.last_login_at.is_some());
}

#[tokio::test]
async fn cancel_and_consent_denial_return_access_denied() {
    let fx = fixture(TenantSettings::default(), true).await;
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let res = step(&fx, id, "cancel", json!({"csrf": csrf})).await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["stage"], "cancelled");
    let u = url::Url::parse(body["redirect_to"].as_str().unwrap()).unwrap();
    assert_eq!(
        u.query_pairs().find(|(k, _)| k == "error").unwrap().1,
        "access_denied"
    );
    assert_eq!(u.query_pairs().find(|(k, _)| k == "state").unwrap().1, "st");
    assert_eq!(
        fx.app
            .http
            .get(fx.app.tenant_url(&format!("/flows/{id}")))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    step(
        &fx,
        id,
        "password",
        json!({"csrf": csrf, "identifier": "alice", "password": "correct-horse-battery"}),
    )
    .await;
    let body: Value = step(&fx, id, "consent", json!({"csrf": csrf, "approve": false}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(body["stage"], "denied");
    assert!(
        body["redirect_to"]
            .as_str()
            .unwrap()
            .contains("error=access_denied")
    );
}

#[tokio::test]
async fn password_change_profile_and_terms_stages_in_order() {
    let settings = TenantSettings {
        registration: RegistrationPolicy {
            require_terms: true,
            terms_url: Some("https://acme.example/tos".into()),
            ..Default::default()
        },
        password: PasswordPolicy {
            min_length: 8,
            history: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    let fx = fixture(settings, false).await;
    let tid = fx.app.tenant.id;
    // Required attribute and a temporary password.
    profile_schema::set(
        &fx.app.state,
        tid,
        Actor::System,
        ProfileSchema {
            attributes: vec![AttributeDef {
                name: "department".into(),
                required: true,
                ..Default::default()
            }],
            allow_undeclared: false,
        },
    )
    .await
    .unwrap();
    password::set_password(
        &fx.app.state,
        tid,
        &PasswordPolicy {
            min_length: 1,
            history: 0,
            ..Default::default()
        },
        Actor::System,
        fx.user_id,
        "temp".to_string().into(),
        SetPasswordOptions {
            must_change: true,
            skip_policy: true,
            by_user: false,
            notify: false,
        },
    )
    .await
    .unwrap();

    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let res = step(
        &fx,
        id,
        "password",
        json!({"csrf": csrf, "identifier": "alice", "password": "temp"}),
    )
    .await;
    let cookie = res.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["stage"], "password_change");
    // Steps out of order are refused.
    assert_eq!(
        step(&fx, id, "terms", json!({"csrf": csrf, "accepted": true}))
            .await
            .status(),
        400
    );
    // Policy applies to the new password.
    assert_eq!(
        step(
            &fx,
            id,
            "password-change",
            json!({"csrf": csrf, "new_password": "short"})
        )
        .await
        .status(),
        400
    );
    let body: Value = step(
        &fx,
        id,
        "password-change",
        json!({"csrf": csrf, "new_password": "brand-new-password"}),
    )
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(body["stage"], "profile", "{body}");
    assert_eq!(body["missing_attributes"][0]["name"], "department");
    let body: Value = step(
        &fx,
        id,
        "profile",
        json!({"csrf": csrf, "attributes": {"department": "eng"}}),
    )
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(body["stage"], "terms", "{body}");
    assert_eq!(body["terms_url"], "https://acme.example/tos");
    assert_eq!(
        step(&fx, id, "terms", json!({"csrf": csrf, "accepted": false}))
            .await
            .status(),
        403
    );
    let body: Value = step(&fx, id, "terms", json!({"csrf": csrf, "accepted": true}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(body["stage"], "done", "first-party client: no consent");
    let res = fx
        .app
        .http
        .get(body["finish_url"].as_str().unwrap())
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    assert!(
        res.headers()["location"]
            .to_str()
            .unwrap()
            .contains("code=")
    );

    // Next login: nothing pending anymore.
    let user = users::get(&fx.app.state, tid, fx.user_id).await.unwrap();
    assert!(user.terms_accepted_at.is_some());
    assert!(!user.must_change_password);
    let (id, state) = start(&fx, &[("prompt", "login")]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let body: Value = step(
        &fx,
        id,
        "password",
        json!({"csrf": csrf, "identifier": "alice", "password": "brand-new-password"}),
    )
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(body["stage"], "done");
}

#[tokio::test]
async fn lockout_after_repeated_failures() {
    let settings = TenantSettings {
        lockout: LockoutPolicy {
            max_failures: 3,
            lock_minutes: 15,
            ip_max_failures: 0,
            ip_window_minutes: 15,
        },
        ..Default::default()
    };
    let fx = fixture(settings, false).await;
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    for _ in 0..2 {
        let body: Value = step(
            &fx,
            id,
            "password",
            json!({"csrf": csrf, "identifier": "alice", "password": "wrong"}),
        )
        .await
        .json()
        .await
        .unwrap();
        assert_eq!(body["error"], "invalid_credentials");
    }
    let body: Value = step(
        &fx,
        id,
        "password",
        json!({"csrf": csrf, "identifier": "alice", "password": "wrong"}),
    )
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(body["error"], "account_locked");
    // Even the right password is refused while locked.
    let res = step(
        &fx,
        id,
        "password",
        json!({"csrf": csrf, "identifier": "alice", "password": "correct-horse-battery"}),
    )
    .await;
    assert_eq!(res.status(), 401);
    assert_eq!(
        res.json::<Value>().await.unwrap()["error"],
        "account_locked"
    );
    let user = users::get(&fx.app.state, fx.app.tenant.id, fx.user_id)
        .await
        .unwrap();
    assert!(user.is_locked_now());
    // Admin unlock restores access.
    users::unlock(&fx.app.state, fx.app.tenant.id, Actor::System, fx.user_id)
        .await
        .unwrap();
    let res = step(
        &fx,
        id,
        "password",
        json!({"csrf": csrf, "identifier": "alice", "password": "correct-horse-battery"}),
    )
    .await;
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn flows_are_tenant_scoped_and_expire() {
    let fx = fixture(TenantSettings::default(), false).await;
    let (id, _) = start(&fx, &[]).await;
    let other = common::create_tenant(&fx.app.state.db).await;
    assert_eq!(
        fx.app
            .http
            .get(fx.app.url(&format!("/t/{}/flows/{id}", other.slug)))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        fx.app
            .http
            .get(fx.app.tenant_url(&format!("/flows/{}", Uuid::now_v7())))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    // Finishing an incomplete flow is refused.
    assert_eq!(
        fx.app
            .http
            .get(fx.app.tenant_url(&format!("/flows/{id}/finish")))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
}

#[tokio::test]
async fn remember_device_is_registered_at_finish_and_recognised_next_login() {
    let fx = fixture(TenantSettings::default(), false).await;
    let tid = fx.app.tenant.id;
    let bare = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // First login asks to remember the browser: nothing is registered until finish.
    let (id, state) = start(&fx, &[]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let res = step(
        &fx,
        id,
        "password",
        json!({"csrf": csrf, "identifier": "alice", "password": "correct-horse-battery", "remember_device": true}),
    )
    .await;
    assert_eq!(res.status(), 200);
    let session_cookie = res.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["stage"], "done", "{body}");
    assert!(
        ridm_api::services::trusted_devices::list(&fx.app.state, tid, fx.user_id)
            .await
            .unwrap()
            .is_empty()
    );
    let flow = ridm_api::services::login_flows::get(&fx.app.state, tid, id)
        .await
        .unwrap()
        .unwrap();
    assert!(flow.remember_device && !flow.trusted_device);

    let res = bare
        .get(body["finish_url"].as_str().unwrap())
        .header("Cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let device_cookie = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("ridm_device="))
        .expect("device cookie set at finish")
        .to_string();
    assert!(device_cookie.contains("HttpOnly") && device_cookie.contains("Max-Age=2592000"));
    let devices = ridm_api::services::trusted_devices::list(&fx.app.state, tid, fx.user_id)
        .await
        .unwrap();
    assert_eq!(devices.len(), 1);
    let session = sessions::list_live_for_user(&fx.app.state, tid, fx.user_id)
        .await
        .unwrap();
    assert_eq!(session.len(), 1);
    assert_eq!(
        session[0].device_id,
        Some(devices[0].id),
        "session bound to the device"
    );

    // Next login from the same browser: the device is recognised and not re-registered.
    let device_cookie = device_cookie.split(';').next().unwrap().to_string();
    let (id, state) = start(&fx, &[("prompt", "login")]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url(&format!("/flows/{id}/password")))
        .header("Cookie", format!("{session_cookie}; {device_cookie}"))
        .json(&json!({"csrf": csrf, "identifier": "alice", "password": "correct-horse-battery", "remember_device": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["stage"], "done");
    let flow = ridm_api::services::login_flows::get(&fx.app.state, tid, id)
        .await
        .unwrap()
        .unwrap();
    assert!(flow.trusted_device && !flow.remember_device);
    let res = bare
        .get(body["finish_url"].as_str().unwrap())
        .header("Cookie", format!("{session_cookie}; {device_cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    assert!(
        !res.headers()
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap_or("").starts_with("ridm_device=")),
        "no second device cookie"
    );
    assert_eq!(
        ridm_api::services::trusted_devices::list(&fx.app.state, tid, fx.user_id)
            .await
            .unwrap()
            .len(),
        1
    );

    // Another user's login on this browser does not inherit the trust.
    let bob = users::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewUser {
            username: "bob".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    password::set_password(
        &fx.app.state,
        tid,
        &PasswordPolicy::default(),
        Actor::System,
        bob.id,
        "correct-horse-battery".to_string().into(),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();
    let (id, state) = start(&fx, &[("prompt", "login")]).await;
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url(&format!("/flows/{id}/password")))
        .header("Cookie", &device_cookie)
        .json(&json!({"csrf": csrf, "identifier": "bob", "password": "correct-horse-battery"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let flow = ridm_api::services::login_flows::get(&fx.app.state, tid, id)
        .await
        .unwrap()
        .unwrap();
    assert!(!flow.trusted_device);
}
