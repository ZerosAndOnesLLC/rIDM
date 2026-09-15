mod common;

use std::sync::{Arc, Mutex};

use common::TestApp;
use ridm_api::models::{
    CaptchaConfig, CaptchaPolicy, CaptchaProvider, ClientType, NewClient, NewUser, ProviderKind,
    TenantSettings,
};
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::{captcha, clients, provider_settings, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// Local siteverify: token "valid" succeeds, anything else fails; records the secret it saw.
async fn siteverify_server(seen: Arc<Mutex<Vec<(String, String)>>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let app = axum::Router::new().route("/siteverify", axum::routing::post(move |body: String| {
            let seen = seen.clone();
            async move {
                let form: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes()).map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
                let get = |k: &str| form.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone()).unwrap_or_default();
                seen.lock().unwrap().push((get("secret"), get("response")));
                let ok = get("response") == "valid";
                axum::Json(json!({"success": ok, "error-codes": if ok { vec![] } else { vec!["invalid-input-response"] }}))
            }
        }));
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://127.0.0.1:{port}/siteverify")
}

#[tokio::test]
async fn captcha_is_demanded_after_failures_and_verified_by_the_provider() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let seen = Arc::new(Mutex::new(vec![]));
    let verify_url = siteverify_server(seen.clone()).await;
    tenants::update(
        &app.state,
        Actor::System,
        tid,
        TenantUpdate {
            settings: Some(TenantSettings {
                captcha: CaptchaPolicy {
                    after_failures: 2,
                    on_registration: true,
                },
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    captcha::configure(
        &app.state,
        tid,
        &CaptchaConfig {
            provider: CaptchaProvider::Turnstile,
            site_key: "site-123".into(),
            secret: "shh".into(),
            verify_url: Some(verify_url),
        },
    )
    .await
    .unwrap();
    // Stored encrypted; readable through the typed accessor only.
    let mut tx = ridm_api::db::tenant_tx(&app.state.db, tid).await.unwrap();
    let raw: Vec<u8> = sqlx::query_scalar(
        "SELECT config_enc FROM tenant_provider_settings WHERE tenant_id = $1 AND kind = 'captcha'",
    )
    .bind(tid)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(!raw.windows(3).any(|w| w == b"shh"));
    let cfg = provider_settings::get::<CaptchaConfig>(&app.state, tid, ProviderKind::Captcha)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cfg.secret, "shh");

    let user = users::create(
        &app.state,
        tid,
        Actor::System,
        NewUser {
            username: "alice".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    password::set_password(
        &app.state,
        tid,
        &TenantSettings::default().password,
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
            name: "spa".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://app.example/cb".into()],
            require_consent: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let res = app
        .http
        .get(app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "openid"),
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
    let state: Value = app
        .http
        .get(app.tenant_url(&format!("/flows/{id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(state["captcha"].is_null(), "no challenge before failures");
    let csrf = state["csrf"].as_str().unwrap().to_string();
    let step = |body: Value| {
        let app = &app;
        async move {
            app.http
                .post(app.tenant_url(&format!("/flows/{id}/password")))
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };
    for _ in 0..2 {
        assert_eq!(
            step(json!({"csrf": csrf, "identifier": "alice", "password": "wrong"}))
                .await
                .status(),
            401
        );
    }
    let state: Value = app
        .http
        .get(app.tenant_url(&format!("/flows/{id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(state["captcha"]["provider"], "turnstile");
    assert_eq!(state["captcha"]["site_key"], "site-123");

    // Without a token: refused before the password is even checked.
    let res =
        step(json!({"csrf": csrf, "identifier": "alice", "password": "correct-horse-battery"}))
            .await;
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["errors"][0]["message"], "captcha_required");
    assert!(seen.lock().unwrap().is_empty());
    // Wrong token: provider says no.
    let res = step(json!({"csrf": csrf, "identifier": "alice", "password": "correct-horse-battery", "captcha_token": "nope"})).await;
    assert_eq!(res.status(), 400);
    assert_eq!(
        res.json::<Value>().await.unwrap()["errors"][0]["message"],
        "captcha_failed"
    );
    // Valid token: login proceeds; the provider received our secret.
    let res = step(json!({"csrf": csrf, "identifier": "alice", "password": "correct-horse-battery", "captcha_token": "valid"})).await;
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let calls = seen.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|(secret, resp)| secret == "shh" && resp == "valid")
    );

    // Disabling the provider removes the requirement even after failures.
    captcha::disable(&app.state, tid).await.unwrap();
    let res = app
        .http
        .get(app.tenant_url("/authorize"))
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
    let id2: Uuid = loc
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .unwrap()
        .1
        .parse()
        .unwrap();
    let st: Value = app
        .http
        .get(app.tenant_url(&format!("/flows/{id2}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let csrf2 = st["csrf"].as_str().unwrap().to_string();
    for _ in 0..3 {
        app.http
            .post(app.tenant_url(&format!("/flows/{id2}/password")))
            .json(&json!({"csrf": csrf2, "identifier": "alice", "password": "wrong"}))
            .send()
            .await
            .unwrap();
    }
    let st: Value = app
        .http
        .get(app.tenant_url(&format!("/flows/{id2}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(st["captcha"].is_null());
}
