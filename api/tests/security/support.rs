//! Helpers shared by the security suite's modules: a public client, a signed
//! in browser, the code and token round trips, and a password login through
//! the flow API the way the UI drives it.

use ridm_api::models::{ClientType, NewClient, NewUser};
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::{clients, tenants, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::common::TestApp;
use crate::{CHALLENGE, VERIFIER};

pub const PASSWORD: &str = "correct-horse-battery";
pub const REDIRECT: &str = "https://app.example/cb";

/// A public SPA client `spa` in `tenant_id`, with `extra` applied.
pub async fn spa(app: &TestApp, tenant_id: Uuid, extra: NewClient) {
    clients::create(
        &app.state,
        tenant_id,
        Actor::System,
        NewClient {
            client_id: Some("spa".into()),
            name: "spa".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec![REDIRECT.into()],
            require_consent: Some(false),
            ..extra
        },
    )
    .await
    .unwrap();
}

/// A user with [`PASSWORD`] set.
pub async fn user_with_password(app: &TestApp, tenant_id: Uuid, username: &str) -> Uuid {
    let tenant = tenants::get(&app.state, tenant_id).await.unwrap();
    let user = users::create(
        &app.state,
        tenant_id,
        Actor::System,
        NewUser {
            username: username.into(),
            email: Some(format!("{username}@example.com")),
            email_verified: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    password::set_password(
        &app.state,
        tenant_id,
        &tenant.settings.password,
        Actor::System,
        user.id,
        PASSWORD.to_string().into(),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();
    user.id
}

/// A live SSO session for `user_id` (password only) and its `Cookie` header value.
pub async fn session(app: &TestApp, tenant_id: Uuid, slug: &str, user_id: Uuid) -> (Uuid, String) {
    let tenant = tenants::get(&app.state, tenant_id).await.unwrap();
    let s = sessions::create(
        &app.state,
        tenant_id,
        NewSession {
            user_id,
            amr: vec!["pwd".into()],
            acr: None,
            ip: None,
            user_agent: None,
            policy: &tenant.settings.session,
        },
    )
    .await
    .unwrap();
    (
        s.id,
        format!("{}={}", sessions::cookie_name(&app.state, slug), s.id),
    )
}

/// `GET /t/{slug}/authorize` for `spa`; returns where it redirected to.
pub async fn authorize(
    http: &reqwest::Client,
    app: &TestApp,
    slug: &str,
    cookie: Option<&str>,
    extra: &[(&str, &str)],
) -> url::Url {
    let mut q = vec![
        ("response_type", "code"),
        ("client_id", "spa"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
        ("state", "st"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];
    // A parameter in `extra` replaces the default of the same name.
    q.retain(|(k, _)| !extra.iter().any(|(e, _)| e == k));
    q.extend_from_slice(extra);
    let mut req = http.get(app.url(&format!("/t/{slug}/authorize"))).query(&q);
    if let Some(c) = cookie {
        req = req.header("Cookie", c);
    }
    let res = req.send().await.unwrap();
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap()
}

pub fn param(u: &url::Url, k: &str) -> Option<String> {
    u.query_pairs()
        .find(|(a, _)| a == k)
        .map(|(_, v)| v.into_owned())
}

/// Exchange a code at `/t/{slug}/token`; returns status and body.
pub async fn exchange(app: &TestApp, slug: &str, code: &str) -> (u16, Value) {
    token(
        app,
        slug,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
            ("client_id", "spa"),
        ],
    )
    .await
}

/// A refresh request for `spa`, with `extra` parameters.
pub async fn refresh(app: &TestApp, slug: &str, rt: &str, extra: &[(&str, &str)]) -> (u16, Value) {
    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", rt),
        ("client_id", "spa"),
    ];
    form.extend_from_slice(extra);
    token(app, slug, &form).await
}

pub async fn token(app: &TestApp, slug: &str, form: &[(&str, &str)]) -> (u16, Value) {
    let res = app
        .http
        .post(app.url(&format!("/t/{slug}/token")))
        .form(form)
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

/// A browser-like client: its own cookie jar, redirects not followed.
pub fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap()
}

/// Start a login at `/t/{slug}/authorize` and pass the password step in
/// `http`'s jar; returns the flow id and its state after the step.
pub async fn password_login(
    http: &reqwest::Client,
    app: &TestApp,
    slug: &str,
    username: &str,
) -> (Uuid, Value) {
    let loc = authorize(http, app, slug, None, &[]).await;
    let id: Uuid = param(&loc, "flow").expect("a login flow").parse().unwrap();
    let state: Value = http
        .get(app.url(&format!("/t/{slug}/flows/{id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let res = http
        .post(app.url(&format!("/t/{slug}/flows/{id}/password")))
        .json(&json!({
            "csrf": state["csrf"],
            "identifier": username,
            "password": PASSWORD,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    (id, res.json().await.unwrap())
}

/// Follow a done flow's finish URL; returns the code on the callback.
pub async fn finish(http: &reqwest::Client, state: &Value) -> String {
    let res = http
        .get(state["finish_url"].as_str().expect("a finish url"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    param(&loc, "code").expect("code on the callback")
}
