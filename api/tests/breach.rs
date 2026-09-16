//! Phase 7.5: breached-password check (k-anonymity, HIBP-compatible).
//! Tenants opt in with `password.check_breached`; the deployment plugs in a
//! checker (mocked here) or switches it off; an outage lets passwords
//! through; the real client talks to a range endpoint served by this test.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::extract::Path;
use axum::http::HeaderMap;
use axum::routing::get;
use common::TestApp;
use ridm_api::models::{ClientType, NewClient, NewUser, PasswordPolicy, TenantSettings};
use ridm_api::services::breach::HibpChecker;
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::{clients, users};
use ridm_api::state::AppState;
use ridm_core::events::Actor;
use ridm_core::providers::{BreachChecker as _, password_sha1_hex};
use ridm_core::test_support::MockBreachChecker;
use serde_json::{Value, json};
use uuid::Uuid;

const BREACHED: &str = "correct-horse-battery-staple";
const CLEAN: &str = "a-long-and-unremarkable-phrase";

async fn fixture(mock: Option<Arc<MockBreachChecker>>, check: bool) -> (TestApp, Uuid) {
    let app = TestApp::spawn_configured(Router::new(), move |st| {
        st.breach = mock.map(|m| m as Arc<dyn ridm_core::providers::BreachChecker>);
    })
    .await;
    let tid = app.tenant.id;
    tenants::update(
        &app.state,
        Actor::System,
        tid,
        TenantUpdate {
            settings: Some(TenantSettings {
                password: PasswordPolicy {
                    check_breached: check,
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
            ..Default::default()
        },
    )
    .await
    .unwrap();
    (app, user.id)
}

async fn set(
    app: &TestApp,
    user_id: Uuid,
    password: &str,
) -> Result<(), ridm_api::error::AppError> {
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    password::set_password(
        &app.state,
        app.tenant.id,
        &tenant.settings.password,
        Actor::System,
        user_id,
        password.to_string().into(),
        SetPasswordOptions::default(),
    )
    .await
}

fn field_errors(err: ridm_api::error::AppError) -> Vec<(String, String)> {
    match err {
        ridm_api::error::AppError::Validation(errors) => {
            errors.into_iter().map(|e| (e.field, e.message)).collect()
        }
        other => panic!("expected a validation error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_breached_password_is_refused_only_when_the_tenant_opts_in() {
    let mock = Arc::new(MockBreachChecker::new());
    mock.add(BREACHED);
    let (app, alice) = fixture(Some(mock.clone()), true).await;

    let errors = field_errors(set(&app, alice, BREACHED).await.unwrap_err());
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].0, "password");
    assert!(errors[0].1.contains("data breach"), "{}", errors[0].1);
    assert_eq!(
        mock.calls(),
        vec![password_sha1_hex(BREACHED)],
        "only the hash is looked up"
    );

    set(&app, alice, CLEAN).await.unwrap();
    assert_eq!(mock.calls().len(), 2);

    // Policy problems come first: nothing is looked up for a too-short password.
    let errors = field_errors(set(&app, alice, "short").await.unwrap_err());
    assert!(errors.iter().any(|(_, m)| m.contains("at least")));
    assert_eq!(mock.calls().len(), 2);

    // An admin override skips the check like every other policy rule.
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    password::set_password(
        &app.state,
        app.tenant.id,
        &tenant.settings.password,
        Actor::System,
        alice,
        BREACHED.to_string().into(),
        SetPasswordOptions {
            skip_policy: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(mock.calls().len(), 2);

    // Self-registration through a login flow reports it as a field error too.
    let mut settings = tenant.settings.0.clone();
    settings.registration.enabled = true;
    settings.registration.require_email_verification = false;
    settings.captcha.on_registration = false;
    tenants::update(
        &app.state,
        Actor::System,
        app.tenant.id,
        TenantUpdate {
            settings: Some(settings),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    clients::create(
        &app.state,
        app.tenant.id,
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
    let res = app
        .http
        .get(app.tenant_url("/authorize"))
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
            ("prompt", "create"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let flow = loc
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    let state: Value = app
        .http
        .get(app.tenant_url(&format!("/flows/{flow}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let res = app
        .http
        .post(app.tenant_url(&format!("/flows/{flow}/register")))
        .json(&json!({"csrf": state["csrf"], "email": "bob@example.com", "password": BREACHED}))
        .send()
        .await
        .unwrap();
    let status = res.status();
    let text = res.text().await.unwrap();
    assert_eq!(status, 400, "{text}");
    let body: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["errors"][0]["field"], "password");
    assert!(
        body["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("data breach")
    );
}

#[tokio::test]
async fn the_check_is_skipped_when_the_tenant_or_the_deployment_has_it_off() {
    let mock = Arc::new(MockBreachChecker::new());
    mock.add(BREACHED);
    let (app, alice) = fixture(Some(mock.clone()), false).await;
    set(&app, alice, BREACHED).await.unwrap();
    assert!(mock.calls().is_empty(), "tenant policy off: no lookup");

    // Deployment switched off (air-gapped): the tenant toggle is inert.
    let (app, alice) = fixture(None, true).await;
    set(&app, alice, BREACHED).await.unwrap();
}

#[tokio::test]
async fn an_outage_lets_the_password_through() {
    let mock = Arc::new(MockBreachChecker::new());
    mock.add(BREACHED);
    mock.fail_next(1);
    let (app, alice) = fixture(Some(mock.clone()), true).await;
    set(&app, alice, BREACHED).await.unwrap();
    assert_eq!(mock.calls().len(), 1);
    // Back up: refused again.
    assert!(set(&app, alice, BREACHED).await.is_err());
}

/// A range endpoint like HIBP's, serving one padded page.
fn range_server() -> Router<AppState> {
    Router::new().route(
        "/range/{prefix}",
        get(
            |Path(prefix): Path<String>, headers: HeaderMap| async move {
                assert_eq!(prefix.len(), 5, "only the five-digit prefix is sent");
                assert_eq!(
                    headers.get("add-padding").and_then(|v| v.to_str().ok()),
                    Some("true")
                );
                let sha = password_sha1_hex(BREACHED);
                if prefix == sha[..5] {
                    format!(
                        "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{}:3\r\n{}:0\r\n",
                        &sha[5..],
                        &password_sha1_hex(CLEAN)[5..]
                    )
                } else {
                    "0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n".to_string()
                }
            },
        ),
    )
}

#[tokio::test]
async fn the_hibp_client_matches_the_suffix_locally() {
    let app = TestApp::spawn_with(range_server()).await;
    let checker = HibpChecker::new(app.url("/range/").parse().unwrap());
    assert_eq!(
        checker.count(&password_sha1_hex(BREACHED)).await.unwrap(),
        3
    );
    // A zero-count padding line is not a hit, and neither is an unknown hash.
    assert_eq!(checker.count(&password_sha1_hex(CLEAN)).await.unwrap(), 0);
    assert_eq!(
        checker
            .count(&password_sha1_hex("something-else-entirely"))
            .await
            .unwrap(),
        0
    );
    assert!(checker.count("not-a-hash").await.is_err());
    // An unreachable endpoint is an outage, not a verdict.
    let dead = HibpChecker::new("http://127.0.0.1:9/range/".parse().unwrap());
    assert!(dead.count(&password_sha1_hex(CLEAN)).await.is_err());
}
