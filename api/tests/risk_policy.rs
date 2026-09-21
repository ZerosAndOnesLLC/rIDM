//! Phase 12.3: risk-based adaptive authentication — the signals, the score,
//! the two thresholds, and what a step-up or a block does to a sign-in.
//!
//! Location comes from the `CloudFront-Viewer-*` headers, which the server
//! only believes behind a trusted proxy; the suite runs from 127.0.0.1 with
//! that address configured as one, and one test takes it away again to prove
//! the rule.

mod common;

use std::sync::Arc;

use common::TestApp;
use ridm_api::db;
use ridm_api::models::{
    ClientType, NewClient, NewUser, RiskPolicy, RiskWeights, TenantSettings, UserStatus,
};
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::{clients, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const PASSWORD: &str = "correct-horse-battery";
const UA: &str = "Mozilla/5.0 (risk suite)";

/// Two places far enough apart that no aeroplane connects them in an hour.
const LONDON: (&str, &str, &str) = ("GB", "51.5074", "-0.1278");
const SYDNEY: (&str, &str, &str) = ("AU", "-33.8688", "151.2093");

struct Fx {
    app: TestApp,
    settings: TenantSettings,
}

/// A tenant with the risk policy as given, a client and one user.
async fn fixture(risk: RiskPolicy) -> Fx {
    let app = TestApp::spawn_configured(axum::Router::new(), |state| {
        let mut config = (*state.config).clone();
        // The suite's own address: without this the geo headers are ignored.
        config.trusted_proxies = vec!["127.0.0.1/32".parse().unwrap()];
        state.config = Arc::new(config);
    })
    .await;
    let tid = app.tenant.id;
    let settings = TenantSettings {
        risk,
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
    let fx = Fx { app, settings };
    user(&fx, "ada").await;
    fx
}

/// A policy that steps up on one new country and blocks on two signals.
fn policy() -> RiskPolicy {
    RiskPolicy {
        enabled: true,
        weights: RiskWeights {
            new_device: 20,
            new_country: 50,
            impossible_travel: 60,
            velocity: 40,
        },
        step_up_at: 50,
        block_at: 100,
        impossible_travel_kmh: 900,
        velocity_window_minutes: 15,
        velocity_max_failures: 3,
    }
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
            status: Some(UserStatus::Active),
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

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap()
}

fn param(u: &url::Url, k: &str) -> Option<String> {
    u.query_pairs()
        .find(|(a, _)| a == k)
        .map(|(_, v)| v.into_owned())
}

fn geo(place: (&str, &str, &str)) -> Vec<(&'static str, String)> {
    vec![
        ("cloudfront-viewer-country", place.0.to_string()),
        ("cloudfront-viewer-latitude", place.1.to_string()),
        ("cloudfront-viewer-longitude", place.2.to_string()),
    ]
}

fn with_geo(
    req: reqwest::RequestBuilder,
    place: Option<(&str, &str, &str)>,
) -> reqwest::RequestBuilder {
    let mut req = req.header("user-agent", UA);
    if let Some(place) = place {
        for (name, value) in geo(place) {
            req = req.header(name, value);
        }
    }
    req
}

/// `GET /authorize` from `place`; returns the redirect target.
async fn authorize(http: &reqwest::Client, fx: &Fx, place: Option<(&str, &str, &str)>) -> url::Url {
    let q = [
        ("response_type", "code"),
        ("client_id", "spa"),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", "openid"),
        ("state", "st"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];
    let res = with_geo(http.get(fx.app.tenant_url("/authorize")).query(&q), place)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303, "authorize");
    url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap()
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

/// Sign in with a password from `place`; returns the HTTP status and body.
async fn sign_in(
    http: &reqwest::Client,
    fx: &Fx,
    place: Option<(&str, &str, &str)>,
    username: &str,
) -> (reqwest::StatusCode, Value) {
    let loc = authorize(http, fx, place).await;
    let id: Uuid = param(&loc, "flow").expect("a login flow").parse().unwrap();
    let csrf = get_flow(http, fx, id).await["csrf"]
        .as_str()
        .unwrap()
        .to_string();
    let res = with_geo(
        http.post(fx.app.tenant_url(&format!("/flows/{id}/password")))
            .json(&json!({"identifier": username, "password": PASSWORD, "csrf": csrf})),
        place,
    )
    .send()
    .await
    .unwrap();
    let status = res.status();
    (status, res.json().await.unwrap())
}

/// The payloads of one event name, newest first. The writer records from the
/// event bus in the background, so the read is retried briefly.
async fn audit(app: &TestApp, name: &str) -> Vec<Value> {
    let mut rows = Vec::new();
    for _ in 0..50 {
        let mut tx = db::bypass_tx(&app.state.db).await.unwrap();
        rows = sqlx::query_scalar::<_, Value>(
            "SELECT payload FROM audit_events WHERE tenant_id = $1 AND name = $2 \
             ORDER BY occurred_at DESC",
        )
        .bind(app.tenant.id)
        .bind(name)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        if !rows.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    rows
}

/// A scalar read with row level security bypassed, the way the suite looks
/// at tenant tables it did not go through the API for.
async fn scalar<T>(app: &TestApp, sql: &'static str) -> T
where
    T: for<'r> sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Send + Unpin,
{
    let mut tx = db::bypass_tx(&app.state.db).await.unwrap();
    let v = sqlx::query_scalar::<_, T>(sql)
        .bind(app.tenant.id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    v
}

#[tokio::test]
async fn a_policy_that_is_off_changes_nothing() {
    let fx = fixture(RiskPolicy::default()).await;
    let http = client();
    // Even from a brand-new country: the default policy is not enabled.
    let (status, body) = sign_in(&http, &fx, Some(SYDNEY), "ada").await;
    assert_eq!(status, 200);
    assert_eq!(body["stage"], "done");
    // And nothing was remembered about where the sign-in came from.
    let seen: i64 = scalar(
        &fx.app,
        "SELECT count(*) FROM user_login_locations WHERE tenant_id = $1",
    )
    .await;
    assert_eq!(seen, 0);
}

#[tokio::test]
async fn the_first_sign_in_is_never_risky_and_is_remembered() {
    let fx = fixture(policy()).await;
    let http = client();
    let (status, body) = sign_in(&http, &fx, Some(LONDON), "ada").await;
    assert_eq!(status, 200);
    assert_eq!(body["stage"], "done", "nothing to compare against yet");
    assert!(audit(&fx.app, "risk.step_up").await.is_empty());

    let country: String = scalar(
        &fx.app,
        "SELECT country FROM user_login_locations WHERE tenant_id = $1",
    )
    .await;
    let logins: i64 = scalar(
        &fx.app,
        "SELECT logins FROM user_login_locations WHERE tenant_id = $1",
    )
    .await;
    assert_eq!((country.as_str(), logins), ("GB", 1));

    // The same place again: still nothing, and the row is counted up.
    let (status, body) = sign_in(&client(), &fx, Some(LONDON), "ada").await;
    assert_eq!(status, 200);
    assert_eq!(body["stage"], "done");
    let logins: i64 = scalar(
        &fx.app,
        "SELECT logins FROM user_login_locations WHERE tenant_id = $1",
    )
    .await;
    assert_eq!(logins, 2);
}

#[tokio::test]
async fn a_new_country_steps_up_to_the_second_factor() {
    let fx = fixture(RiskPolicy {
        // Only the country counts, so the score is exactly the threshold.
        weights: RiskWeights {
            new_device: 0,
            ..policy().weights
        },
        impossible_travel_kmh: 0,
        ..policy()
    })
    .await;
    // Seen in London first.
    let (status, _) = sign_in(&client(), &fx, Some(LONDON), "ada").await;
    assert_eq!(status, 200);

    // Now from Sydney: the policy demands a second factor although the
    // tenant's MFA policy is off and the user enrolled nothing.
    let (status, body) = sign_in(&client(), &fx, Some(SYDNEY), "ada").await;
    assert_eq!(status, 200);
    assert_eq!(body["stage"], "mfa", "{body}");

    let rows = audit(&fx.app, "risk.step_up").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let data = &rows[0];
    assert_eq!(data["score"], 50);
    assert_eq!(data["country"], "AU");
    assert_eq!(data["signals"], json!(["new_country"]));
}

#[tokio::test]
async fn impossible_travel_on_a_new_device_blocks_the_sign_in() {
    let fx = fixture(policy()).await;
    // London, an hour ago as far as the history is concerned.
    let (status, _) = sign_in(&client(), &fx, Some(LONDON), "ada").await;
    assert_eq!(status, 200);

    // Sydney, now, from a browser never seen before: new country (50),
    // impossible travel (60) and a new device (20) — well past 100.
    let (status, body) = sign_in(&client(), &fx, Some(SYDNEY), "ada").await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], "access_denied");
    let redirect = body["redirect_to"]
        .as_str()
        .expect("a redirect for the client");
    let redirect = url::Url::parse(redirect).unwrap();
    assert!(redirect.as_str().starts_with("https://app.example/cb"));
    assert_eq!(param(&redirect, "error").as_deref(), Some("access_denied"));
    assert_eq!(param(&redirect, "state").as_deref(), Some("st"));

    let rows = audit(&fx.app, "risk.blocked").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let signals = rows[0]["signals"].as_array().unwrap().clone();
    assert!(signals.contains(&json!("impossible_travel")), "{signals:?}");
    assert!(signals.contains(&json!("new_country")), "{signals:?}");

    // A refused sign-in leaves nothing: no session, and Sydney did not
    // become a place this user is known to sign in from.
    let sessions: i64 = scalar(
        &fx.app,
        "SELECT count(*) FROM sso_sessions WHERE tenant_id = $1",
    )
    .await;
    assert_eq!(sessions, 1, "only the London sign-in");
    let countries: String = scalar(
        &fx.app,
        "SELECT string_agg(country, ',' ORDER BY country) FROM user_login_locations \
         WHERE tenant_id = $1",
    )
    .await;
    assert_eq!(countries, "GB");
}

#[tokio::test]
async fn a_blocked_attempt_is_a_failure_the_velocity_signal_can_see() {
    let fx = fixture(policy()).await;
    let (status, _) = sign_in(&client(), &fx, Some(LONDON), "ada").await;
    assert_eq!(status, 200);
    let (status, _) = sign_in(&client(), &fx, Some(SYDNEY), "ada").await;
    assert_eq!(status, 403);
    let latest: String = scalar(
        &fx.app,
        "SELECT reason || ':' || success FROM login_attempts WHERE tenant_id = $1 \
         ORDER BY created_at DESC LIMIT 1",
    )
    .await;
    assert_eq!(latest, "risk_blocked:false");
}

#[tokio::test]
async fn thresholds_of_zero_switch_an_outcome_off() {
    // Never block, however high the score.
    let fx = fixture(RiskPolicy {
        block_at: 0,
        ..policy()
    })
    .await;
    let (status, _) = sign_in(&client(), &fx, Some(LONDON), "ada").await;
    assert_eq!(status, 200);
    let (status, body) = sign_in(&client(), &fx, Some(SYDNEY), "ada").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["stage"], "mfa", "the step-up still applies");

    // Never step up either: the score is recorded nowhere and the sign-in
    // runs to the end.
    let fx = fixture(RiskPolicy {
        step_up_at: 0,
        block_at: 0,
        ..policy()
    })
    .await;
    let (status, _) = sign_in(&client(), &fx, Some(LONDON), "ada").await;
    assert_eq!(status, 200);
    let (status, body) = sign_in(&client(), &fx, Some(SYDNEY), "ada").await;
    assert_eq!(status, 200);
    assert_eq!(body["stage"], "done", "{body}");
    assert!(audit(&fx.app, "risk.step_up").await.is_empty());
}

#[tokio::test]
async fn a_geo_header_from_an_untrusted_peer_is_ignored() {
    // The same policy, but nothing is a trusted proxy: the headers a client
    // sends about itself say nothing, so no location signal can fire.
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let settings = TenantSettings {
        risk: policy(),
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
    let fx = Fx { app, settings };
    user(&fx, "ada").await;

    let (status, _) = sign_in(&client(), &fx, Some(LONDON), "ada").await;
    assert_eq!(status, 200);
    let (status, body) = sign_in(&client(), &fx, Some(SYDNEY), "ada").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["stage"], "done", "no country was ever believed");
    let seen: i64 = scalar(
        &fx.app,
        "SELECT count(*) FROM user_login_locations WHERE tenant_id = $1",
    )
    .await;
    assert_eq!(seen, 0);
}

#[tokio::test]
async fn a_resumed_session_from_a_new_country_steps_up() {
    let fx = fixture(RiskPolicy {
        weights: RiskWeights {
            new_device: 0,
            ..policy().weights
        },
        impossible_travel_kmh: 0,
        ..policy()
    })
    .await;
    // One browser, signed in from London and holding its session cookie.
    let http = client();
    let (status, body) = sign_in(&http, &fx, Some(LONDON), "ada").await;
    assert_eq!(status, 200);
    assert_eq!(body["stage"], "done");

    // The same browser at /authorize again, now reported from Sydney: the
    // session is not enough any more.
    let loc = authorize(&http, &fx, Some(SYDNEY)).await;
    assert!(loc.path().ends_with("/mfa/"), "{loc}");
    let id: Uuid = param(&loc, "flow").expect("a flow").parse().unwrap();
    assert_eq!(get_flow(&http, &fx, id).await["stage"], "mfa");

    // From London it still resumes silently.
    let loc = authorize(&http, &fx, Some(LONDON)).await;
    assert!(
        loc.as_str().starts_with("https://app.example/cb"),
        "{loc}: straight back to the client"
    );
}

#[tokio::test]
async fn a_resumed_session_the_policy_blocks_cannot_be_used() {
    let fx = fixture(policy()).await;
    let http = client();
    let (status, _) = sign_in(&http, &fx, Some(LONDON), "ada").await;
    assert_eq!(status, 200);

    // Impossible travel plus a new country on the session's next use: the
    // client is told `access_denied` rather than shown a step to pass.
    let loc = authorize(&http, &fx, Some(SYDNEY)).await;
    assert!(loc.as_str().starts_with("https://app.example/cb"), "{loc}");
    assert_eq!(param(&loc, "error").as_deref(), Some("access_denied"));
    assert_eq!(audit(&fx.app, "risk.blocked").await.len(), 1);
}
