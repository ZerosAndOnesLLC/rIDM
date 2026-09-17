//! Phase 9.11: the findings the OpenID Foundation conformance suite raised
//! against rIDM (`conformance/`), each pinned by a test.
//!
//! * `oidcc-refresh-token`: the ID token minted from a refresh token repeats
//!   the original `auth_time`, `amr` and `acr` (OIDC Core §12.2).
//! * `oidcc-codereuse`: replaying an authorization code revokes everything it
//!   produced, the access token included (RFC 6749 §4.1.2).
//! * `oidcc-ensure-request-with-acr-values-succeeds`: a request that carries
//!   `acr_values` gets an `acr` claim back, and discovery names the classes.
//! * `oidcc-scope-email` and friends: the scope-derived standard claims are
//!   read from the userinfo endpoint, not carried in the ID token unless the
//!   client asks for them (OIDC Core §5.4).

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::TestApp;
use ridm_api::models::{ClientType, NewClient, NewUser, TenantSettings};
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::{clients, flows, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PASSWORD: &str = "correct-horse-battery";
const REDIRECT: &str = "https://app.example/cb";

struct Fx {
    app: TestApp,
}

/// A tenant with one confidential client (`rp`) and one signed-up user.
async fn fixture() -> Fx {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("rp".into()),
            name: "Relying Party".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec![REDIRECT.into()],
            allowed_scopes: Some(vec![
                "openid".into(),
                "profile".into(),
                "email".into(),
                "offline_access".into(),
            ]),
            require_consent: Some(false),
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
        &TenantSettings::default().password,
        Actor::System,
        user.id,
        PASSWORD.to_string().into(),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();
    Fx { app }
}

fn browser() -> reqwest::Client {
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

/// Sign in through the flow API and return the authorization code.
async fn sign_in(http: &reqwest::Client, fx: &Fx, scope: &str, extra: &[(&str, &str)]) -> String {
    sign_in_as(http, fx, "rp", scope, extra).await
}

async fn sign_in_as(
    http: &reqwest::Client,
    fx: &Fx,
    client_id: &str,
    scope: &str,
    extra: &[(&str, &str)],
) -> String {
    let mut q = vec![
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", REDIRECT),
        ("scope", scope),
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
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let id: Uuid = param(&loc, "flow").expect("a login flow").parse().unwrap();

    let state: Value = http
        .get(fx.app.tenant_url(&format!("/flows/{id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let res = http
        .post(fx.app.tenant_url(&format!("/flows/{id}/password")))
        .json(&json!({
            "csrf": state["csrf"].as_str().unwrap(),
            "identifier": "alice",
            "password": PASSWORD,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let after: Value = res.json().await.unwrap();
    assert_eq!(after["stage"], "done", "{after}");

    let res = http
        .get(after["finish_url"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    param(&loc, "code").expect("code on the callback")
}

async fn exchange(fx: &Fx, code: &str) -> Value {
    exchange_as(fx, "rp", code).await
}

async fn exchange_as(fx: &Fx, client_id: &str, code: &str) -> Value {
    fx.app
        .http
        .post(fx.app.tenant_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn claims(jwt: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

async fn userinfo(fx: &Fx, access_token: &str) -> Value {
    fx.app
        .http
        .get(fx.app.tenant_url("/userinfo"))
        .bearer_auth(access_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// OIDC Core §12.2: the refreshed ID token repeats the authentication context.
#[tokio::test]
async fn refreshed_id_token_repeats_the_authentication_context() {
    let fx = fixture().await;
    let http = browser();
    let code = sign_in(&http, &fx, "openid offline_access", &[]).await;
    let first = exchange(&fx, &code).await;
    let before = claims(first["id_token"].as_str().expect("id_token"));
    assert!(before["auth_time"].is_number(), "{before}");
    assert_eq!(before["amr"], json!(["pwd"]));
    assert_eq!(before["acr"], flows::ACR_SINGLE);

    let refreshed: Value = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "rp"),
            (
                "refresh_token",
                first["refresh_token"].as_str().expect("refresh_token"),
            ),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let after = claims(refreshed["id_token"].as_str().expect("id_token"));
    assert_eq!(after["auth_time"], before["auth_time"], "{after}");
    assert_eq!(after["amr"], before["amr"]);
    assert_eq!(after["acr"], before["acr"]);
    assert_eq!(after["sub"], before["sub"]);
}

/// RFC 6749 §4.1.2: replaying a code revokes what the first exchange produced,
/// the access token (a JWT, stopped through the `jti` denylist) included.
#[tokio::test]
async fn replaying_a_code_revokes_its_access_and_refresh_tokens() {
    let fx = fixture().await;
    let http = browser();
    let code = sign_in(&http, &fx, "openid offline_access", &[]).await;
    let first = exchange(&fx, &code).await;
    let access = first["access_token"].as_str().unwrap().to_string();
    let refresh = first["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(
        fx.app
            .http
            .get(fx.app.tenant_url("/userinfo"))
            .bearer_auth(&access)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // The replay itself is refused...
    let replay = exchange(&fx, &code).await;
    assert_eq!(replay["error"], "invalid_grant", "{replay}");

    // ...and neither token survives it.
    assert_eq!(
        fx.app
            .http
            .get(fx.app.tenant_url("/userinfo"))
            .bearer_auth(&access)
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "the access token issued from the replayed code still works"
    );
    let refreshed: Value = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "rp"),
            ("refresh_token", refresh.as_str()),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(refreshed["error"], "invalid_grant", "{refreshed}");
}

/// A request carrying `acr_values` gets an `acr` claim back (OIDC Core
/// §3.1.2.1), and discovery names the classes a session can reach.
#[tokio::test]
async fn acr_is_reported_and_advertised() {
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
        doc["acr_values_supported"],
        json!([flows::ACR_SINGLE, flows::ACR_MFA])
    );

    let http = browser();
    let code = sign_in(&http, &fx, "openid", &[("acr_values", "urn:example:gold")]).await;
    let tokens = exchange(&fx, &code).await;
    let id = claims(tokens["id_token"].as_str().expect("id_token"));
    // A class rIDM cannot assert is voluntary: the session reports its own.
    assert_eq!(id["acr"], flows::ACR_SINGLE, "{id}");
}

/// OIDC Core §5.4: with an access token issued, the scope-derived claims are
/// read from the userinfo endpoint. A client may ask for them in the ID token.
#[tokio::test]
async fn scope_claims_live_at_userinfo_unless_the_client_opts_in() {
    let fx = fixture().await;
    let http = browser();
    let code = sign_in(&http, &fx, "openid profile email", &[]).await;
    let tokens = exchange(&fx, &code).await;
    let id = claims(tokens["id_token"].as_str().expect("id_token"));
    for claim in ["email", "email_verified", "preferred_username"] {
        assert!(id.get(claim).is_none(), "id_token carries {claim}: {id}");
    }
    let info = userinfo(&fx, tokens["access_token"].as_str().unwrap()).await;
    assert_eq!(info["email"], "alice@example.com", "{info}");
    assert_eq!(info["preferred_username"], "alice");

    // A client that opted in gets them in the ID token as well.
    clients::create(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("rp2".into()),
            name: "Opted In".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec![REDIRECT.into()],
            allowed_scopes: Some(vec!["openid".into(), "profile".into(), "email".into()]),
            require_consent: Some(false),
            id_token_scope_claims: Some(true),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let http = browser();
    let code = sign_in_as(&http, &fx, "rp2", "openid profile email", &[]).await;
    let tokens = exchange_as(&fx, "rp2", &code).await;
    let id = claims(tokens["id_token"].as_str().expect("id_token"));
    assert_eq!(id["email"], "alice@example.com", "{id}");
    assert_eq!(id["preferred_username"], "alice");
}
