//! Phase 8.3: signing in through upstream providers. A mock OpenID
//! provider (discovery, authorize, token, JWKS, userinfo) and a GitHub-like
//! OAuth 2.0 provider are mounted into the test app; the tests drive the
//! browser's part with a cookie jar and no automatic redirects.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::{Form, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::Utc;
use common::TestApp;
use common::admin::{admin_token, call};
use jsonwebtoken::EncodingKey;
use reqwest::Method;
use ridm_api::models::{
    AttributeDef, ClientType, IdpAuthMethod, IdpKind, IdpMappers, LinkPolicy, NewClient,
    NewIdentityProvider, NewUser, ProfileSchema, RsaBits, SigningAlg,
};
use ridm_api::services::account_console::{ACCOUNT_AUDIENCE, ACCOUNT_CLIENT_ID};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::tokens::{self, AccessTokenRequest, TokenClient};
use ridm_api::services::{
    broker, clients, identity_providers, keys, login_flows, profile_schema, users,
};
use ridm_api::state::AppState;
use ridm_core::events::Actor;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const CLIENT_ID: &str = "ridm-test";
const CLIENT_SECRET: &str = "s3cret-s3cret";

// ---------------------------------------------------------------------------
// The mock providers
// ---------------------------------------------------------------------------

struct CodeRec {
    nonce: Option<String>,
    challenge: Option<String>,
    redirect_uri: String,
}

struct Mock {
    /// `{app base}/mock`, known once the app has a port.
    base: Mutex<String>,
    kid: String,
    public_jwk: Value,
    key: EncodingKey,
    /// Claims of the next ID token (`sub`, `email`, ...).
    claims: Mutex<Value>,
    /// The userinfo document.
    userinfo: Mutex<Value>,
    /// GitHub-like `/user/emails`.
    emails: Mutex<Value>,
    deny: AtomicBool,
    wrong_nonce: AtomicBool,
    wrong_issuer: AtomicBool,
    codes: Mutex<HashMap<String, CodeRec>>,
    /// Query parameters of the last authorization request.
    last_authorize: Mutex<HashMap<String, String>>,
    /// Form fields of the last token request.
    last_token: Mutex<HashMap<String, String>>,
    token_requests: Mutex<u32>,
}

impl Mock {
    fn new() -> Arc<Self> {
        let pair = keys::generate(SigningAlg::ES256, RsaBits::B2048).unwrap();
        let key = tokens::encoding_key_from_der(SigningAlg::ES256, &pair.private_der).unwrap();
        Arc::new(Self {
            base: Mutex::new(String::new()),
            kid: pair.kid.clone(),
            public_jwk: pair.public_jwk.clone(),
            key,
            claims: Mutex::new(
                json!({"sub": "upstream-1", "email": "alice@upstream.example", "email_verified": true, "preferred_username": "alice", "given_name": "Alice"}),
            ),
            userinfo: Mutex::new(json!({})),
            emails: Mutex::new(json!([])),
            deny: AtomicBool::new(false),
            wrong_nonce: AtomicBool::new(false),
            wrong_issuer: AtomicBool::new(false),
            codes: Mutex::new(HashMap::new()),
            last_authorize: Mutex::new(HashMap::new()),
            last_token: Mutex::new(HashMap::new()),
            token_requests: Mutex::new(0),
        })
    }

    fn base(&self) -> String {
        self.base.lock().unwrap().clone()
    }

    fn set_claims(&self, v: Value) {
        *self.claims.lock().unwrap() = v;
    }

    fn authorize(&self, q: HashMap<String, String>, with_nonce: bool) -> axum::response::Response {
        *self.last_authorize.lock().unwrap() = q.clone();
        let redirect_uri = q.get("redirect_uri").cloned().unwrap_or_default();
        let state = q.get("state").cloned().unwrap_or_default();
        let mut u = url::Url::parse(&redirect_uri).unwrap();
        if self.deny.load(Ordering::SeqCst) {
            u.query_pairs_mut()
                .append_pair("error", "access_denied")
                .append_pair("state", &state);
            return Redirect::to(u.as_str()).into_response();
        }
        let code = Uuid::new_v4().simple().to_string();
        self.codes.lock().unwrap().insert(
            code.clone(),
            CodeRec {
                nonce: if with_nonce {
                    q.get("nonce").cloned()
                } else {
                    None
                },
                challenge: q.get("code_challenge").cloned(),
                redirect_uri: redirect_uri.clone(),
            },
        );
        u.query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", &state);
        Redirect::to(u.as_str()).into_response()
    }

    /// Check client auth (basic or post), the code, redirect URI and PKCE.
    fn token(
        &self,
        headers: &HeaderMap,
        form: HashMap<String, String>,
        oidc: bool,
    ) -> axum::response::Response {
        *self.last_token.lock().unwrap() = form.clone();
        *self.token_requests.lock().unwrap() += 1;
        let basic = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Basic "))
            .and_then(|b| STANDARD.decode(b).ok())
            .and_then(|b| String::from_utf8(b).ok());
        let authed = basic.as_deref() == Some(&format!("{CLIENT_ID}:{CLIENT_SECRET}"))
            || (form.get("client_id").map(String::as_str) == Some(CLIENT_ID)
                && form.get("client_secret").map(String::as_str) == Some(CLIENT_SECRET));
        if !authed {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({"error": "invalid_client"})),
            )
                .into_response();
        }
        let code = form.get("code").cloned().unwrap_or_default();
        let Some(rec) = self.codes.lock().unwrap().remove(&code) else {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"error": "invalid_grant"})),
            )
                .into_response();
        };
        if form.get("redirect_uri") != Some(&rec.redirect_uri) {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"error": "invalid_grant", "error_description": "redirect_uri"})),
            )
                .into_response();
        }
        if let Some(ch) = &rec.challenge {
            let verifier = form.get("code_verifier").cloned().unwrap_or_default();
            let expect = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            if &expect != ch {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({"error": "invalid_grant", "error_description": "pkce"})),
                )
                    .into_response();
            }
        }
        let access_token = format!("at-{code}");
        if !oidc {
            return axum::Json(json!({"access_token": access_token, "token_type": "bearer"}))
                .into_response();
        }
        let now = Utc::now().timestamp();
        let mut claims = self.claims.lock().unwrap().clone();
        let issuer = if self.wrong_issuer.load(Ordering::SeqCst) {
            "https://evil.example".to_string()
        } else {
            self.base()
        };
        claims["iss"] = json!(issuer);
        claims["aud"] = json!(CLIENT_ID);
        claims["iat"] = json!(now);
        claims["exp"] = json!(now + 300);
        if let Some(n) = rec.nonce {
            claims["nonce"] = json!(if self.wrong_nonce.load(Ordering::SeqCst) {
                "bad".to_string()
            } else {
                n
            });
        }
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        let id_token = jsonwebtoken::encode(&header, &claims, &self.key).unwrap();
        axum::Json(
            json!({"access_token": access_token, "id_token": id_token, "token_type": "bearer"}),
        )
        .into_response()
    }
}

fn bearer_ok(headers: &HeaderMap) -> bool {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("Bearer at-"))
}

fn mock_router(mock: Arc<Mock>) -> Router<AppState> {
    let m = mock.clone();
    let discovery = move || {
        let m = m.clone();
        async move {
            let b = m.base();
            axum::Json(json!({
                "issuer": b,
                "authorization_endpoint": format!("{b}/authorize"),
                "token_endpoint": format!("{b}/token"),
                "userinfo_endpoint": format!("{b}/userinfo"),
                "jwks_uri": format!("{b}/jwks"),
                "scopes_supported": ["openid", "email", "profile"],
            }))
        }
    };
    let m = mock.clone();
    let authorize = move |Query(q): Query<HashMap<String, String>>| {
        let m = m.clone();
        async move { m.authorize(q, true) }
    };
    let m = mock.clone();
    let token = move |headers: HeaderMap, Form(form): Form<HashMap<String, String>>| {
        let m = m.clone();
        async move { m.token(&headers, form, true) }
    };
    let m = mock.clone();
    let jwks = move || {
        let m = m.clone();
        async move { axum::Json(json!({"keys": [m.public_jwk.clone()]})) }
    };
    let m = mock.clone();
    let userinfo = move |headers: HeaderMap| {
        let m = m.clone();
        async move {
            if !bearer_ok(&headers) {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            axum::Json(m.userinfo.lock().unwrap().clone()).into_response()
        }
    };
    // GitHub-like: no ID token, identity from `/user` and `/user/emails`.
    let m = mock.clone();
    let gh_authorize = move |Query(q): Query<HashMap<String, String>>| {
        let m = m.clone();
        async move { m.authorize(q, false) }
    };
    let m = mock.clone();
    let gh_token = move |headers: HeaderMap, Form(form): Form<HashMap<String, String>>| {
        let m = m.clone();
        async move { m.token(&headers, form, false) }
    };
    let m = mock.clone();
    let gh_user = move |headers: HeaderMap| {
        let m = m.clone();
        async move {
            if !bearer_ok(&headers) {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            axum::Json(m.userinfo.lock().unwrap().clone()).into_response()
        }
    };
    let m = mock.clone();
    let gh_emails = move |headers: HeaderMap| {
        let m = m.clone();
        async move {
            if !bearer_ok(&headers) {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            axum::Json(m.emails.lock().unwrap().clone()).into_response()
        }
    };
    Router::new()
        .route("/mock/.well-known/openid-configuration", get(discovery))
        .route("/mock/authorize", get(authorize))
        .route("/mock/token", post(token))
        .route("/mock/jwks", get(jwks))
        .route("/mock/userinfo", get(userinfo))
        .route("/mock/gh/authorize", get(gh_authorize))
        .route("/mock/gh/token", post(gh_token))
        .route("/mock/gh/user", get(gh_user))
        .route("/mock/gh/user/emails", get(gh_emails))
}

// ---------------------------------------------------------------------------
// Fixture and drivers
// ---------------------------------------------------------------------------

struct Fx {
    app: TestApp,
    mock: Arc<Mock>,
}

async fn fixture() -> Fx {
    let mock = Mock::new();
    let app = TestApp::spawn_with(mock_router(mock.clone())).await;
    *mock.base.lock().unwrap() = app.url("/mock");
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
    Fx { app, mock }
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

/// An OIDC provider pointing at the mock.
async fn oidc_idp(fx: &Fx, alias: &str, policy: LinkPolicy, mappers: Option<IdpMappers>) -> Uuid {
    let b = fx.mock.base();
    identity_providers::create(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        NewIdentityProvider {
            alias: alias.into(),
            kind: Some(IdpKind::Oidc),
            display_name: Some("Mock ID".into()),
            issuer: Some(b.clone()),
            authorization_endpoint: Some(format!("{b}/authorize")),
            token_endpoint: Some(format!("{b}/token")),
            userinfo_endpoint: Some(format!("{b}/userinfo")),
            jwks_uri: Some(format!("{b}/jwks")),
            client_id: CLIENT_ID.into(),
            client_secret: Some(CLIENT_SECRET.into()),
            link_policy: Some(policy),
            mappers,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .id
}

/// A login flow at its first step.
async fn start_flow(http: &reqwest::Client, fx: &Fx) -> Uuid {
    let res = http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "openid profile"),
            ("state", "st"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let u = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    param(&u, "flow").unwrap().parse().unwrap()
}

fn location(res: &reqwest::Response) -> url::Url {
    url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap()
}

/// Drive a brokered sign-in: start → provider → callback. Returns the
/// callback's answer (a redirect to the UI, or an error).
async fn broker_round_trip(http: &reqwest::Client, fx: &Fx, start_url: &str) -> reqwest::Response {
    let res = http.get(start_url).send().await.unwrap();
    assert_eq!(
        res.status(),
        303,
        "start redirects to the provider: {}",
        res.text().await.unwrap()
    );
    let to_provider = location(&res);
    assert!(
        to_provider.as_str().starts_with(&fx.mock.base()),
        "{to_provider}"
    );
    let res = http.get(to_provider).send().await.unwrap();
    assert_eq!(res.status(), 303, "the provider redirects back");
    let to_callback = location(&res);
    assert!(to_callback.path().ends_with("/callback"), "{to_callback}");
    http.get(to_callback).send().await.unwrap()
}

async fn login_via(http: &reqwest::Client, fx: &Fx, alias: &str, flow: Uuid) -> reqwest::Response {
    let start = fx
        .app
        .tenant_url(&format!("/broker/{alias}/start?flow={flow}"));
    broker_round_trip(http, fx, &start).await
}

async fn flow_state(fx: &Fx, id: Uuid) -> login_flows::LoginFlow {
    login_flows::get(&fx.app.state, fx.app.tenant.id, id)
        .await
        .unwrap()
        .expect("flow exists")
}

async fn user_count(fx: &Fx) -> i64 {
    let mut tx = ridm_api::db::tenant_tx(&fx.app.state.db, fx.app.tenant.id)
        .await
        .unwrap();
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM users WHERE tenant_id = $1 AND deleted_at IS NULL",
    )
    .bind(fx.app.tenant.id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    n
}

// ---------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_first_sign_in_creates_and_links_the_user_and_later_ones_reuse_it() {
    let fx = fixture().await;
    profile_schema::set(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        ProfileSchema {
            attributes: vec![AttributeDef {
                name: "first_name".into(),
                ..Default::default()
            }],
            allow_undeclared: false,
        },
    )
    .await
    .unwrap();
    let mut mappers = IdpMappers::default();
    mappers
        .attributes
        .insert("first_name".into(), "given_name".into());
    let idp = oidc_idp(&fx, "mock", LinkPolicy::VerifiedEmail, Some(mappers)).await;
    let before = user_count(&fx).await;

    let http = client();
    let flow = start_flow(&http, &fx).await;
    let res = login_via(&http, &fx, "mock", flow).await;
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    let to_ui = location(&res);
    assert!(to_ui.path().ends_with("/login/"), "{to_ui}");
    assert_eq!(
        param(&to_ui, "flow").as_deref(),
        Some(flow.to_string().as_str())
    );
    assert!(
        res.headers()
            .get_all("set-cookie")
            .iter()
            .any(|c| c.to_str().unwrap().contains("ridm_session=")),
        "the session cookie is set on the callback"
    );

    let f = flow_state(&fx, flow).await;
    assert_eq!(
        f.stage,
        login_flows::FlowStage::Done,
        "no consent needed: done"
    );
    assert_eq!(f.amr, ["fed"]);
    let user = users::get(&fx.app.state, fx.app.tenant.id, f.user_id.unwrap())
        .await
        .unwrap();
    assert_eq!(user.username, "alice");
    assert_eq!(user.email.as_deref(), Some("alice@upstream.example"));
    assert!(user.email_verified);
    assert_eq!(user.attributes["first_name"], "Alice", "mapped on creation");
    assert_eq!(user_count(&fx).await, before + 1);
    let links = broker::identities_of(&fx.app.state, fx.app.tenant.id, user.id)
        .await
        .unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].idp_id, idp);
    assert_eq!(links[0].alias, "mock");
    assert_eq!(links[0].external_subject, "upstream-1");
    assert!(links[0].last_login_at.is_some());

    // The authorization request carried PKCE and a nonce, the token
    // request the verifier and basic auth.
    let a = fx.mock.last_authorize.lock().unwrap().clone();
    assert_eq!(a["response_type"], "code");
    assert_eq!(a["client_id"], CLIENT_ID);
    assert_eq!(a["code_challenge_method"], "S256");
    assert!(a.contains_key("nonce"));
    assert_eq!(a["scope"], "openid email profile");
    let t = fx.mock.last_token.lock().unwrap().clone();
    assert!(t.contains_key("code_verifier"));
    assert!(!t.contains_key("client_secret"), "basic auth by default");

    // Signing in again, with a changed name upstream, reuses the account
    // and refreshes the mapped attribute.
    fx.mock.set_claims(json!({"sub": "upstream-1", "email": "alice@upstream.example", "email_verified": true, "preferred_username": "alice", "given_name": "Alicia"}));
    let http2 = client();
    let flow2 = start_flow(&http2, &fx).await;
    let res = login_via(&http2, &fx, "mock", flow2).await;
    assert_eq!(res.status(), 303);
    let f2 = flow_state(&fx, flow2).await;
    assert_eq!(f2.user_id, Some(user.id));
    assert_eq!(user_count(&fx).await, before + 1, "no second account");
    let again = users::get(&fx.app.state, fx.app.tenant.id, user.id)
        .await
        .unwrap();
    assert_eq!(again.attributes["first_name"], "Alicia");
}

#[tokio::test]
async fn verified_email_links_an_existing_account_only_when_both_sides_verified() {
    let fx = fixture().await;
    oidc_idp(&fx, "mock", LinkPolicy::VerifiedEmail, None).await;
    let tid = fx.app.tenant.id;
    let bob = users::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewUser {
            username: "bob".into(),
            email: Some("bob@example.com".into()),
            email_verified: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    users::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewUser {
            username: "carol".into(),
            email: Some("carol@example.com".into()),
            email_verified: false,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let before = user_count(&fx).await;

    // Bob: verified on both sides, linked.
    fx.mock
        .set_claims(json!({"sub": "up-bob", "email": "Bob@Example.com", "email_verified": true}));
    let http = client();
    let flow = start_flow(&http, &fx).await;
    let res = login_via(&http, &fx, "mock", flow).await;
    assert_eq!(res.status(), 303);
    assert_eq!(flow_state(&fx, flow).await.user_id, Some(bob.id));
    assert_eq!(user_count(&fx).await, before);

    // Carol: the local address is not verified, so no link.
    fx.mock.set_claims(
        json!({"sub": "up-carol", "email": "carol@example.com", "email_verified": true}),
    );
    let http = client();
    let flow = start_flow(&http, &fx).await;
    let res = login_via(&http, &fx, "mock", flow).await;
    assert_eq!(res.status(), 303);
    let to_ui = location(&res);
    assert_eq!(
        param(&to_ui, "broker_error").as_deref(),
        Some("email_in_use")
    );
    assert_eq!(param(&to_ui, "provider").as_deref(), Some("mock"));
    assert_eq!(flow_state(&fx, flow).await.user_id, None);
    assert_eq!(user_count(&fx).await, before);

    // Dave: upstream says the address is unverified, the local one is: no link either.
    users::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewUser {
            username: "dave".into(),
            email: Some("dave@example.com".into()),
            email_verified: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    fx.mock.set_claims(
        json!({"sub": "up-dave", "email": "dave@example.com", "email_verified": false}),
    );
    let http = client();
    let flow = start_flow(&http, &fx).await;
    let res = login_via(&http, &fx, "mock", flow).await;
    assert_eq!(
        param(&location(&res), "broker_error").as_deref(),
        Some("email_in_use")
    );
}

#[tokio::test]
async fn explicit_and_always_new_policies() {
    let fx = fixture().await;
    let tid = fx.app.tenant.id;
    oidc_idp(&fx, "strict", LinkPolicy::Explicit, None).await;
    let b = fx.mock.base();
    identity_providers::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewIdentityProvider {
            alias: "fresh".into(),
            kind: Some(IdpKind::Oidc),
            display_name: Some("Fresh".into()),
            issuer: Some(b.clone()),
            authorization_endpoint: Some(format!("{b}/authorize")),
            token_endpoint: Some(format!("{b}/token")),
            jwks_uri: Some(format!("{b}/jwks")),
            client_id: CLIENT_ID.into(),
            client_secret: Some(CLIENT_SECRET.into()),
            link_policy: Some(LinkPolicy::AlwaysNew),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    users::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewUser {
            username: "erin".into(),
            email: Some("erin@example.com".into()),
            email_verified: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let before = user_count(&fx).await;
    fx.mock.set_claims(json!({"sub": "up-erin", "email": "erin@example.com", "email_verified": true, "preferred_username": "erin"}));

    let http = client();
    let flow = start_flow(&http, &fx).await;
    let res = login_via(&http, &fx, "strict", flow).await;
    assert_eq!(
        param(&location(&res), "broker_error").as_deref(),
        Some("email_in_use")
    );
    assert_eq!(user_count(&fx).await, before);

    let http = client();
    let flow = start_flow(&http, &fx).await;
    let res = login_via(&http, &fx, "fresh", flow).await;
    assert_eq!(res.status(), 303);
    assert!(param(&location(&res), "broker_error").is_none());
    let f = flow_state(&fx, flow).await;
    let u = users::get(&fx.app.state, tid, f.user_id.unwrap())
        .await
        .unwrap();
    assert_ne!(u.username, "erin", "a new account with a free name");
    assert!(
        u.username.starts_with("erin-") || u.username.starts_with("fresh-"),
        "{}",
        u.username
    );
    assert!(u.email.is_none(), "the address belongs to another account");
    assert_eq!(user_count(&fx).await, before + 1);
}

#[tokio::test]
async fn state_nonce_issuer_and_refusals_are_checked() {
    let fx = fixture().await;
    oidc_idp(&fx, "mock", LinkPolicy::VerifiedEmail, None).await;

    // A callback with an unknown state is refused outright.
    let http = client();
    let res = http
        .get(fx.app.tenant_url("/broker/mock/callback?code=x&state=nope"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_state");

    // A state works once: replaying the callback is refused.
    let flow = start_flow(&http, &fx).await;
    let start = fx
        .app
        .tenant_url(&format!("/broker/mock/start?flow={flow}"));
    let res = http.get(&start).send().await.unwrap();
    let res = http.get(location(&res)).send().await.unwrap();
    let callback = location(&res);
    let res = http.get(callback.clone()).send().await.unwrap();
    assert_eq!(res.status(), 303);
    let res = http.get(callback).send().await.unwrap();
    assert_eq!(res.status(), 400);

    // The user refusing at the provider.
    fx.mock.deny.store(true, Ordering::SeqCst);
    let http = client();
    let flow = start_flow(&http, &fx).await;
    let res = login_via(&http, &fx, "mock", flow).await;
    assert_eq!(
        param(&location(&res), "broker_error").as_deref(),
        Some("denied")
    );
    assert_eq!(flow_state(&fx, flow).await.user_id, None);
    fx.mock.deny.store(false, Ordering::SeqCst);

    // A nonce that does not match the one sent.
    fx.mock.wrong_nonce.store(true, Ordering::SeqCst);
    let http = client();
    let flow = start_flow(&http, &fx).await;
    let res = login_via(&http, &fx, "mock", flow).await;
    assert_eq!(
        param(&location(&res), "broker_error").as_deref(),
        Some("upstream")
    );
    assert_eq!(flow_state(&fx, flow).await.user_id, None);
    fx.mock.wrong_nonce.store(false, Ordering::SeqCst);

    // An ID token from another issuer.
    fx.mock.wrong_issuer.store(true, Ordering::SeqCst);
    let http = client();
    let flow = start_flow(&http, &fx).await;
    let res = login_via(&http, &fx, "mock", flow).await;
    assert_eq!(
        param(&location(&res), "broker_error").as_deref(),
        Some("upstream")
    );
    fx.mock.wrong_issuer.store(false, Ordering::SeqCst);

    // A flow past its first step does not accept a provider sign-in.
    let http = client();
    let flow = start_flow(&http, &fx).await;
    let res = login_via(&http, &fx, "mock", flow).await;
    assert_eq!(res.status(), 303);
    let res = http
        .get(
            fx.app
                .tenant_url(&format!("/broker/mock/start?flow={flow}")),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);

    // Unknown or disabled providers are not found.
    let res = http
        .get(
            fx.app
                .tenant_url(&format!("/broker/nope/start?flow={flow}")),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test]
async fn a_first_sign_in_completes_the_profile_when_the_schema_requires_it() {
    let fx = fixture().await;
    profile_schema::set(
        &fx.app.state,
        fx.app.tenant.id,
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
    oidc_idp(&fx, "mock", LinkPolicy::VerifiedEmail, None).await;
    let http = client();
    let flow = start_flow(&http, &fx).await;
    let res = login_via(&http, &fx, "mock", flow).await;
    assert_eq!(res.status(), 303);
    let to_ui = location(&res);
    assert!(
        to_ui.path().ends_with("/login/"),
        "the login page hosts the profile step: {to_ui}"
    );
    let f = flow_state(&fx, flow).await;
    assert_eq!(f.stage, login_flows::FlowStage::Profile);
    assert!(
        f.user_id.is_some(),
        "the account exists; only its profile is incomplete"
    );
    // The public state names the missing attribute for the page.
    let state: Value = http
        .get(fx.app.tenant_url(&format!("/flows/{flow}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(state["stage"], "profile");
    assert_eq!(state["missing_attributes"][0]["name"], "department");
}

#[tokio::test]
async fn an_oauth2_provider_takes_the_identity_from_userinfo() {
    let fx = fixture().await;
    let b = fx.mock.base();
    identity_providers::create(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        NewIdentityProvider {
            alias: "gh".into(),
            preset: Some("github".into()),
            authorization_endpoint: Some(format!("{b}/gh/authorize")),
            token_endpoint: Some(format!("{b}/gh/token")),
            userinfo_endpoint: Some(format!("{b}/gh/user")),
            client_id: CLIENT_ID.into(),
            client_secret: Some(CLIENT_SECRET.into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    *fx.mock.userinfo.lock().unwrap() =
        json!({"id": 4242, "login": "octo", "name": "Octo Cat", "email": null});
    *fx.mock.emails.lock().unwrap() = json!([
        {"email": "old@example.com", "primary": false, "verified": true},
        {"email": "octo@example.com", "primary": true, "verified": true}
    ]);
    let http = client();
    let flow = start_flow(&http, &fx).await;
    let res = login_via(&http, &fx, "gh", flow).await;
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    let f = flow_state(&fx, flow).await;
    let u = users::get(&fx.app.state, fx.app.tenant.id, f.user_id.unwrap())
        .await
        .unwrap();
    assert_eq!(u.username, "octo");
    assert_eq!(
        u.email.as_deref(),
        Some("octo@example.com"),
        "the primary verified address"
    );
    assert!(u.email_verified);
    let links = broker::identities_of(&fx.app.state, fx.app.tenant.id, u.id)
        .await
        .unwrap();
    assert_eq!(
        links[0].external_subject, "4242",
        "the numeric id as the subject"
    );
    assert_eq!(links[0].external_username.as_deref(), Some("octo"));
    let a = fx.mock.last_authorize.lock().unwrap().clone();
    assert!(!a.contains_key("nonce"), "plain OAuth 2.0 has no nonce");
    let t = fx.mock.last_token.lock().unwrap().clone();
    assert_eq!(
        t.get("client_secret").map(String::as_str),
        Some(CLIENT_SECRET),
        "GitHub takes the secret in the body"
    );
}

#[tokio::test]
async fn the_login_page_lists_offered_providers() {
    let fx = fixture().await;
    let tid = fx.app.tenant.id;
    oidc_idp(&fx, "shown", LinkPolicy::VerifiedEmail, None).await;
    let hidden = oidc_idp(&fx, "hidden", LinkPolicy::VerifiedEmail, None).await;
    identity_providers::update(
        &fx.app.state,
        tid,
        Actor::System,
        &hidden.to_string(),
        ridm_api::models::IdentityProviderUpdate {
            hidden: Some(true),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let http = client();
    let flow = start_flow(&http, &fx).await;
    let state: Value = http
        .get(fx.app.tenant_url(&format!("/flows/{flow}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        state["identity_providers"],
        json!([{"alias": "shown", "display_name": "Mock ID", "preset": null}])
    );
    // A hidden provider still signs people in by direct link.
    let res = login_via(&http, &fx, "hidden", flow).await;
    assert_eq!(res.status(), 303);
    assert!(param(&location(&res), "broker_error").is_none());
}

// ---------------------------------------------------------------------------
// Account console: linking and unlinking
// ---------------------------------------------------------------------------

async fn account_token(fx: &Fx, user_id: Uuid) -> String {
    let tenant = ridm_api::services::tenants::get(&fx.app.state, fx.app.tenant.id)
        .await
        .unwrap();
    let user = users::get(&fx.app.state, tenant.id, user_id).await.unwrap();
    let session = sessions::create(
        &fx.app.state,
        tenant.id,
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
    let mut client = TokenClient::public(ACCOUNT_CLIENT_ID);
    client.access_token_ttl = Duration::from_secs(300);
    tokens::issue_access_token(
        &fx.app.state,
        AccessTokenRequest {
            tenant: &tenant,
            client: &client,
            user: Some(&user),
            scopes: &["openid".into()],
            audiences: &[ACCOUNT_AUDIENCE.to_string()],
            roles: &[],
            groups: &[],
            session_id: Some(session.id),
            auth_time: Some(Utc::now()),
            amr: &["pwd".into()],
            acr: None,
            cnf_jkt: None,
            act: None,
        },
    )
    .await
    .unwrap()
    .token
}

#[tokio::test]
async fn the_account_console_links_and_unlinks_identities() {
    let fx = fixture().await;
    let tid = fx.app.tenant.id;
    let idp = oidc_idp(&fx, "mock", LinkPolicy::Explicit, None).await;
    let frank = users::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewUser {
            username: "frank".into(),
            email: Some("frank@example.com".into()),
            email_verified: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let t = account_token(&fx, frank.id).await;
    let base = format!("/t/{}/account/identities", fx.app.tenant.slug);

    let (status, body, _) = call(&fx.app, Method::GET, &base, Some(&t), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["linked"], json!([]));
    assert_eq!(body["available"][0]["alias"], "mock");

    // Start linking: a ticket-bearing URL the browser takes to the broker.
    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &format!("{base}/link"),
        Some(&t),
        Some(&json!({"alias": "mock", "return_to": "/account/security/"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let start = body["url"].as_str().unwrap().to_string();
    assert!(start.contains("/broker/mock/start?ticket="), "{start}");
    fx.mock.set_claims(
        json!({"sub": "up-frank", "email": "frank-other@example.com", "email_verified": true}),
    );
    let http = client();
    let res = broker_round_trip(&http, &fx, &start).await;
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    let back = location(&res);
    assert!(back.path().ends_with("/account/security/"), "{back}");
    assert_eq!(param(&back, "linked").as_deref(), Some("1"));
    // The ticket worked once.
    let res = http.get(&start).send().await.unwrap();
    assert_eq!(res.status(), 404);

    let (_, body, _) = call(&fx.app, Method::GET, &base, Some(&t), None).await;
    assert_eq!(body["linked"][0]["alias"], "mock");
    assert_eq!(body["linked"][0]["external_subject"], "up-frank");
    assert_eq!(body["available"], json!([]));

    // Signing in through the provider now lands on Frank's account even
    // though the addresses differ (explicit policy, linked by hand).
    let http = client();
    let flow = start_flow(&http, &fx).await;
    let res = login_via(&http, &fx, "mock", flow).await;
    assert_eq!(res.status(), 303);
    assert_eq!(flow_state(&fx, flow).await.user_id, Some(frank.id));

    // Another user cannot take an identity that is already Frank's.
    let grace = users::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewUser {
            username: "grace".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let tg = account_token(&fx, grace.id).await;
    let (_, body, _) = call(
        &fx.app,
        Method::POST,
        &format!("{base}/link"),
        Some(&tg),
        Some(&json!({"alias": "mock"})),
    )
    .await;
    let res = broker_round_trip(&client(), &fx, body["url"].as_str().unwrap()).await;
    assert_eq!(
        param(&location(&res), "link_error").as_deref(),
        Some("already_linked")
    );

    // Unlink.
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("{base}/{idp}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (_, body, _) = call(&fx.app, Method::GET, &base, Some(&t), None).await;
    assert_eq!(body["linked"], json!([]));
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("{base}/{idp}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);
}

// ---------------------------------------------------------------------------
// Admin API
// ---------------------------------------------------------------------------

#[tokio::test]
async fn administrators_manage_providers_and_never_see_secrets() {
    let fx = fixture().await;
    let tid = fx.app.tenant.id;
    let t = admin_token(&fx.app, tid, "ridm:owner").await;
    let base = format!("/admin/tenants/{}/identity-providers", fx.app.tenant.slug);
    let b = fx.mock.base();

    let (status, body, _) = call(
        &fx.app,
        Method::GET,
        &format!("{base}/presets"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let names: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["google", "microsoft", "github", "apple", "gitlab"]);

    // Discovery previews an issuer's endpoints.
    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &format!("{base}/discover"),
        Some(&t),
        Some(&json!({"issuer": b})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["jwks_uri"], format!("{b}/jwks"));
    let (status, _, _) = call(
        &fx.app,
        Method::POST,
        &format!("{base}/discover"),
        Some(&t),
        Some(&json!({"issuer": "http://idp.example.com"})),
    )
    .await;
    assert_eq!(status, 400, "plain http beyond loopback");

    // Create from the issuer alone: the endpoints are discovered.
    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"alias": "Mock", "display_name": "Mock ID", "issuer": b, "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET})),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["alias"], "mock");
    assert_eq!(body["kind"], "oidc");
    assert_eq!(body["authorization_endpoint"], format!("{b}/authorize"));
    assert_eq!(body["scopes"], json!(["openid", "email", "profile"]));
    assert_eq!(body["client_secret_set"], true);
    assert_eq!(body["token_endpoint_auth_method"], "client_secret_basic");
    assert!(
        body.get("client_secret").is_none() && body.get("client_secret_enc").is_none(),
        "{body}"
    );
    assert_eq!(
        body["callback_url"],
        fx.app.tenant_url("/broker/mock/callback")
    );
    let id = body["id"].as_str().unwrap().to_string();

    let (status, _, _) = call(
        &fx.app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"alias": "mock", "issuer": b, "client_id": "x"})),
    )
    .await;
    assert_eq!(status, 409);
    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"alias": "bad alias", "issuer": b, "client_id": "x"})),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["errors"][0]["field"], "alias");
    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"alias": "nosecret", "issuer": b, "client_id": "x", "pkce": false})),
    )
    .await;
    assert_eq!(status, 400, "no secret and no PKCE: {body}");

    // Presets fill in the rest; a GitHub provider needs only its credentials.
    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"alias": "github", "preset": "github", "client_id": "gh", "client_secret": "gh-secret"})),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["kind"], "oauth2");
    assert_eq!(body["display_name"], "GitHub");
    assert_eq!(body["userinfo_endpoint"], "https://api.github.com/user");
    assert_eq!(body["mappers"]["subject"], "id");

    // By alias or id; patching; the secret cleared.
    let (status, body, _) = call(
        &fx.app,
        Method::GET,
        &format!("{base}/mock"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["id"], id);
    let (status, body, _) = call(
        &fx.app,
        Method::PATCH,
        &format!("{base}/{id}"),
        Some(&t),
        Some(&json!({"display_name": "Mock (renamed)", "link_policy": "explicit", "client_secret": null})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["display_name"], "Mock (renamed)");
    assert_eq!(body["link_policy"], "explicit");
    assert_eq!(body["client_secret_set"], false);
    let (_, body, _) = call(&fx.app, Method::GET, &base, Some(&t), None).await;
    assert_eq!(body.as_array().unwrap().len(), 2);

    // Confinement: another tenant sees nothing of it.
    let other = common::create_tenant(&fx.app.state.db).await;
    let t2 = admin_token(&fx.app, other.id, "ridm:owner").await;
    let (status, _, _) = call(
        &fx.app,
        Method::GET,
        &format!("/admin/tenants/{}/identity-providers/{id}", other.slug),
        Some(&t2),
        None,
    )
    .await;
    assert_eq!(status, 404);
    let (status, _, _) = call(&fx.app, Method::GET, &base, Some(&t2), None).await;
    assert_eq!(status, 403);

    // A user manager may not touch providers.
    let tm = admin_token(&fx.app, tid, "ridm:user-manager").await;
    let (status, _, _) = call(&fx.app, Method::GET, &base, Some(&tm), None).await;
    assert_eq!(status, 403);

    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("{base}/github"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = call(
        &fx.app,
        Method::GET,
        &format!("{base}/github"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn administrators_list_and_unlink_a_users_identities() {
    let fx = fixture().await;
    let tid = fx.app.tenant.id;
    let idp = oidc_idp(&fx, "mock", LinkPolicy::VerifiedEmail, None).await;
    let http = client();
    let flow = start_flow(&http, &fx).await;
    login_via(&http, &fx, "mock", flow).await;
    let user_id = flow_state(&fx, flow).await.user_id.unwrap();
    let t = admin_token(&fx.app, tid, "ridm:owner").await;
    let base = format!(
        "/admin/tenants/{}/users/{user_id}/identities",
        fx.app.tenant.slug
    );
    let (status, body, _) = call(&fx.app, Method::GET, &base, Some(&t), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body[0]["alias"], "mock");
    assert_eq!(body[0]["idp_id"], idp.to_string());
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("{base}/{idp}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (_, body, _) = call(&fx.app, Method::GET, &base, Some(&t), None).await;
    assert_eq!(body, json!([]));

    // Deleting the provider removes the links it made, not the users.
    let http = client();
    let flow = start_flow(&http, &fx).await;
    login_via(&http, &fx, "mock", flow).await;
    let (_, body, _) = call(&fx.app, Method::GET, &base, Some(&t), None).await;
    assert_eq!(
        body.as_array().unwrap().len(),
        1,
        "linked again on the next sign-in"
    );
    identity_providers::delete(&fx.app.state, tid, Actor::System, "mock")
        .await
        .unwrap();
    let (_, body, _) = call(&fx.app, Method::GET, &base, Some(&t), None).await;
    assert_eq!(body, json!([]));
    assert!(users::get(&fx.app.state, tid, user_id).await.is_ok());
    assert_eq!(
        identity_providers::create(
            &fx.app.state,
            tid,
            Actor::System,
            NewIdentityProvider {
                alias: "pkce-only".into(),
                kind: Some(IdpKind::Oidc),
                issuer: Some(fx.mock.base()),
                client_id: CLIENT_ID.into(),
                token_endpoint_auth_method: Some(IdpAuthMethod::None),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .token_endpoint_auth_method,
        IdpAuthMethod::None,
        "a public upstream client is allowed with PKCE"
    );
}
