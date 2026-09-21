//! Phase 12.6: the FAPI 2.0 Security Profile as a per-client switch, and
//! `require_pushed_authorization_requests` on its own. A `fapi2` client is
//! registered only in the profile's shape, sends every authorization request
//! through PAR with PKCE, authenticates with a `private_key_jwt` whose `aud`
//! is the issuer, signs with PS256/ES256/EdDSA, gets DPoP-bound tokens
//! rIDM signed with ES256 or EdDSA, and keeps its refresh token.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use common::TestApp;
use jsonwebtoken::{Algorithm, Header};
use ridm_api::models::{
    ClientType, DcrPolicy, NewClient, NewUser, RsaBits, SecurityProfile, SigningAlg,
    TokenEndpointAuthMethod, grants,
};
use ridm_api::oidc::client_auth::JWT_BEARER_ASSERTION;
use ridm_api::services::keys::{self, GeneratedKey};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::{clients, tenants, tokens, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const REDIRECT: &str = "https://bank.example/cb";

struct Fx {
    app: TestApp,
    cookie: String,
    /// The client's signing key (ES256), registered in its JWKS.
    key: GeneratedKey,
    issuer: String,
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
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    assert_eq!(
        tenant.settings.keys.default_alg,
        SigningAlg::RS256,
        "the tenant signs with an algorithm the profile forbids"
    );
    let s = sessions::create(
        &app.state,
        tid,
        NewSession {
            user_id: user.id,
            amr: vec!["pwd".into()],
            acr: None,
            ip: None,
            user_agent: None,
            policy: &tenant.settings.session,
        },
    )
    .await
    .unwrap();
    let cookie = format!(
        "{}={}",
        sessions::cookie_name(&app.state, &app.tenant.slug),
        s.id
    );
    let key = keys::generate(SigningAlg::ES256, RsaBits::B2048).unwrap();
    clients::create(&app.state, tid, Actor::System, fapi_client("bank", &key))
        .await
        .unwrap();
    let issuer = format!("{}/t/{}", app.base_url, app.tenant.slug);
    Fx {
        app,
        cookie,
        key,
        issuer,
    }
}

fn fapi_client(id: &str, key: &GeneratedKey) -> NewClient {
    NewClient {
        client_id: Some(id.into()),
        name: "Bank".into(),
        client_type: Some(ClientType::Web),
        token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
        jwks: Some(json!({"keys": [key.public_jwk.clone()]})),
        redirect_uris: vec![REDIRECT.into()],
        allowed_grants: Some(vec![
            grants::AUTHORIZATION_CODE.into(),
            grants::REFRESH_TOKEN.into(),
        ]),
        allowed_scopes: Some(vec!["openid".into(), "offline_access".into()]),
        require_consent: Some(false),
        security_profile: Some(SecurityProfile::Fapi2),
        ..Default::default()
    }
}

fn sign(alg: Algorithm, der_alg: SigningAlg, der: &[u8], kid: &str, claims: &Value) -> String {
    let mut header = Header::new(alg);
    header.kid = Some(kid.to_string());
    let key = tokens::encoding_key_from_der(der_alg, der).unwrap();
    jsonwebtoken::encode(&header, claims, &key).unwrap()
}

/// A `private_key_jwt` assertion for `bank` with audience `aud`.
fn assertion(fx: &Fx, aud: &str) -> String {
    let now = Utc::now().timestamp();
    sign(
        Algorithm::ES256,
        SigningAlg::ES256,
        &fx.key.private_der,
        &fx.key.kid,
        &json!({"iss": "bank", "sub": "bank", "aud": aud, "iat": now, "exp": now + 60, "jti": Uuid::new_v4().to_string()}),
    )
}

/// A DPoP proof for `POST {url}` made with `key`.
fn dpop(key: &GeneratedKey, url: &str) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".into());
    header.jwk = Some(serde_json::from_value(key.public_jwk.clone()).unwrap());
    let enc = tokens::encoding_key_from_der(SigningAlg::ES256, &key.private_der).unwrap();
    jsonwebtoken::encode(
        &header,
        &json!({"jti": Uuid::new_v4().to_string(), "htm": "POST", "htu": url, "iat": Utc::now().timestamp()}),
        &enc,
    )
    .unwrap()
}

fn header_of(jwt: &str) -> Value {
    let h = jwt.split('.').next().unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).unwrap()).unwrap()
}

fn claims_of(jwt: &str) -> Value {
    let p = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).unwrap()).unwrap()
}

fn location(res: &reqwest::Response) -> url::Url {
    url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap()
}

fn q(u: &url::Url, k: &str) -> Option<String> {
    u.query_pairs()
        .find(|(a, _)| a == k)
        .map(|(_, v)| v.into_owned())
}

/// Push an authorization request as `bank`.
async fn push(fx: &Fx, assertion: &str, extra: &[(&str, &str)]) -> (u16, Value) {
    let mut form = vec![
        ("client_assertion_type", JWT_BEARER_ASSERTION),
        ("client_assertion", assertion),
        ("response_type", "code"),
        ("client_id", "bank"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid offline_access"),
        ("state", "st"),
    ];
    form.extend_from_slice(extra);
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/par"))
        .form(&form)
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

/// PAR with PKCE, then `/authorize` in alice's browser: the code.
async fn code(fx: &Fx) -> String {
    let (status, body) = push(
        fx,
        &assertion(fx, &fx.issuer),
        &[
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[
            ("client_id", "bank"),
            ("request_uri", body["request_uri"].as_str().unwrap()),
        ])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let loc = location(&res);
    assert_eq!(q(&loc, "iss").as_deref(), Some(fx.issuer.as_str()));
    q(&loc, "code").expect("a code")
}

async fn token(fx: &Fx, form: &[(&str, &str)], proof: Option<&str>) -> (u16, Value) {
    let assertion = assertion(fx, &fx.issuer);
    let mut all = vec![
        ("client_assertion_type", JWT_BEARER_ASSERTION),
        ("client_assertion", assertion.as_str()),
    ];
    all.extend_from_slice(form);
    let mut req = fx.app.http.post(fx.app.tenant_url("/token")).form(&all);
    if let Some(p) = proof {
        req = req.header("dpop", p);
    }
    let res = req.send().await.unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn registration_holds_the_client_to_the_profile() {
    let fx = fixture().await;
    let bank = clients::find_by_client_id(&fx.app.state, fx.app.tenant.id, "bank")
        .await
        .unwrap()
        .unwrap();
    assert!(bank.require_pkce && bank.dpop_bound_access_tokens && bank.requires_par());
    let refused = |c: NewClient| {
        let st = fx.app.state.clone();
        let tid = fx.app.tenant.id;
        async move {
            match clients::create(&st, tid, Actor::System, c).await {
                Err(e) => e.to_string(),
                Ok(_) => String::new(),
            }
        }
    };
    let base = || fapi_client("x", &fx.key);
    for (why, c) in [
        (
            "client_secret",
            NewClient {
                token_endpoint_auth_method: Some(TokenEndpointAuthMethod::ClientSecretBasic),
                jwks: None,
                ..base()
            },
        ),
        (
            "public",
            NewClient {
                client_type: Some(ClientType::Spa),
                ..base()
            },
        ),
        (
            "device grant",
            NewClient {
                allowed_grants: Some(vec![grants::DEVICE_CODE.into()]),
                ..base()
            },
        ),
        (
            "PKCE off",
            NewClient {
                require_pkce: Some(false),
                ..base()
            },
        ),
        (
            "DPoP off",
            NewClient {
                dpop_bound_access_tokens: Some(false),
                ..base()
            },
        ),
        (
            "http redirect",
            NewClient {
                redirect_uris: vec!["http://localhost:8080/cb".into()],
                ..base()
            },
        ),
    ] {
        let err = refused(c).await;
        assert!(!err.is_empty(), "{why} was accepted");
    }
}

#[tokio::test]
async fn the_whole_flow_under_the_profile() {
    let fx = fixture().await;
    let code = code(&fx).await;
    let token_url = fx.app.tenant_url("/token");
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
    ];
    // No proof: refused before the code is spent.
    let (status, body) = token(&fx, &form, None).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_dpop_proof"))
    );
    let dpop_key = keys::generate(SigningAlg::ES256, RsaBits::B2048).unwrap();
    let (status, tokens) = token(&fx, &form, Some(&dpop(&dpop_key, &token_url))).await;
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(tokens["token_type"], "DPoP");
    // Signed with an algorithm the profile allows, though the tenant's
    // default is RS256.
    for t in ["access_token", "id_token"] {
        assert_eq!(
            header_of(tokens[t].as_str().unwrap())["alg"],
            "ES256",
            "{t}"
        );
    }
    let jkt = claims_of(tokens["access_token"].as_str().unwrap())["cnf"]["jkt"].clone();
    assert!(jkt.is_string());

    // The refresh token is not rotated: the same one comes back and keeps working.
    let rt = tokens["refresh_token"].as_str().unwrap().to_string();
    for _ in 0..2 {
        let (status, refreshed) = token(
            &fx,
            &[("grant_type", "refresh_token"), ("refresh_token", &rt)],
            Some(&dpop(&dpop_key, &token_url)),
        )
        .await;
        assert_eq!(status, 200, "{refreshed}");
        assert_eq!(refreshed["refresh_token"], rt.as_str());
    }
}

#[tokio::test]
async fn authorization_requests_come_through_par_with_pkce() {
    let fx = fixture().await;
    // Straight to /authorize: refused to the redirect URI.
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "bank"),
            ("redirect_uri", REDIRECT),
            ("scope", "openid"),
            ("state", "st"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let loc = location(&res);
    assert_eq!(q(&loc, "error").as_deref(), Some("invalid_request"));
    assert_eq!(q(&loc, "state").as_deref(), Some("st"));
    assert!(q(&loc, "code").is_none());
    // Through PAR without PKCE: refused at the push.
    let (status, body) = push(&fx, &assertion(&fx, &fx.issuer), &[]).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_request")),
        "{body}"
    );
}

#[tokio::test]
async fn client_assertions_are_held_to_the_profile() {
    let fx = fixture().await;
    let pkce = [
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];
    // The token endpoint URL as audience is fine for others, not here.
    let at_token_endpoint = assertion(&fx, &fx.app.tenant_url("/token"));
    let (status, body) = push(&fx, &at_token_endpoint, &pkce).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("invalid_client")),
        "{body}"
    );
    // An array holding the issuer is not the issuer as a string.
    let now = Utc::now().timestamp();
    let as_array = sign(
        Algorithm::ES256,
        SigningAlg::ES256,
        &fx.key.private_der,
        &fx.key.kid,
        &json!({"iss": "bank", "sub": "bank", "aud": [fx.issuer], "iat": now, "exp": now + 60, "jti": Uuid::new_v4().to_string()}),
    );
    let (status, _) = push(&fx, &as_array, &pkce).await;
    assert_eq!(status, 401);
    // RS256 is outside the profile, even with a registered RSA key.
    let rsa = keys::generate(SigningAlg::RS256, RsaBits::B2048).unwrap();
    let c = clients::find_by_client_id(&fx.app.state, fx.app.tenant.id, "bank")
        .await
        .unwrap()
        .unwrap();
    let mut input = fapi_client("bank", &fx.key);
    input.jwks = Some(json!({"keys": [fx.key.public_jwk.clone(), rsa.public_jwk.clone()]}));
    clients::update_metadata(&fx.app.state, fx.app.tenant.id, Actor::System, c.id, input)
        .await
        .unwrap();
    let rs256 = sign(
        Algorithm::RS256,
        SigningAlg::RS256,
        &rsa.private_der,
        &rsa.kid,
        &json!({"iss": "bank", "sub": "bank", "aud": fx.issuer, "iat": now, "exp": now + 60, "jti": Uuid::new_v4().to_string()}),
    );
    let (status, body) = push(&fx, &rs256, &pkce).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("invalid_client")),
        "{body}"
    );
    // And the good one passes.
    let (status, _) = push(&fx, &assertion(&fx, &fx.issuer), &pkce).await;
    assert_eq!(status, 201);
}

#[tokio::test]
async fn dpop_proofs_use_the_profiles_algorithms() {
    let fx = fixture().await;
    let code = code(&fx).await;
    let token_url = fx.app.tenant_url("/token");
    let rsa = keys::generate(SigningAlg::RS256, RsaBits::B2048).unwrap();
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("dpop+jwt".into());
    header.jwk = Some(serde_json::from_value(rsa.public_jwk.clone()).unwrap());
    let enc = tokens::encoding_key_from_der(SigningAlg::RS256, &rsa.private_der).unwrap();
    let proof = jsonwebtoken::encode(
        &header,
        &json!({"jti": Uuid::new_v4().to_string(), "htm": "POST", "htu": token_url, "iat": Utc::now().timestamp()}),
        &enc,
    )
    .unwrap();
    let (status, body) = token(
        &fx,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
        Some(&proof),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_dpop_proof")),
        "{body}"
    );
}

#[tokio::test]
async fn require_par_stands_on_its_own() {
    let fx = fixture().await;
    let web = clients::create(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("parweb".into()),
            name: "parweb".into(),
            client_type: Some(ClientType::Web),
            redirect_uris: vec![REDIRECT.into()],
            require_consent: Some(false),
            require_pushed_authorization_requests: Some(true),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(!web.client.is_fapi2() && web.client.requires_par());
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "parweb"),
            ("redirect_uri", REDIRECT),
            ("scope", "openid"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(
        q(&location(&res), "error").as_deref(),
        Some("invalid_request")
    );
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/par"))
        .basic_auth("parweb", Some(web.client_secret.as_deref().unwrap()))
        .form(&[
            ("response_type", "code"),
            ("redirect_uri", REDIRECT),
            ("scope", "openid"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let body: Value = res.json().await.unwrap();
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[
            ("client_id", "parweb"),
            ("request_uri", body["request_uri"].as_str().unwrap()),
        ])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    assert!(q(&location(&res), "code").is_some());

    // Dynamic registration keeps the flag (it used to drop it).
    let meta: ridm_api::oidc::register::Metadata = serde_json::from_value(json!({
        "redirect_uris": [REDIRECT],
        "require_pushed_authorization_requests": true,
    }))
    .unwrap();
    let input = ridm_api::oidc::register::to_new_client(&meta, &DcrPolicy::default()).unwrap();
    assert_eq!(input.require_pushed_authorization_requests, Some(true));
}

#[tokio::test]
async fn the_signing_key_the_profile_needs_is_made_on_demand() {
    // A tenant whose default is RS256 had no ES256 key before a FAPI client
    // asked for tokens; the ID token's key is published now, as ES256.
    let fx = fixture().await;
    let code = code(&fx).await;
    let token_url = fx.app.tenant_url("/token");
    let dpop_key = keys::generate(SigningAlg::ES256, RsaBits::B2048).unwrap();
    let (status, tokens) = token(
        &fx,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
        Some(&dpop(&dpop_key, &token_url)),
    )
    .await;
    assert_eq!(status, 200, "{tokens}");
    let kid = header_of(tokens["id_token"].as_str().unwrap())["kid"].clone();
    let jwks: Value = fx
        .app
        .http
        .get(fx.app.tenant_url("/.well-known/jwks.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let published = jwks["keys"].as_array().unwrap();
    assert!(
        published
            .iter()
            .any(|k| k["kid"] == kid && k["alg"] == "ES256"),
        "{jwks}"
    );
}
