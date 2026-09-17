//! DPoP (RFC 9449): proofs at the token endpoint, bound tokens at resources,
//! bound refresh tokens, clients that demand binding, and discovery.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use common::TestApp;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ridm_api::models::{ClientType, NewClient, NewUser, RsaBits, SigningAlg, grants};
use ridm_api::services::account_console::ACCOUNT_AUDIENCE;
use ridm_api::services::keys::{self, GeneratedKey};
use ridm_api::services::refresh_tokens::{self, IssueRequest};
use ridm_api::services::tokens::{self, AccessTokenRequest, TokenClient};
use ridm_api::services::{clients, tenants, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

struct Key {
    pair: GeneratedKey,
    enc: EncodingKey,
}

fn key() -> Key {
    let pair = keys::generate(SigningAlg::ES256, RsaBits::B2048).unwrap();
    let enc = tokens::encoding_key_from_der(SigningAlg::ES256, &pair.private_der).unwrap();
    Key { pair, enc }
}

struct ProofOpts<'a> {
    htm: &'a str,
    htu: &'a str,
    access_token: Option<&'a str>,
    iat: i64,
    jti: String,
    typ: &'a str,
}

impl ProofOpts<'_> {
    fn new<'a>(htm: &'a str, htu: &'a str) -> ProofOpts<'a> {
        ProofOpts {
            htm,
            htu,
            access_token: None,
            iat: Utc::now().timestamp(),
            jti: Uuid::new_v4().to_string(),
            typ: "dpop+jwt",
        }
    }
}

fn proof(k: &Key, o: ProofOpts<'_>) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some(o.typ.into());
    header.jwk = Some(serde_json::from_value(k.pair.public_jwk.clone()).unwrap());
    let mut claims = json!({ "jti": o.jti, "htm": o.htm, "htu": o.htu, "iat": o.iat });
    if let Some(at) = o.access_token {
        claims["ath"] = json!(URL_SAFE_NO_PAD.encode(Sha256::digest(at.as_bytes())));
    }
    jsonwebtoken::encode(&header, &claims, &k.enc).unwrap()
}

fn claims_of(jwt: &str) -> Value {
    let payload = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

async fn machine(app: &TestApp, id: &str, bound: bool) -> (String, String) {
    let c = clients::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some(id.into()),
            name: id.into(),
            client_type: Some(ClientType::Machine),
            dpop_bound_access_tokens: Some(bound),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    (
        c.client.client_id.clone(),
        c.client_secret.as_deref().map(|s| s.to_string()).unwrap(),
    )
}

async fn token_request(
    app: &TestApp,
    creds: &(String, String),
    proofs: &[String],
) -> reqwest::Response {
    let mut req = app
        .http
        .post(app.tenant_url("/token"))
        .basic_auth(&creds.0, Some(&creds.1))
        .form(&[("grant_type", "client_credentials")]);
    for p in proofs {
        req = req.header("dpop", p);
    }
    req.send().await.unwrap()
}

#[tokio::test]
async fn a_proof_at_the_token_endpoint_binds_the_token() {
    let app = TestApp::spawn().await;
    let creds = machine(&app, "svc", false).await;
    let k = key();
    let htu = app.tenant_url("/token");
    let res = token_request(&app, &creds, &[proof(&k, ProofOpts::new("POST", &htu))]).await;
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["token_type"], "DPoP");
    let at = body["access_token"].as_str().unwrap().to_string();
    let claims = claims_of(&at);
    assert_eq!(
        claims["cnf"]["jkt"], k.pair.kid,
        "the key's RFC 7638 thumbprint"
    );

    // Introspection reports the binding.
    let res = app
        .http
        .post(app.tenant_url("/introspect"))
        .basic_auth(&creds.0, Some(&creds.1))
        .form(&[("token", at.as_str())])
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["active"], true);
    assert_eq!(body["token_type"], "DPoP");
    assert_eq!(body["cnf"]["jkt"], k.pair.kid);

    // Without a proof the client still gets ordinary bearer tokens.
    let res = token_request(&app, &creds, &[]).await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["token_type"], "Bearer");
    assert!(
        claims_of(body["access_token"].as_str().unwrap())
            .get("cnf")
            .is_none()
    );
}

#[tokio::test]
async fn bad_proofs_are_refused() {
    let app = TestApp::spawn().await;
    let creds = machine(&app, "svc", false).await;
    let k = key();
    let htu = app.tenant_url("/token");
    let refused = |body: Value| {
        assert_eq!(body["error"], "invalid_dpop_proof", "{body}");
    };

    // Replay.
    let p = proof(&k, ProofOpts::new("POST", &htu));
    assert_eq!(
        token_request(&app, &creds, std::slice::from_ref(&p))
            .await
            .status(),
        200
    );
    let res = token_request(&app, &creds, &[p]).await;
    assert_eq!(res.status(), 400);
    refused(res.json().await.unwrap());

    // Method, URL, age, future, type, two headers, garbage.
    refused(
        token_request(&app, &creds, &[proof(&k, ProofOpts::new("GET", &htu))])
            .await
            .json()
            .await
            .unwrap(),
    );
    let other = app.tenant_url("/userinfo");
    refused(
        token_request(&app, &creds, &[proof(&k, ProofOpts::new("POST", &other))])
            .await
            .json()
            .await
            .unwrap(),
    );
    let mut old = ProofOpts::new("POST", &htu);
    old.iat = Utc::now().timestamp() - 600;
    refused(
        token_request(&app, &creds, &[proof(&k, old)])
            .await
            .json()
            .await
            .unwrap(),
    );
    let mut future = ProofOpts::new("POST", &htu);
    future.iat = Utc::now().timestamp() + 120;
    refused(
        token_request(&app, &creds, &[proof(&k, future)])
            .await
            .json()
            .await
            .unwrap(),
    );
    let mut typ = ProofOpts::new("POST", &htu);
    typ.typ = "JWT";
    refused(
        token_request(&app, &creds, &[proof(&k, typ)])
            .await
            .json()
            .await
            .unwrap(),
    );
    let two = [
        proof(&k, ProofOpts::new("POST", &htu)),
        proof(&k, ProofOpts::new("POST", &htu)),
    ];
    refused(
        token_request(&app, &creds, &two)
            .await
            .json()
            .await
            .unwrap(),
    );
    refused(
        token_request(&app, &creds, &["nonsense".into()])
            .await
            .json()
            .await
            .unwrap(),
    );
    // The query string does not count, so this one passes.
    let with_query = format!("{htu}?x=1");
    assert_eq!(
        token_request(
            &app,
            &creds,
            &[proof(&k, ProofOpts::new("POST", &with_query))]
        )
        .await
        .status(),
        200
    );
}

#[tokio::test]
async fn a_client_registered_for_binding_must_present_a_proof() {
    let app = TestApp::spawn().await;
    let creds = machine(&app, "strict", true).await;
    let res = token_request(&app, &creds, &[]).await;
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_dpop_proof");
    let k = key();
    let htu = app.tenant_url("/token");
    let res = token_request(&app, &creds, &[proof(&k, ProofOpts::new("POST", &htu))]).await;
    assert_eq!(res.status(), 200);
    // The flag rides in the registration document.
    let c = clients::find_by_client_id(&app.state, app.tenant.id, "strict")
        .await
        .unwrap()
        .unwrap();
    assert!(c.dpop_bound_access_tokens);
}

/// A bound user token minted the way the token endpoint would.
async fn bound_user_token(app: &TestApp, jkt: &str, audience: &str, client_id: &str) -> String {
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let user = users::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewUser {
            username: format!("u-{}", &Uuid::new_v4().simple().to_string()[..8]),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    tokens::issue_access_token(
        &app.state,
        AccessTokenRequest {
            tenant: &tenant,
            client: &TokenClient::public(client_id),
            user: Some(&user),
            scopes: &["openid".into(), "profile".into()],
            audiences: &[audience.to_string()],
            roles: &[],
            groups: &[],
            session_id: None,
            auth_time: None,
            amr: &["pwd".into()],
            acr: None,
            cnf_jkt: Some(jkt),
            act: None,
        },
    )
    .await
    .unwrap()
    .token
}

#[tokio::test]
async fn resources_demand_the_proof_for_bound_tokens() {
    let app = TestApp::spawn().await;
    clients::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("spa".into()),
            name: "spa".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://app.example/cb".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let k = key();
    let at = bound_user_token(&app, &k.pair.kid, "spa", "spa").await;
    let htu = app.tenant_url("/userinfo");
    let get = |auth: String, proof: Option<String>| {
        let mut req = app
            .http
            .get(app.tenant_url("/userinfo"))
            .header("authorization", auth);
        if let Some(p) = proof {
            req = req.header("dpop", p);
        }
        req.send()
    };

    // As a bearer token: refused, with a DPoP challenge.
    let res = get(format!("Bearer {at}"), None).await.unwrap();
    assert_eq!(res.status(), 401);
    let challenge = res.headers()["www-authenticate"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(challenge.starts_with("DPoP "), "{challenge}");
    assert!(challenge.contains("algs="));
    // DPoP scheme without a proof.
    let res = get(format!("DPoP {at}"), None).await.unwrap();
    assert_eq!(res.status(), 401);
    // A proof that does not name the token.
    let res = get(
        format!("DPoP {at}"),
        Some(proof(&k, ProofOpts::new("GET", &htu))),
    )
    .await
    .unwrap();
    assert_eq!(res.status(), 401);
    // A proof from another key.
    let other = key();
    let mut o = ProofOpts::new("GET", &htu);
    o.access_token = Some(&at);
    let res = get(format!("DPoP {at}"), Some(proof(&other, o)))
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    // The right key, naming the token: welcome.
    let mut o = ProofOpts::new("GET", &htu);
    o.access_token = Some(&at);
    let res = get(format!("DPoP {at}"), Some(proof(&k, o))).await.unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());

    // Unbound tokens keep working as bearer tokens.
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let plain = tokens::issue_access_token(
        &app.state,
        AccessTokenRequest {
            tenant: &tenant,
            client: &TokenClient::public("spa"),
            user: Some(
                &users::get(
                    &app.state,
                    tenant.id,
                    claims_of(&at)["sub"].as_str().unwrap().parse().unwrap(),
                )
                .await
                .unwrap(),
            ),
            scopes: &["openid".into()],
            audiences: &["spa".into()],
            roles: &[],
            groups: &[],
            session_id: None,
            auth_time: None,
            amr: &[],
            acr: None,
            cnf_jkt: None,
            act: None,
        },
    )
    .await
    .unwrap()
    .token;
    let res = get(format!("Bearer {plain}"), None).await.unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn the_account_api_enforces_the_binding_too() {
    let app = TestApp::spawn().await;
    let k = key();
    let at = bound_user_token(&app, &k.pair.kid, ACCOUNT_AUDIENCE, "ridm-account-console").await;
    let url = app.tenant_url("/account/me");
    let res = app.http.get(&url).bearer_auth(&at).send().await.unwrap();
    assert_eq!(res.status(), 401);
    let mut o = ProofOpts::new("GET", &url);
    o.access_token = Some(&at);
    let res = app
        .http
        .get(&url)
        .header("authorization", format!("DPoP {at}"))
        .header("dpop", proof(&k, o))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
}

#[tokio::test]
async fn a_bound_refresh_token_needs_the_same_key() {
    let app = TestApp::spawn().await;
    clients::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("spa".into()),
            name: "spa".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://app.example/cb".into()],
            allowed_grants: Some(vec![
                grants::AUTHORIZATION_CODE.into(),
                grants::REFRESH_TOKEN.into(),
            ]),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let user = users::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewUser {
            username: "bob".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let k = key();
    let issued = refresh_tokens::issue(
        &app.state,
        app.tenant.id,
        IssueRequest {
            client_id: "spa",
            user_id: Some(user.id),
            session_id: None,
            scopes: &["openid".into()],
            audiences: &[],
            ttl: chrono::Duration::minutes(10),
            dpop_jkt: Some(&k.pair.kid),
            auth_time: None,
            amr: &[],
            acr: None,
        },
    )
    .await
    .unwrap();
    let htu = app.tenant_url("/token");
    let refresh = |rt: String, p: Option<String>| {
        let mut req = app.http.post(app.tenant_url("/token")).form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "spa"),
            ("refresh_token", rt.as_str()),
        ]);
        if let Some(p) = p {
            req = req.header("dpop", p);
        }
        req.send()
    };
    // No proof: refused, and the token is not spent.
    let res = refresh(issued.token.to_string(), None).await.unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    // Another key: refused, still not spent.
    let other = key();
    let res = refresh(
        issued.token.to_string(),
        Some(proof(&other, ProofOpts::new("POST", &htu))),
    )
    .await
    .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    // The right key: rotated, and the new token carries the binding on.
    let res = refresh(
        issued.token.to_string(),
        Some(proof(&k, ProofOpts::new("POST", &htu))),
    )
    .await
    .unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["token_type"], "DPoP");
    assert_eq!(
        claims_of(body["access_token"].as_str().unwrap())["cnf"]["jkt"],
        k.pair.kid
    );
    let next = body["refresh_token"].as_str().unwrap().to_string();
    let res = refresh(
        next.clone(),
        Some(proof(&other, ProofOpts::new("POST", &htu))),
    )
    .await
    .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    let res = refresh(next, Some(proof(&k, ProofOpts::new("POST", &htu))))
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn discovery_lists_the_proof_algorithms() {
    let app = TestApp::spawn().await;
    let doc: Value = app
        .http
        .get(app.tenant_url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let algs = doc["dpop_signing_alg_values_supported"].as_array().unwrap();
    assert!(algs.iter().any(|a| a == "ES256"));
}

/// Phase 9.12 review finding. Token exchange verified the subject token
/// without looking at its `cnf`, so a stolen sender-constrained token could be
/// traded for an unbound one and the binding simply dropped (RFC 9449 §5).
#[tokio::test]
async fn exchange_cannot_strip_a_sender_constrained_binding() {
    let app = TestApp::spawn().await;
    let victim_key = key();
    let audience = "https://orders.example";
    ridm_api::services::resource_servers::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        ridm_api::models::NewResourceServer {
            identifier: audience.into(),
            name: "Orders".into(),
            token_ttl_secs: None,
            signing_alg: None,
            allow_offline_access: None,
        },
    )
    .await
    .unwrap();
    let created = clients::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("gateway".into()),
            name: "Gateway".into(),
            client_type: Some(ClientType::Machine),
            allowed_grants: Some(vec![grants::TOKEN_EXCHANGE.into()]),
            allowed_scopes: Some(vec!["openid".into(), "profile".into()]),
            allowed_audiences: vec![audience.into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let secret = created.client_secret.as_deref().unwrap().to_string();
    // A token bound to the victim's key, as the attacker would have stolen it.
    let stolen = bound_user_token(&app, &victim_key.pair.kid, audience, "frontend").await;

    let exchange = |proof: Option<String>| {
        let app = &app;
        let secret = secret.clone();
        let stolen = stolen.clone();
        async move {
            let mut req = app
                .http
                .post(app.tenant_url("/token"))
                .basic_auth("gateway", Some(&secret))
                .form(&[
                    ("grant_type", grants::TOKEN_EXCHANGE),
                    ("subject_token", stolen.as_str()),
                    (
                        "subject_token_type",
                        "urn:ietf:params:oauth:token-type:access_token",
                    ),
                    ("audience", audience),
                ]);
            if let Some(p) = proof {
                req = req.header("dpop", p);
            }
            req.send().await.unwrap()
        }
    };

    // No proof at all: the binding would be dropped, so the exchange is refused.
    let res = exchange(None).await;
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant", "{body}");

    // A proof from the attacker's own key is not the victim's key either.
    let attacker = key();
    let url = app.tenant_url("/token");
    let res = exchange(Some(proof(&attacker, ProofOpts::new("POST", &url)))).await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant", "{body}");

    // Holding the bound key, the legitimate presenter may still exchange.
    let res = exchange(Some(proof(&victim_key, ProofOpts::new("POST", &url)))).await;
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
}
