mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::TestApp;
use ridm_api::models::{
    ClientType, NewClient, NewUser, RsaBits, SigningAlg, TokenEndpointAuthMethod,
};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::tokens::{self, VerifyOptions};
use ridm_api::services::{clients, keys, tenants, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Fx {
    app: TestApp,
    cookie: String,
}

async fn fixture() -> Fx {
    let app = TestApp::spawn().await;
    let user = users::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewUser {
            username: "alice".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let s = sessions::create(
        &app.state,
        tenant.id,
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
    Fx { app, cookie }
}

fn location(res: &reqwest::Response) -> url::Url {
    url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap()
}

fn q(u: &url::Url, k: &str) -> Option<String> {
    u.query_pairs()
        .find(|(a, _)| a == k)
        .map(|(_, v)| v.into_owned())
}

#[tokio::test]
async fn pushed_authorization_requests() {
    let fx = fixture().await;
    let tid = fx.app.tenant.id;
    let web = clients::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("web".into()),
            name: "web".into(),
            client_type: Some(ClientType::Web),
            redirect_uris: vec!["https://app.example/cb".into()],
            require_consent: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let secret = web.client_secret.unwrap();
    let other = clients::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("other".into()),
            name: "other".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://app.example/cb".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .client
    .client_id;

    let push = |form: Vec<(&'static str, &'static str)>| {
        let fx = &fx;
        let secret = secret.clone();
        async move {
            let res = fx
                .app
                .http
                .post(fx.app.tenant_url("/par"))
                .basic_auth("web", Some(&*secret))
                .form(&form)
                .send()
                .await
                .unwrap();
            let status = res.status().as_u16();
            assert_eq!(res.headers()["cache-control"], "no-store");
            (status, res.json::<Value>().await.unwrap())
        }
    };
    let full = vec![
        ("response_type", "code"),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", "openid"),
        ("state", "par-state"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];
    let (status, body) = push(full.clone()).await;
    assert_eq!(status, 201, "{body}");
    let request_uri = body["request_uri"].as_str().unwrap().to_string();
    assert!(request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));
    assert_eq!(body["expires_in"], 60);

    // Validation errors come back as JSON (no redirect at PAR time).
    let (status, body) = push(vec![
        ("response_type", "code"),
        ("redirect_uri", "https://evil.example/cb"),
        ("scope", "openid"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ])
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_request");
    let (status, body) = push(vec![
        ("response_type", "code"),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", "nope"),
    ])
    .await;
    assert_eq!(
        (status, body["error"].as_str().unwrap()),
        (400, "invalid_scope")
    );
    let (status, body) = push(vec![
        ("response_type", "code"),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", "openid"),
        ("request_uri", "urn:x"),
    ])
    .await;
    assert_eq!(
        (status, body["error"].as_str().unwrap()),
        (400, "invalid_request")
    );
    // Client authentication is required.
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/par"))
        .form(&full)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    // Another client cannot use the pushed request.
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[
            ("client_id", other.as_str()),
            ("request_uri", request_uri.as_str()),
        ])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    // ... and the attempt consumed it (single use); push again for the real thing.
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[("client_id", "web"), ("request_uri", request_uri.as_str())])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let (_, body) = push(full.clone()).await;
    let request_uri = body["request_uri"].as_str().unwrap().to_string();
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[("client_id", "web"), ("request_uri", request_uri.as_str())])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    let loc = location(&res);
    assert_eq!(loc.path(), "/cb");
    assert!(q(&loc, "code").is_some());
    assert_eq!(q(&loc, "state").as_deref(), Some("par-state"));
    // Replay of the request_uri fails.
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[("client_id", "web"), ("request_uri", request_uri.as_str())])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let html = res.text().await.unwrap();
    assert!(html.contains("invalid_request_uri"), "{html}");
}

#[tokio::test]
async fn signed_request_objects() {
    let fx = fixture().await;
    let tid = fx.app.tenant.id;
    let pair = keys::generate(SigningAlg::ES256, RsaBits::B2048).unwrap();
    let rogue = keys::generate(SigningAlg::ES256, RsaBits::B2048).unwrap();
    clients::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("jar".into()),
            name: "jar".into(),
            client_type: Some(ClientType::Web),
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
            jwks: Some(json!({"keys": [pair.public_jwk.clone()]})),
            redirect_uris: vec!["https://app.example/cb".into()],
            require_consent: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let issuer = format!("{}/t/{}", fx.app.base_url, fx.app.tenant.slug);
    let sign = |claims: Value, der: &[u8], kid: &str| {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(kid.to_string());
        let key = tokens::encoding_key_from_der(SigningAlg::ES256, der).unwrap();
        jsonwebtoken::encode(&header, &claims, &key).unwrap()
    };
    let now = chrono::Utc::now().timestamp();
    let good = json!({
        "iss": "jar", "aud": issuer, "exp": now + 300, "client_id": "jar", "response_type": "code",
        "redirect_uri": "https://app.example/cb", "scope": "openid", "state": "jar-state",
        "code_challenge": CHALLENGE, "code_challenge_method": "S256",
        "claims": {"id_token": {"email": {"essential": true}}}
    });
    let jwt = sign(good.clone(), &pair.private_der, &pair.kid);
    // Only client_id and request outside; everything else comes from the object.
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[("client_id", "jar"), ("request", jwt.as_str())])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    let loc = location(&res);
    assert!(q(&loc, "code").is_some());
    assert_eq!(q(&loc, "state").as_deref(), Some("jar-state"));

    // Plain parameter contradicting the object → rejected (shown to user).
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[
            ("client_id", "jar"),
            ("response_type", "token"),
            ("request", jwt.as_str()),
        ])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert!(res.text().await.unwrap().contains("invalid_request_object"));
    // Wrong key, wrong audience, wrong iss, alg none.
    for bad in [
        sign(good.clone(), &rogue.private_der, &pair.kid),
        sign(
            {
                let mut c = good.clone();
                c["aud"] = json!("https://elsewhere");
                c
            },
            &pair.private_der,
            &pair.kid,
        ),
        sign(
            {
                let mut c = good.clone();
                c["iss"] = json!("someone-else");
                c["client_id"] = json!("someone-else");
                c
            },
            &pair.private_der,
            &pair.kid,
        ),
        format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode(good.to_string())
        ),
    ] {
        let res = fx
            .app
            .http
            .get(fx.app.tenant_url("/authorize"))
            .query(&[("client_id", "jar"), ("request", bad.as_str())])
            .header("Cookie", &fx.cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 400);
    }

    // JAR inside PAR works too.
    let assertion = ridm_api::oidc::client_auth::build_assertion(
        "jar",
        &format!("{issuer}/token"),
        SigningAlg::ES256,
        &pair.kid,
        &pair.private_der,
        60,
    )
    .unwrap();
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/par"))
        .form(&[
            (
                "client_assertion_type",
                ridm_api::oidc::client_auth::JWT_BEARER_ASSERTION,
            ),
            ("client_assertion", assertion.as_str()),
            ("request", jwt.as_str()),
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
            ("client_id", "jar"),
            ("request_uri", body["request_uri"].as_str().unwrap()),
        ])
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    assert!(q(&location(&res), "code").is_some());
}

#[tokio::test]
async fn jarm_wraps_success_and_error_responses() {
    let fx = fixture().await;
    let tid = fx.app.tenant.id;
    let tenant = tenants::get(&fx.app.state, tid).await.unwrap();
    clients::create(
        &fx.app.state,
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
    let base = [
        ("response_type", "code"),
        ("client_id", "spa"),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", "openid"),
        ("state", "j1"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];

    for mode in ["jwt", "query.jwt"] {
        let mut p = base.to_vec();
        p.push(("response_mode", mode));
        let res = fx
            .app
            .http
            .get(fx.app.tenant_url("/authorize"))
            .query(&p)
            .header("Cookie", &fx.cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 303);
        let loc = location(&res);
        assert!(
            q(&loc, "code").is_none(),
            "parameters must be inside the JWT"
        );
        let response = q(&loc, "response").expect("response param");
        let claims = tokens::verify(
            &fx.app.state,
            &tenant,
            &response,
            &VerifyOptions {
                audience: Some("spa".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(claims["code"].is_string());
        assert_eq!(claims["state"], "j1");
        assert!(claims["exp"].is_number());
    }
    // fragment.jwt and form_post.jwt.
    let mut p = base.to_vec();
    p.push(("response_mode", "fragment.jwt"));
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&p)
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    let loc = location(&res);
    assert!(loc.fragment().unwrap().starts_with("response="));
    let mut p = base.to_vec();
    p.push(("response_mode", "form_post.jwt"));
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&p)
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let html = res.text().await.unwrap();
    assert!(html.contains("name=\"response\""));
    assert!(!html.contains("name=\"code\""));

    // Errors are JARM-encoded as well.
    let mut p = base.to_vec();
    p.retain(|(k, _)| *k != "scope");
    p.push(("scope", "nope"));
    p.push(("response_mode", "query.jwt"));
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&p)
        .header("Cookie", &fx.cookie)
        .send()
        .await
        .unwrap();
    let loc = location(&res);
    assert!(q(&loc, "error").is_none());
    let claims = tokens::verify(
        &fx.app.state,
        &tenant,
        &q(&loc, "response").unwrap(),
        &VerifyOptions {
            audience: Some("spa".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(claims["error"], "invalid_scope");
    assert_eq!(claims["state"], "j1");

    // Discovery advertises everything.
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
    assert!(
        doc["pushed_authorization_request_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/par")
    );
    assert_eq!(doc["request_parameter_supported"], true);
    assert_eq!(doc["request_uri_parameter_supported"], true);
    assert!(
        doc["response_modes_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "query.jwt")
    );
    assert!(
        doc["authorization_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a == "RS256")
    );
}
