mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::TestApp;
use ridm_api::models::{
    ClientType, NewClient, NewRole, NewUser, Principal, RsaBits, SigningAlg,
    TokenEndpointAuthMethod,
};
use ridm_api::oidc::client_auth::{JWT_BEARER_ASSERTION, build_assertion};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::tokens::{self, VerifyOptions};
use ridm_api::services::{clients, keys, roles, tenants, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Fx {
    app: TestApp,
    user_id: Uuid,
}

async fn fixture() -> Fx {
    let app = TestApp::spawn().await;
    let user = users::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewUser {
            username: "alice".into(),
            email: Some("alice@example.com".into()),
            email_verified: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let role = roles::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewRole {
            name: "editor".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    roles::assign(
        &app.state,
        app.tenant.id,
        Actor::System,
        role.id,
        Principal::User { id: user.id },
    )
    .await
    .unwrap();
    Fx {
        app,
        user_id: user.id,
    }
}

async fn spa(fx: &Fx) -> String {
    clients::create(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("spa".into()),
            name: "SPA".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://app.example/cb".into()],
            require_consent: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .client
    .client_id
}

async fn cookie(fx: &Fx) -> String {
    let tenant = tenants::get(&fx.app.state, fx.app.tenant.id).await.unwrap();
    let s = sessions::create(
        &fx.app.state,
        tenant.id,
        NewSession {
            user_id: fx.user_id,
            amr: vec!["pwd".into()],
            acr: None,
            ip: None,
            user_agent: None,
            policy: &tenant.settings.session,
        },
    )
    .await
    .unwrap();
    format!("{}={}", sessions::cookie_name(&fx.app.state), s.id)
}

/// Run /authorize with a session and return the code.
async fn get_code(fx: &Fx, client_id: &str, scope: &str, extra: &[(&str, &str)]) -> String {
    let c = cookie(fx).await;
    let mut q = vec![
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", "https://app.example/cb"),
        ("scope", scope),
        ("state", "s"),
        ("nonce", "n1"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];
    q.extend_from_slice(extra);
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/authorize"))
        .query(&q)
        .header("Cookie", c)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    loc.query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| panic!("no code in {loc}"))
}

async fn post_token(fx: &Fx, form: &[(&str, &str)], basic: Option<(&str, &str)>) -> (u16, Value) {
    let mut req = fx.app.http.post(fx.app.tenant_url("/token")).form(form);
    if let Some((id, secret)) = basic {
        req = req.basic_auth(id, Some(secret));
    }
    let res = req.send().await.unwrap();
    let status = res.status().as_u16();
    assert_eq!(res.headers()["cache-control"], "no-store");
    (status, res.json().await.unwrap())
}

fn payload(jwt: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn authorization_code_pkce_round_trip_then_refresh_rotation() {
    let fx = fixture().await;
    let client_id = spa(&fx).await;
    let tenant = tenants::get(&fx.app.state, fx.app.tenant.id).await.unwrap();
    let code = get_code(&fx, &client_id, "openid profile email", &[]).await;

    let (status, body) = post_token(
        &fx,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://app.example/cb"),
            ("code_verifier", VERIFIER),
            ("client_id", &client_id),
        ],
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["expires_in"].as_i64().unwrap() > 0);
    assert_eq!(body["scope"], "openid profile email");
    let at = body["access_token"].as_str().unwrap();
    let idt = body["id_token"].as_str().unwrap();
    let rt = body["refresh_token"].as_str().unwrap();
    assert!(rt.starts_with("rt_"));

    let at_claims = tokens::verify(
        &fx.app.state,
        &tenant,
        at,
        &VerifyOptions {
            typ: Some("at+jwt".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(at_claims["sub"], fx.user_id.to_string());
    assert_eq!(at_claims["client_id"], "spa");
    assert_eq!(at_claims["roles"], json!(["editor"]));
    assert_eq!(at_claims["amr"], json!(["pwd"]));
    assert!(at_claims["sid"].is_string());
    let id_claims = tokens::verify(
        &fx.app.state,
        &tenant,
        idt,
        &VerifyOptions {
            audience: Some("spa".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(id_claims["nonce"], "n1");
    assert_eq!(id_claims["email"], "alice@example.com");
    assert_eq!(
        id_claims["at_hash"],
        tokens::half_hash(SigningAlg::RS256, at)
    );
    assert!(id_claims["auth_time"].is_number());

    // Code is single use; the replay revokes the family it produced.
    let (status, body) = post_token(
        &fx,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://app.example/cb"),
            ("code_verifier", VERIFIER),
            ("client_id", &client_id),
        ],
        None,
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_grant");
    let (status, body) = post_token(
        &fx,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt),
            ("client_id", &client_id),
        ],
        None,
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_grant");

    // Fresh grant, then rotation with scope narrowing.
    let code = get_code(&fx, &client_id, "openid profile email", &[]).await;
    let (_, body) = post_token(
        &fx,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://app.example/cb"),
            ("code_verifier", VERIFIER),
            ("client_id", &client_id),
        ],
        None,
    )
    .await;
    let rt1 = body["refresh_token"].as_str().unwrap().to_string();
    let (status, body) = post_token(
        &fx,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &rt1),
            ("client_id", &client_id),
            ("scope", "openid email"),
        ],
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["scope"], "openid email");
    let rt2 = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(rt1, rt2);
    assert!(
        body["id_token"].is_string(),
        "openid scope keeps issuing id tokens on refresh"
    );
    assert!(
        payload(body["id_token"].as_str().unwrap())
            .get("nonce")
            .is_none()
    );
    let (status, body) = post_token(
        &fx,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &rt2),
            ("client_id", &client_id),
            ("scope", "openid phone"),
        ],
        None,
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["error"], "invalid_scope",
        "scope cannot exceed the original grant"
    );
    // rt1 was consumed → reuse detection revokes the family; rt2 dies with it.
    let (_, body) = post_token(
        &fx,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &rt1),
            ("client_id", &client_id),
        ],
        None,
    )
    .await;
    assert_eq!(body["error"], "invalid_grant");
    let (_, body) = post_token(
        &fx,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &rt2),
            ("client_id", &client_id),
        ],
        None,
    )
    .await;
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn authorization_code_negative_cases() {
    let fx = fixture().await;
    let client_id = spa(&fx).await;
    let other = clients::create(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("other".into()),
            name: "Other".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://app.example/cb".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .client
    .client_id;

    let err = |form: Vec<(&'static str, String)>| {
        let fx = &fx;
        async move {
            let form_ref: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let (status, body) = post_token(fx, &form_ref, None).await;
            (
                status,
                body["error"].as_str().unwrap_or_default().to_string(),
                body["error_description"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            )
        }
    };
    let base = |code: &str, extra: Vec<(&'static str, String)>| {
        let mut f = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("redirect_uri", "https://app.example/cb".to_string()),
            ("code_verifier", VERIFIER.to_string()),
            ("client_id", client_id.clone()),
        ];
        for (k, v) in extra {
            f.retain(|(fk, _)| *fk != k);
            f.push((k, v));
        }
        f
    };

    let code = get_code(&fx, &client_id, "openid", &[]).await;
    let (s, e, d) = err(base(
        &code,
        vec![(
            "code_verifier",
            "wrong-verifier-wrong-verifier-wrong-verifier-x".into(),
        )],
    ))
    .await;
    assert_eq!((s, e.as_str()), (400, "invalid_grant"), "{d}");
    // A failed PKCE check consumed the code; it cannot be retried.
    assert_eq!(err(base(&code, vec![])).await.1, "invalid_grant");

    let code = get_code(&fx, &client_id, "openid", &[]).await;
    assert_eq!(
        err(base(
            &code,
            vec![("redirect_uri", "https://app.example/other".into())]
        ))
        .await
        .1,
        "invalid_grant"
    );
    let code = get_code(&fx, &client_id, "openid", &[]).await;
    assert_eq!(
        err(base(&code, vec![("client_id", other.clone())])).await.1,
        "invalid_grant"
    );
    let code = get_code(&fx, &client_id, "openid", &[]).await;
    let (_, e, d) = err(base(&code, vec![("code_verifier", String::new())])).await;
    assert_eq!(e, "invalid_request");
    assert!(d.contains("code_verifier"), "{d}");
    assert_eq!(err(base("garbage", vec![])).await.1, "invalid_grant");
    assert_eq!(
        err(base(&code, vec![("grant_type", "password".into())]))
            .await
            .1,
        "unsupported_grant_type"
    );
    assert_eq!(
        err(base(
            &code,
            vec![("grant_type", "client_credentials".into())]
        ))
        .await
        .1,
        "unauthorized_client"
    );
    let (s, e, _) = err(base(&code, vec![("client_id", "ghost".into())])).await;
    assert_eq!((s, e.as_str()), (401, "invalid_client"));
    let (s, e, _) = err(base(&code, vec![("client_secret", "cs_x".into())])).await;
    assert_eq!(
        (s, e.as_str()),
        (401, "invalid_client"),
        "public clients must not send a secret"
    );

    // Wrong content type.
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .json(&json!({"grant_type": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn client_credentials_with_basic_post_and_private_key_jwt() {
    let fx = fixture().await;
    let tid = fx.app.tenant.id;
    let tenant = tenants::get(&fx.app.state, tid).await.unwrap();
    ridm_api::services::scopes::create(
        &fx.app.state,
        tid,
        Actor::System,
        ridm_api::models::NewScope {
            name: "read:things".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut tx = ridm_api::db::tenant_tx(&fx.app.state.db, tid)
        .await
        .unwrap();
    let rs = ridm_api::repos::resource_servers::insert(
        &mut *tx,
        tid,
        Uuid::now_v7(),
        "https://things.example",
        "Things",
        Some(120),
        None,
        true,
    )
    .await
    .unwrap();
    let perm = ridm_api::repos::resource_servers::insert_permission(
        &mut *tx,
        tid,
        Uuid::now_v7(),
        rs.id,
        "things:read",
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // basic
    let created = clients::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("svc-basic".into()),
            name: "svc".into(),
            client_type: Some(ClientType::Machine),
            allowed_scopes: Some(vec!["read:things".into()]),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let secret = created.client_secret.unwrap();
    let (status, body) = post_token(
        &fx,
        &[
            ("grant_type", "client_credentials"),
            ("scope", "read:things"),
        ],
        Some(("svc-basic", &secret)),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("refresh_token").is_none());
    assert!(body.get("id_token").is_none());
    let claims = tokens::verify(
        &fx.app.state,
        &tenant,
        body["access_token"].as_str().unwrap(),
        &VerifyOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(claims["sub"], "svc-basic");
    assert_eq!(claims["aud"], "svc-basic");
    assert_eq!(claims["scope"], "read:things");
    assert!(claims.get("roles").is_none());

    let (status, body) = post_token(
        &fx,
        &[("grant_type", "client_credentials")],
        Some(("svc-basic", "cs_wrong")),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str().unwrap()),
        (401, "invalid_client")
    );
    let (_, body) = post_token(
        &fx,
        &[("grant_type", "client_credentials"), ("scope", "openid")],
        Some(("svc-basic", &secret)),
    )
    .await;
    assert_eq!(body["error"], "invalid_scope");
    let (_, body) = post_token(
        &fx,
        &[("grant_type", "client_credentials"), ("scope", "profile")],
        Some(("svc-basic", &secret)),
    )
    .await;
    assert_eq!(body["error"], "invalid_scope");
    // Registered method is basic: post is refused.
    let (status, body) = post_token(
        &fx,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", "svc-basic"),
            ("client_secret", &secret),
        ],
        None,
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str().unwrap()),
        (401, "invalid_client")
    );

    // post + service account + resource with permissions + per-RS TTL
    let sa = users::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewUser {
            username: "svc-account".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let role = roles::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewRole {
            name: "things-reader".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    roles::assign(
        &fx.app.state,
        tid,
        Actor::System,
        role.id,
        Principal::User { id: sa.id },
    )
    .await
    .unwrap();
    let mut tx = ridm_api::db::tenant_tx(&fx.app.state.db, tid)
        .await
        .unwrap();
    ridm_api::repos::resource_servers::assign_permission(&mut *tx, tid, role.id, perm.id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let created = clients::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("svc-post".into()),
            name: "svc".into(),
            client_type: Some(ClientType::Machine),
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::ClientSecretPost),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut tx = ridm_api::db::tenant_tx(&fx.app.state.db, tid)
        .await
        .unwrap();
    ridm_api::repos::clients::set_service_account(&mut *tx, tid, created.client.id, Some(sa.id))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    fx.app
        .state
        .cache
        .invalidate(&[ridm_api::cache::keys::client_by_client_id(tid, "svc-post")])
        .await
        .unwrap();
    let secret = created.client_secret.unwrap();
    let (status, body) = post_token(
        &fx,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", "svc-post"),
            ("client_secret", &secret),
            ("resource", "https://things.example"),
        ],
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body["expires_in"].as_i64().unwrap() <= 120,
        "resource server TTL applies"
    );
    let claims = tokens::verify(
        &fx.app.state,
        &tenant,
        body["access_token"].as_str().unwrap(),
        &VerifyOptions {
            audience: Some("https://things.example".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        claims["sub"],
        sa.id.to_string(),
        "service account user is the subject"
    );
    assert_eq!(claims["roles"], json!(["things-reader"]));
    assert_eq!(claims["permissions"], json!(["things:read"]));
    let (_, body) = post_token(
        &fx,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", "svc-post"),
            ("client_secret", &secret),
            ("resource", "https://unknown.example"),
        ],
        None,
    )
    .await;
    assert_eq!(body["error"], "invalid_target");

    // private_key_jwt with an inline JWKS
    let pair = keys::generate(SigningAlg::ES256, RsaBits::B2048).unwrap();
    let created = clients::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("svc-jwt".into()),
            name: "svc".into(),
            client_type: Some(ClientType::Machine),
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
            jwks: Some(json!({"keys": [pair.public_jwk]})),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(created.client_secret.is_none());
    let token_endpoint = format!("{}/t/{}/token", fx.app.base_url, fx.app.tenant.slug);
    let assertion = build_assertion(
        "svc-jwt",
        &token_endpoint,
        SigningAlg::ES256,
        &pair.kid,
        &pair.private_der,
        60,
    )
    .unwrap();
    let (status, body) = post_token(
        &fx,
        &[
            ("grant_type", "client_credentials"),
            ("client_assertion_type", JWT_BEARER_ASSERTION),
            ("client_assertion", &assertion),
        ],
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    // Replay of the same assertion is refused; a different key is refused.
    let (status, body) = post_token(
        &fx,
        &[
            ("grant_type", "client_credentials"),
            ("client_assertion_type", JWT_BEARER_ASSERTION),
            ("client_assertion", &assertion),
        ],
        None,
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str().unwrap()),
        (401, "invalid_client")
    );
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("replayed")
    );
    let rogue = keys::generate(SigningAlg::ES256, RsaBits::B2048).unwrap();
    let forged = build_assertion(
        "svc-jwt",
        &token_endpoint,
        SigningAlg::ES256,
        &pair.kid,
        &rogue.private_der,
        60,
    )
    .unwrap();
    let (status, _) = post_token(
        &fx,
        &[
            ("grant_type", "client_credentials"),
            ("client_assertion_type", JWT_BEARER_ASSERTION),
            ("client_assertion", &forged),
        ],
        None,
    )
    .await;
    assert_eq!(status, 401);
    let wrong_aud = build_assertion(
        "svc-jwt",
        "https://elsewhere.example/token",
        SigningAlg::ES256,
        &pair.kid,
        &pair.private_der,
        60,
    )
    .unwrap();
    let (status, _) = post_token(
        &fx,
        &[
            ("grant_type", "client_credentials"),
            ("client_assertion_type", JWT_BEARER_ASSERTION),
            ("client_assertion", &wrong_aud),
        ],
        None,
    )
    .await;
    assert_eq!(status, 401);
    let too_long = build_assertion(
        "svc-jwt",
        &token_endpoint,
        SigningAlg::ES256,
        &pair.kid,
        &pair.private_der,
        3600,
    )
    .unwrap();
    let (status, body) = post_token(
        &fx,
        &[
            ("grant_type", "client_credentials"),
            ("client_assertion_type", JWT_BEARER_ASSERTION),
            ("client_assertion", &too_long),
        ],
        None,
    )
    .await;
    assert_eq!(status, 401);
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("lifetime")
    );

    // Public client cannot do client_credentials at all.
    let spa_id = spa(&fx).await;
    let (_, body) = post_token(
        &fx,
        &[("grant_type", "client_credentials"), ("client_id", &spa_id)],
        None,
    )
    .await;
    assert_eq!(body["error"], "unauthorized_client");
}
