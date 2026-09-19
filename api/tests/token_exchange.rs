//! RFC 8693 token exchange: impersonation and delegation on behalf of a
//! subject token's user, scope narrowing, audiences, lifetime, and refusals.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::TestApp;
use common::admin::{TokenOpts, token};
use ridm_api::models::{ClientType, NewClient, NewResourceServer, NewUser, grants};
use ridm_api::services::{clients, denylist, resource_servers, tenants, users};
use ridm_core::events::Actor;
use serde_json::Value;
use std::time::Duration;
use uuid::Uuid;

const TT_ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";
const TT_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

struct Fx {
    app: TestApp,
    user_id: Uuid,
    gateway_id: String,
    gateway_secret: String,
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
    resource_servers::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewResourceServer {
            identifier: "https://orders.example".into(),
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
            allowed_grants: Some(vec![grants::CLIENT_CREDENTIALS.into(), GRANT.into()]),
            allowed_scopes: Some(vec!["openid".into(), "profile".into()]),
            // Exchange demands an explicit entitlement: a client with no
            // allowed audiences may not trade someone else's token for one.
            allowed_audiences: vec!["https://orders.example".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    Fx {
        app,
        user_id: user.id,
        gateway_id: created.client.client_id.clone(),
        gateway_secret: created
            .client_secret
            .as_deref()
            .map(|s| s.to_string())
            .unwrap(),
    }
}

fn claims_of(jwt: &str) -> Value {
    let payload = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

/// A user token as some first-party app would hold it.
async fn subject_token(fx: &Fx) -> String {
    let tenant = tenants::get(&fx.app.state, fx.app.tenant.id).await.unwrap();
    token(
        &fx.app,
        &tenant,
        fx.user_id,
        TokenOpts {
            audiences: &["https://frontend.example"],
            session_id: Some(Uuid::new_v4()),
            ttl: Duration::from_secs(120),
        },
    )
    .await
}

async fn exchange(fx: &Fx, form: &[(&str, &str)]) -> reqwest::Response {
    let mut all = vec![("grant_type", GRANT)];
    all.extend_from_slice(form);
    fx.app
        .http
        .post(fx.app.tenant_url("/token"))
        .basic_auth(&fx.gateway_id, Some(&fx.gateway_secret))
        .form(&all)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn exchanges_a_user_token_for_another_audience() {
    let fx = fixture().await;
    let subject = subject_token(&fx).await;
    let subject_claims = claims_of(&subject);
    let res = exchange(
        &fx,
        &[
            ("subject_token", &subject),
            ("subject_token_type", TT_ACCESS),
            ("audience", "https://orders.example"),
            ("scope", "openid"),
        ],
    )
    .await;
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["issued_token_type"], TT_ACCESS);
    assert_eq!(body["token_type"], "Bearer");
    assert!(body.get("refresh_token").is_none());
    assert_eq!(body["scope"], "openid");
    let claims = claims_of(body["access_token"].as_str().unwrap());
    assert_eq!(claims["sub"], subject_claims["sub"], "same subject");
    assert_eq!(claims["client_id"], "gateway");
    assert_eq!(claims["aud"], "https://orders.example");
    assert_eq!(claims["sid"], subject_claims["sid"], "session inherited");
    assert!(claims.get("act").is_none(), "impersonation carries no act");
    assert!(
        claims["exp"].as_i64().unwrap() <= subject_claims["exp"].as_i64().unwrap(),
        "never outlives the subject token"
    );
    assert!(body["expires_in"].as_i64().unwrap() <= 120);
    // The jwt type name is accepted as well.
    let res = exchange(
        &fx,
        &[("subject_token", &subject), ("subject_token_type", TT_JWT)],
    )
    .await;
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn delegation_records_the_actor_and_nests() {
    let fx = fixture().await;
    let subject = subject_token(&fx).await;
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .basic_auth(&fx.gateway_id, Some(&fx.gateway_secret))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap();
    let actor: Value = res.json().await.unwrap();
    let actor_token = actor["access_token"].as_str().unwrap().to_string();

    let res = exchange(
        &fx,
        &[
            ("subject_token", &subject),
            ("subject_token_type", TT_ACCESS),
            ("actor_token", &actor_token),
            ("actor_token_type", TT_ACCESS),
        ],
    )
    .await;
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let first = body["access_token"].as_str().unwrap().to_string();
    let claims = claims_of(&first);
    assert_eq!(claims["act"]["sub"], "gateway");
    assert_eq!(claims["act"]["client_id"], "gateway");
    assert!(claims["act"].get("act").is_none());

    // Exchanging the delegated token again nests the previous actor.
    let res = exchange(
        &fx,
        &[
            ("subject_token", &first),
            ("subject_token_type", TT_ACCESS),
            ("actor_token", &actor_token),
            ("actor_token_type", TT_ACCESS),
        ],
    )
    .await;
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let claims = claims_of(body["access_token"].as_str().unwrap());
    assert_eq!(claims["act"]["sub"], "gateway");
    assert_eq!(claims["act"]["act"]["sub"], "gateway");

    // The pair must be complete.
    let res = exchange(
        &fx,
        &[
            ("subject_token", &subject),
            ("subject_token_type", TT_ACCESS),
            ("actor_token", &actor_token),
        ],
    )
    .await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn scope_can_only_narrow_and_stays_within_the_client() {
    let fx = fixture().await;
    let subject = subject_token(&fx).await; // scope: openid
    let res = exchange(
        &fx,
        &[
            ("subject_token", &subject),
            ("subject_token_type", TT_ACCESS),
            ("scope", "openid profile"),
        ],
    )
    .await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["error"], "invalid_scope",
        "profile not held by the subject"
    );

    let tenant = tenants::get(&fx.app.state, fx.app.tenant.id).await.unwrap();
    let wide = ridm_api::services::tokens::issue_access_token(
        &fx.app.state,
        ridm_api::services::tokens::AccessTokenRequest {
            tenant: &tenant,
            client: &ridm_api::services::tokens::TokenClient::public("frontend"),
            user: Some(
                &users::get(&fx.app.state, tenant.id, fx.user_id)
                    .await
                    .unwrap(),
            ),
            scopes: &["openid".into(), "email".into()],
            audiences: &[],
            roles: &[],
            groups: &[],
            session_id: None,
            org_id: None,
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
    // Without a scope parameter the result is the intersection with the client's scopes.
    let res = exchange(
        &fx,
        &[("subject_token", &wide), ("subject_token_type", TT_ACCESS)],
    )
    .await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["scope"], "openid");
    // Asking for a held scope the client may not have is refused.
    let res = exchange(
        &fx,
        &[
            ("subject_token", &wide),
            ("subject_token_type", TT_ACCESS),
            ("scope", "email"),
        ],
    )
    .await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_scope");
}

#[tokio::test]
async fn refusals() {
    let fx = fixture().await;
    let subject = subject_token(&fx).await;

    let res = exchange(&fx, &[("subject_token_type", TT_ACCESS)]).await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");

    let res = exchange(
        &fx,
        &[
            ("subject_token", &subject),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:saml2",
            ),
        ],
    )
    .await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");

    let res = exchange(
        &fx,
        &[
            ("subject_token", "not.a.jwt"),
            ("subject_token_type", TT_ACCESS),
        ],
    )
    .await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");

    let res = exchange(
        &fx,
        &[
            ("subject_token", &subject),
            ("subject_token_type", TT_ACCESS),
            (
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:id_token",
            ),
        ],
    )
    .await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");

    let res = exchange(
        &fx,
        &[
            ("subject_token", &subject),
            ("subject_token_type", TT_ACCESS),
            ("audience", "https://nowhere.example"),
        ],
    )
    .await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_target");

    // A revoked subject token is no good.
    let claims = claims_of(&subject);
    denylist::deny(
        &fx.app.state,
        fx.app.tenant.id,
        claims["jti"].as_str().unwrap(),
        chrono::Utc::now() + chrono::Duration::minutes(5),
    )
    .await
    .unwrap();
    let res = exchange(
        &fx,
        &[
            ("subject_token", &subject),
            ("subject_token_type", TT_ACCESS),
        ],
    )
    .await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");

    // A client without the grant.
    let plain = clients::create(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("plain".into()),
            name: "plain".into(),
            client_type: Some(ClientType::Machine),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .basic_auth("plain", plain.client_secret.as_deref().map(|s| s.as_str()))
        .form(&[
            ("grant_type", GRANT),
            ("subject_token", subject.as_str()),
            ("subject_token_type", TT_ACCESS),
        ])
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "unauthorized_client");
}

#[tokio::test]
async fn discovery_advertises_the_grant() {
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
    assert!(
        doc["grant_types_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g == GRANT)
    );
}

/// Phase 9.12 review finding. On every other grant an empty
/// `allowed_audiences` means "no restriction", because the client acts for a
/// user who authorized it. A subject token presented here may have been minted
/// for someone else entirely, so an unrestricted client could have traded any
/// live token of the tenant for one aimed anywhere, carrying that user's
/// identity and permissions. Exchange demands an explicit entitlement.
#[tokio::test]
async fn exchange_needs_an_explicit_audience_entitlement() {
    let fx = fixture().await;
    let subject = subject_token(&fx).await;

    // A second client with the grant but nothing it may exchange for.
    let created = clients::create(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("unentitled".into()),
            name: "Unentitled".into(),
            client_type: Some(ClientType::Machine),
            allowed_grants: Some(vec![GRANT.into()]),
            allowed_scopes: Some(vec!["openid".into()]),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let secret = created.client_secret.as_deref().unwrap().to_string();

    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .basic_auth("unentitled", Some(&secret))
        .form(&[
            ("grant_type", GRANT),
            ("subject_token", subject.as_str()),
            ("subject_token_type", TT_ACCESS),
            ("audience", "https://orders.example"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_target", "{body}");

    // The entitled client still exchanges for the audience it holds, and for
    // nothing else.
    let ok = exchange(
        &fx,
        &[
            ("subject_token", &subject),
            ("subject_token_type", TT_ACCESS),
            ("audience", "https://orders.example"),
        ],
    )
    .await;
    assert_eq!(ok.status(), 200);
    let res = exchange(
        &fx,
        &[
            ("subject_token", &subject),
            ("subject_token_type", TT_ACCESS),
            ("audience", "https://elsewhere.example"),
        ],
    )
    .await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_target", "{body}");
}
