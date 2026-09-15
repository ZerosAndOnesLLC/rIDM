mod common;

use common::TestApp;
use ridm_api::models::{DcrMode, DcrPolicy, TenantSettings};
use ridm_api::services::dcr;
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_core::events::Actor;
use serde_json::{Value, json};

async fn set_mode(app: &TestApp, mode: DcrMode, allowed: Vec<&str>) {
    let settings = TenantSettings {
        dcr: DcrPolicy {
            mode,
            allowed_grants: allowed.into_iter().map(String::from).collect(),
        },
        ..Default::default()
    };
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
}

#[tokio::test]
async fn open_registration_and_management_lifecycle() {
    let app = TestApp::spawn().await;
    // Disabled by default: 403 and no registration_endpoint advertised.
    let res = app
        .http
        .post(app.tenant_url("/register"))
        .json(&json!({"redirect_uris": ["https://a.example/cb"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let doc: Value = app
        .http
        .get(app.tenant_url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(doc.get("registration_endpoint").is_none());

    set_mode(&app, DcrMode::Open, vec![]).await;
    let doc: Value = app
        .http
        .get(app.tenant_url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        doc["registration_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/register")
    );

    let res = app
        .http
        .post(app.tenant_url("/register"))
        .json(&json!({
            "client_name": "Dyn SPA",
            "redirect_uris": ["https://a.example/cb"],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "openid profile",
            "application_type": "web",
            "post_logout_redirect_uris": ["https://a.example/bye"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    assert_eq!(res.headers()["cache-control"], "no-store");
    let reg: Value = res.json().await.unwrap();
    let client_id = reg["client_id"].as_str().unwrap().to_string();
    let rat = reg["registration_access_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(rat.starts_with("rat_"));
    assert!(reg.get("client_secret").is_none(), "public client");
    assert_eq!(reg["client_name"], "Dyn SPA");
    assert_eq!(reg["token_endpoint_auth_method"], "none");
    assert_eq!(
        reg["grant_types"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(reg["scope"], "openid profile");
    assert_eq!(reg["response_types"], json!(["code"]));
    let mgmt = reg["registration_client_uri"].as_str().unwrap().to_string();
    assert_eq!(mgmt, app.tenant_url(&format!("/register/{client_id}")));

    // A confidential registration returns a secret and defaults to basic auth.
    let res = app
        .http
        .post(app.tenant_url("/register"))
        .json(&json!({"redirect_uris": ["https://b.example/cb"]}))
        .send()
        .await
        .unwrap();
    let conf: Value = res.json().await.unwrap();
    assert!(conf["client_secret"].as_str().unwrap().starts_with("cs_"));
    assert_eq!(conf["client_secret_expires_at"], 0);
    assert_eq!(conf["token_endpoint_auth_method"], "client_secret_basic");

    // The registered client works at /authorize (unknown redirect → not registered).
    let res = app
        .http
        .get(app.tenant_url("/authorize"))
        .query(&[
            ("client_id", client_id.as_str()),
            ("redirect_uri", "https://other.example/cb"),
            ("response_type", "code"),
            ("scope", "openid"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);

    // Management: read, update, delete with the registration token.
    let res = app.http.get(&mgmt).bearer_auth(&rat).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let read: Value = res.json().await.unwrap();
    assert_eq!(read["client_id"], client_id);
    assert!(read.get("registration_access_token").is_none());
    let res = app
        .http
        .get(&mgmt)
        .bearer_auth("rat_wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let res = app.http.get(&mgmt).send().await.unwrap();
    assert_eq!(res.status(), 401);
    // Another client's token does not open this one.
    let res = app
        .http
        .get(&mgmt)
        .bearer_auth(conf["registration_access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    let res = app.http.put(&mgmt).bearer_auth(&rat).json(&json!({
        "client_id": client_id, "client_name": "Renamed", "redirect_uris": ["https://a.example/cb", "https://a.example/cb2"],
        "token_endpoint_auth_method": "none", "grant_types": ["authorization_code"], "scope": "openid"
    })).send().await.unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let updated: Value = app
        .http
        .get(&mgmt)
        .bearer_auth(&rat)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated["client_name"], "Renamed");
    assert_eq!(updated["redirect_uris"].as_array().unwrap().len(), 2);
    assert_eq!(updated["grant_types"], json!(["authorization_code"]));
    let res = app
        .http
        .put(&mgmt)
        .bearer_auth(&rat)
        .json(&json!({"client_id": "changed", "redirect_uris": ["https://a.example/cb"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let res = app
        .http
        .put(&mgmt)
        .bearer_auth(&rat)
        .json(&json!({"redirect_uris": ["http://insecure.example/cb"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert_eq!(
        res.json::<Value>().await.unwrap()["error"],
        "invalid_redirect_uri"
    );

    let res = app
        .http
        .delete(&mgmt)
        .bearer_auth(&rat)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    let res = app.http.get(&mgmt).bearer_auth(&rat).send().await.unwrap();
    assert_eq!(res.status(), 401);

    // Metadata validation errors.
    let res = app
        .http
        .post(app.tenant_url("/register"))
        .json(&json!({"redirect_uris": ["https://a.example/cb#frag"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.json::<Value>().await.unwrap()["error"],
        "invalid_redirect_uri"
    );
    let res = app
        .http
        .post(app.tenant_url("/register"))
        .json(&json!({"redirect_uris": ["https://a.example/cb"], "grant_types": ["implicit"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.json::<Value>().await.unwrap()["error"],
        "invalid_client_metadata"
    );
    let res = app
        .http
        .post(app.tenant_url("/register"))
        .json(&json!({"redirect_uris": ["https://a.example/cb"], "response_types": ["token"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.json::<Value>().await.unwrap()["error"],
        "invalid_client_metadata"
    );
    let res = app
        .http
        .post(app.tenant_url("/register"))
        .body("not json")
        .header("content-type", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    // Native apps may use custom schemes; machine clients need no redirect.
    let res = app.http.post(app.tenant_url("/register")).json(&json!({"application_type": "native", "redirect_uris": ["com.example.app:/cb"], "token_endpoint_auth_method": "none"})).send().await.unwrap();
    assert_eq!(res.status(), 201);
    assert_eq!(
        res.json::<Value>().await.unwrap()["application_type"],
        "native"
    );
    let res = app
        .http
        .post(app.tenant_url("/register"))
        .json(&json!({"grant_types": ["client_credentials"], "client_name": "svc"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let svc: Value = res.json().await.unwrap();
    assert!(svc["client_secret"].is_string());
    assert_eq!(svc["response_types"], json!([]));
}

#[tokio::test]
async fn initial_access_tokens_gate_registration_with_a_use_budget() {
    let app = TestApp::spawn().await;
    set_mode(
        &app,
        DcrMode::InitialAccessToken,
        vec!["authorization_code", "refresh_token"],
    )
    .await;
    let body =
        json!({"redirect_uris": ["https://a.example/cb"], "token_endpoint_auth_method": "none"});

    let res = app
        .http
        .post(app.tenant_url("/register"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    assert!(
        res.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("invalid_token")
    );
    let res = app
        .http
        .post(app.tenant_url("/register"))
        .bearer_auth("iat_bogus")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    let iat = dcr::issue_initial_access_token(&app.state, app.tenant.id, 600, 2)
        .await
        .unwrap();
    for _ in 0..2 {
        let res = app
            .http
            .post(app.tenant_url("/register"))
            .bearer_auth(&*iat)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
    }
    let res = app
        .http
        .post(app.tenant_url("/register"))
        .bearer_auth(&*iat)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "budget exhausted");

    // Policy restricts grant types; a disallowed one costs a use but fails.
    let iat = dcr::issue_initial_access_token(&app.state, app.tenant.id, 600, 1)
        .await
        .unwrap();
    let res = app
        .http
        .post(app.tenant_url("/register"))
        .bearer_auth(&*iat)
        .json(&json!({"grant_types": ["client_credentials"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert!(
        res.json::<Value>().await.unwrap()["error_description"]
            .as_str()
            .unwrap()
            .contains("not permitted")
    );

    // Tokens are per tenant.
    let other = common::create_tenant(&app.state.db).await;
    let iat = dcr::issue_initial_access_token(&app.state, app.tenant.id, 600, 1)
        .await
        .unwrap();
    assert!(
        !dcr::consume_initial_access_token(&app.state, other.id, &iat)
            .await
            .unwrap()
    );
    assert!(
        dcr::consume_initial_access_token(&app.state, app.tenant.id, &iat)
            .await
            .unwrap()
    );
    // Revoked tokens stop working.
    let iat = dcr::issue_initial_access_token(&app.state, app.tenant.id, 600, 5)
        .await
        .unwrap();
    dcr::revoke_initial_access_token(&app.state, app.tenant.id, &iat)
        .await
        .unwrap();
    assert!(
        !dcr::consume_initial_access_token(&app.state, app.tenant.id, &iat)
            .await
            .unwrap()
    );
}
