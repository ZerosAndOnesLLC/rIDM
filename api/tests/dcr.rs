mod common;

use common::TestApp;
use ridm_api::models::{DcrMode, DcrPolicy, NewInitialAccessToken, TenantSettings};
use ridm_api::services::dcr;
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_core::events::Actor;
use serde_json::{Value, json};

/// Issue an initial access token through the service; returns its id and secret.
async fn issue_iat(app: &TestApp, ttl_secs: u64, uses: u32) -> (uuid::Uuid, String) {
    let created = dcr::issue(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewInitialAccessToken {
            description: Some("test".into()),
            expires_in_secs: Some(ttl_secs),
            max_uses: Some(uses),
        },
    )
    .await
    .unwrap();
    (created.record.id, created.token)
}

async fn set_mode(app: &TestApp, mode: DcrMode, allowed: Vec<&str>) {
    set_policy(app, mode, allowed, true).await;
}

async fn set_policy(app: &TestApp, mode: DcrMode, allowed: Vec<&str>, require_pkce: bool) {
    let settings = TenantSettings {
        dcr: DcrPolicy {
            mode,
            allowed_grants: allowed.into_iter().map(String::from).collect(),
            require_pkce,
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

    let (_, iat) = issue_iat(&app, 600, 2).await;
    for _ in 0..2 {
        let res = app
            .http
            .post(app.tenant_url("/register"))
            .bearer_auth(&iat)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
    }
    let res = app
        .http
        .post(app.tenant_url("/register"))
        .bearer_auth(&iat)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "budget exhausted");

    // Policy restricts grant types; a disallowed one costs a use but fails.
    let (_, iat) = issue_iat(&app, 600, 1).await;
    let res = app
        .http
        .post(app.tenant_url("/register"))
        .bearer_auth(&iat)
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
    let (_, iat) = issue_iat(&app, 600, 1).await;
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
    let (id, iat) = issue_iat(&app, 600, 5).await;
    dcr::revoke(&app.state, app.tenant.id, Actor::System, id)
        .await
        .unwrap();
    assert!(
        !dcr::consume_initial_access_token(&app.state, app.tenant.id, &iat)
            .await
            .unwrap()
    );
}

/// `dcr.require_pkce` decides whether a dynamically registered confidential
/// client may authorize without a code challenge; public clients always must.
#[tokio::test]
async fn pkce_requirement_for_registered_clients_follows_the_policy() {
    let app = TestApp::spawn().await;
    let register = |auth: &'static str| {
        let app = &app;
        async move {
            let res = app
                .http
                .post(app.tenant_url("/register"))
                .json(&json!({
                    "redirect_uris": ["https://rp.example/cb"],
                    "token_endpoint_auth_method": auth,
                }))
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), 201);
            let reg: Value = res.json().await.unwrap();
            reg["client_id"].as_str().unwrap().to_string()
        }
    };
    let authorize = |client_id: String| {
        let app = &app;
        async move {
            let res = app
                .http
                .get(app.tenant_url("/authorize"))
                .query(&[
                    ("client_id", client_id.as_str()),
                    ("redirect_uri", "https://rp.example/cb"),
                    ("response_type", "code"),
                    ("scope", "openid"),
                    ("state", "s"),
                ])
                .send()
                .await
                .unwrap();
            assert!(res.status().is_redirection(), "{}", res.status());
            res.headers()["location"].to_str().unwrap().to_string()
        }
    };

    // Default policy: every registered client must send a code challenge.
    set_policy(&app, DcrMode::Open, vec![], true).await;
    let confidential = register("client_secret_basic").await;
    let location = authorize(confidential).await;
    assert!(
        location.starts_with("https://rp.example/cb?")
            && location.contains("error=invalid_request"),
        "{location}"
    );

    // Relaxed policy: a confidential client proceeds to the login page.
    set_policy(&app, DcrMode::Open, vec![], false).await;
    let confidential = register("client_secret_basic").await;
    let location = authorize(confidential).await;
    assert!(
        location.starts_with(app.state.config.ui_url.as_str()) && !location.contains("error="),
        "{location}"
    );
    // A public client still must use PKCE.
    let public = register("none").await;
    let location = authorize(public).await;
    assert!(
        location.starts_with("https://rp.example/cb?")
            && location.contains("error=invalid_request"),
        "{location}"
    );
}

/// The admin API issues, lists and revokes initial access tokens, so
/// `dcr.mode = initial_access_token` is usable without touching the service
/// layer: the secret is shown once, the list never shows it, an expiry and a
/// use budget are honoured, and a revoked token stops registering at once.
#[tokio::test]
async fn admins_issue_list_and_revoke_initial_access_tokens() {
    use common::admin::{admin_token, call};
    use reqwest::Method;
    use ridm_api::services::admin_access::{CLIENT_MANAGER_ROLE, VIEWER_ROLE};

    let app = TestApp::spawn().await;
    set_mode(
        &app,
        DcrMode::InitialAccessToken,
        vec!["authorization_code", "refresh_token"],
    )
    .await;
    let manager = admin_token(&app, app.tenant.id, CLIENT_MANAGER_ROLE).await;
    let viewer = admin_token(&app, app.tenant.id, VIEWER_ROLE).await;
    let path = format!(
        "/admin/tenants/{}/dcr/initial-access-tokens",
        app.tenant.slug
    );

    // Issue: the token comes back once, with its limits.
    let (status, created, _) = call(
        &app,
        Method::POST,
        &path,
        Some(&manager),
        Some(&json!({"description": "ci", "expires_in_secs": 3600, "max_uses": 1})),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let token = created["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("iat_"));
    assert_eq!(created["max_uses"], 1);
    assert_eq!(created["uses"], 0);
    assert!(created["expires_at"].is_string());
    let id = created["id"].as_str().unwrap().to_string();

    // A viewer may not issue one; bad limits are refused.
    let (status, _, _) = call(&app, Method::POST, &path, Some(&viewer), Some(&json!({}))).await;
    assert_eq!(status, 403);
    for bad in [json!({"max_uses": 0}), json!({"expires_in_secs": 0})] {
        let (status, _, _) = call(&app, Method::POST, &path, Some(&manager), Some(&bad)).await;
        assert_eq!(status, 400, "{bad}");
    }

    // It registers a client, once.
    let body =
        json!({"redirect_uris": ["https://a.example/cb"], "token_endpoint_auth_method": "none"});
    let register = |bearer: String| {
        let app = &app;
        let body = body.clone();
        async move {
            app.http
                .post(app.tenant_url("/register"))
                .bearer_auth(bearer)
                .json(&body)
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(register(token.clone()).await, 201);
    assert_eq!(register(token.clone()).await, 401, "one use only");

    // The list shows the use and never the secret; a viewer may read it.
    let (status, list, _) = call(&app, Method::GET, &path, Some(&viewer), None).await;
    assert_eq!(status, 200);
    let row = list
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == id.as_str())
        .unwrap();
    assert_eq!(row["uses"], 1);
    assert_eq!(row["description"], "ci");
    assert!(row.get("token").is_none() && row.get("token_hash").is_none());
    assert!(!list.to_string().contains(&token));

    // No limits: registers until revoked; revoking is immediate.
    let (_, open, _) = call(&app, Method::POST, &path, Some(&manager), Some(&json!({}))).await;
    assert!(open["expires_at"].is_null() && open["max_uses"].is_null());
    let open_token = open["token"].as_str().unwrap().to_string();
    assert_eq!(register(open_token.clone()).await, 201);
    assert_eq!(register(open_token.clone()).await, 201);
    let revoke = format!("{path}/{}", open["id"].as_str().unwrap());
    let (status, _, _) = call(&app, Method::DELETE, &revoke, Some(&viewer), None).await;
    assert_eq!(status, 403);
    let (status, _, _) = call(&app, Method::DELETE, &revoke, Some(&manager), None).await;
    assert_eq!(status, 204);
    assert_eq!(register(open_token).await, 401);
    let (status, _, _) = call(&app, Method::DELETE, &revoke, Some(&manager), None).await;
    assert_eq!(status, 404, "already revoked");
}
