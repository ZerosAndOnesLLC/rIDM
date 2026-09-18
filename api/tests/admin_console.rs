//! The built-in `ridm-admin-console` client: seeded per tenant, pinned to
//! `UI_URL`, undeletable, kept out of tenant documents, and able to obtain
//! admin-audience tokens through the public PKCE flow.

mod common;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::TestApp;
use common::admin::{admin_token, call, user_with_role};
use reqwest::Method;
use ridm_api::models::{MASTER_TENANT_ID, NewClient};
use ridm_api::services::admin_access::{ADMIN_AUDIENCE, OWNER_ROLE};
use ridm_api::services::admin_console::{self, CONSOLE_CLIENT_ID};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::{clients, tenants};
use ridm_core::events::Actor;
use serde_json::{Value, json};

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

#[tokio::test]
async fn console_client_is_seeded_and_follows_ui_url() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let callback = admin_console::callback_uri(&app.state.config);
    assert_eq!(callback, format!("{}/console/callback/", app.base_url));

    let created = admin_console::ensure(&app.state, tid).await.unwrap();
    assert_eq!(created.client_id, CONSOLE_CLIENT_ID);
    assert!(created.is_public());
    assert!(created.require_pkce);
    assert!(!created.require_consent);
    assert_eq!(created.redirect_uris, vec![callback.clone()]);
    assert_eq!(
        created.post_logout_redirect_uris,
        vec![format!("{}/console/", app.base_url)]
    );
    assert_eq!(created.allowed_audiences, vec![ADMIN_AUDIENCE.to_string()]);
    assert!(created.allows_grant("authorization_code"));
    assert!(created.allows_grant("refresh_token"));

    // Idempotent.
    let again = admin_console::ensure(&app.state, tid).await.unwrap();
    assert_eq!(again.id, created.id);
    assert_eq!(again.updated_at, created.updated_at);

    // An administrator tunes the token lifetime and someone moves the redirect
    // URI: the next startup restores the URI and keeps the tuning.
    let (_, _) = clients::update_metadata(
        &app.state,
        tid,
        Actor::System,
        created.id,
        NewClient {
            name: "Console (renamed)".into(),
            redirect_uris: vec!["https://elsewhere.example/cb".into()],
            access_token_ttl_secs: Some(120),
            allowed_audiences: vec![],
            ..admin_console::desired(&app.state.config)
        },
    )
    .await
    .unwrap();
    let restored = admin_console::ensure(&app.state, tid).await.unwrap();
    assert_eq!(restored.id, created.id);
    assert_eq!(restored.redirect_uris, vec![callback]);
    assert_eq!(restored.allowed_audiences, vec![ADMIN_AUDIENCE.to_string()]);
    assert_eq!(restored.access_token_ttl_secs, Some(120));
    assert_eq!(restored.name, "Console (renamed)");
}

#[tokio::test]
async fn new_tenants_get_the_console_client() {
    let app = TestApp::spawn().await;
    let t = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;
    let slug = format!(
        "console-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let (status, _, _) = call(
        &app,
        Method::POST,
        "/admin/tenants",
        Some(&t),
        Some(&json!({"slug": slug, "display_name": "Console tenant"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body, _) = call(
        &app,
        Method::GET,
        &format!("/admin/tenants/{slug}/clients/{CONSOLE_CLIENT_ID}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["client_id"], CONSOLE_CLIENT_ID);
    assert_eq!(body["allowed_audiences"], json!([ADMIN_AUDIENCE]));

    // Startup brings every tenant in line, including ones created by hand.
    admin_console::ensure_all(&app.state).await.unwrap();
    let mine = clients::find_by_client_id(&app.state, app.tenant.id, CONSOLE_CLIENT_ID)
        .await
        .unwrap();
    assert!(mine.is_some());
}

#[tokio::test]
async fn console_client_is_built_in() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let slug = app.tenant.slug.clone();
    admin_console::ensure(&app.state, tid).await.unwrap();
    let t = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;

    let (status, body, _) = call(
        &app,
        Method::DELETE,
        &format!("/admin/tenants/{slug}/clients/{CONSOLE_CLIENT_ID}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Not part of the tenant document...
    let (status, doc, _) = call(
        &app,
        Method::GET,
        &format!("/admin/tenants/{slug}/export"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        doc["clients"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["client_id"] != CONSOLE_CLIENT_ID),
        "{doc}"
    );
    // ...so a prune never plans its deletion...
    let (status, plan, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{slug}/import?dry_run=true&prune=true"),
        Some(&t),
        Some(&doc),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{plan}");
    assert_eq!(plan["summary"]["delete"], 0, "{plan}");
    // ...and a document that lists it is refused.
    let mut with_console = doc.clone();
    with_console["clients"].as_array_mut().unwrap().push(json!({
        "client_id": CONSOLE_CLIENT_ID,
        "status": "active",
        "service_account": false,
        "metadata": {"name": "Console", "client_type": "spa"}
    }));
    let (status, body, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{slug}/import?dry_run=true"),
        Some(&t),
        Some(&with_console),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["detail"].as_str().unwrap().contains("built in"));
}

#[tokio::test]
async fn console_login_yields_admin_tokens() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    admin_console::ensure(&app.state, tid).await.unwrap();
    let admin = user_with_role(&app, tid, Some(OWNER_ROLE)).await;
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    let session = sessions::create(
        &app.state,
        tid,
        NewSession {
            user_id: admin,
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
        session.id
    );
    let callback = admin_console::callback_uri(&app.state.config);

    // The console never asks for a resource: the client's audience applies.
    let res = app
        .http
        .get(app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", CONSOLE_CLIENT_ID),
            ("redirect_uri", callback.as_str()),
            ("scope", "openid profile email"),
            ("state", "s1"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    assert!(loc.as_str().starts_with(&callback), "{loc}");
    let code = loc
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("code (no consent step for the console)");

    let tokens: Value = app
        .http
        .post(app.tenant_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", CONSOLE_CLIENT_ID),
            ("code", code.as_str()),
            ("redirect_uri", callback.as_str()),
            ("code_verifier", VERIFIER),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let at = tokens["access_token"].as_str().unwrap().to_string();
    let rt = tokens["refresh_token"].as_str().unwrap().to_string();
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(at.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["aud"], ADMIN_AUDIENCE);
    assert_eq!(claims["sid"], session.id.to_string());

    let (status, me, _) = call(&app, Method::GET, "/admin/me", Some(&at), None).await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["user_id"], admin.to_string());
    assert_eq!(me["scope"], "tenant");
    assert!(me["roles"].as_array().unwrap().contains(&json!(OWNER_ROLE)));

    // Refresh keeps the audience.
    let refreshed: Value = app
        .http
        .post(app.tenant_url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", CONSOLE_CLIENT_ID),
            ("refresh_token", rt.as_str()),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let at2 = refreshed["access_token"].as_str().unwrap();
    let (status, _, _) = call(&app, Method::GET, "/admin/me", Some(at2), None).await;
    assert_eq!(status, StatusCode::OK);

    // Signing out of the browser session ends admin access at once.
    sessions::revoke(&app.state, tid, session.id).await.unwrap();
    let (status, _, _) = call(&app, Method::GET, "/admin/me", Some(at2), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
