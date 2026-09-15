//! Phase 5.5: admin API for claim mappers, including the effect on tokens.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::admin::{admin_token, call, get_json};
use common::{TestApp, create_tenant};
use reqwest::Method;
use ridm_api::models::{ClientType, MASTER_TENANT_ID, NewClient};
use ridm_api::services::admin_access::{
    ADMIN_ROLE, CLIENT_MANAGER_ROLE, OWNER_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE,
};
use ridm_api::services::clients;
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

fn payload(jwt: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

async fn access_token(app: &TestApp, client_id: &str, secret: &str) -> Value {
    let res: Value = app
        .http
        .post(app.tenant_url("/token"))
        .basic_auth(client_id, Some(secret))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    payload(res["access_token"].as_str().unwrap())
}

#[tokio::test]
async fn client_manager_runs_the_mapper_lifecycle_and_tokens_follow() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let base = format!("/admin/tenants/{}/claim-mappers", app.tenant.slug);
    let t = admin_token(&app, tid, CLIENT_MANAGER_ROLE).await;
    let created = clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("robot".into()),
            name: "Robot".into(),
            client_type: Some(ClientType::Machine),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let secret = created.client_secret.unwrap().to_string();
    let other_client = clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            name: "Other".into(),
            client_type: Some(ClientType::Machine),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .client;

    // Validation.
    for (body, needle) in [
        (
            json!({"name": "x", "config": {"type": "hardcoded", "claim": "a", "value": 1, "include_in": ["access"]}, "colour": "red"}),
            "colour",
        ),
        (
            json!({"name": "x", "config": {"type": "nope", "include_in": ["access"]}}),
            "invalid mapper config",
        ),
        (
            json!({"name": "x", "config": {"type": "hardcoded", "claim": "a", "value": 1, "include_in": []}}),
            "include_in",
        ),
        (
            json!({"name": "x", "config": {"type": "hardcoded", "claim": "a", "value": 1, "include_in": ["access"], "name": "y"}}),
            "config.name",
        ),
        (
            json!({"name": "x", "config": {"type": "template", "claim": "a", "template": "{{#if", "include_in": ["access"]}}),
            "compile",
        ),
        (
            json!({"name": "x", "config": ["not", "an", "object"]}),
            "object",
        ),
        (
            json!({"name": "x", "client_id": Uuid::new_v4(), "config": {"type": "hardcoded", "claim": "a", "value": 1, "include_in": ["access"]}}),
            "client_id",
        ),
    ] {
        let (status, err, _) = call(&app, Method::POST, &base, Some(&t), Some(&body)).await;
        assert_eq!(status, 400, "{body} -> {err}");
        assert!(
            err["detail"].as_str().unwrap().contains(needle),
            "{err} should mention {needle}"
        );
    }

    // A tenant-wide mapper reaches every client's tokens at once.
    let before = access_token(&app, "robot", &secret).await;
    assert!(before.get("tier").is_none());
    let (status, tenant_wide, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"name": "tier", "config": {"type": "hardcoded", "claim": "tier", "value": "gold", "include_in": ["access", "id"]}})),
    )
    .await;
    assert_eq!(status, 201, "{tenant_wide}");
    assert!(tenant_wide["client_id"].is_null());
    let tw_id = tenant_wide["id"].as_str().unwrap().to_string();
    assert_eq!(access_token(&app, "robot", &secret).await["tier"], "gold");

    // A client-scoped mapper applies to that client only.
    let (status, scoped, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"name": "region", "client_id": other_client.id, "config": {"type": "hardcoded", "claim": "region", "value": "eu", "include_in": ["access"]}})),
    )
    .await;
    assert_eq!(status, 201, "{scoped}");
    let scoped_id = scoped["id"].as_str().unwrap().to_string();
    assert!(
        access_token(&app, "robot", &secret)
            .await
            .get("region")
            .is_none()
    );

    // Listing: all, or one client's.
    let (_, all, _) = get_json(&app, &base, Some(&t)).await;
    assert_eq!(all.as_array().unwrap().len(), 2);
    let (_, of_other, _) = get_json(
        &app,
        &format!("{base}?client_id={}", other_client.id),
        Some(&t),
    )
    .await;
    assert_eq!(of_other.as_array().unwrap().len(), 1);
    assert_eq!(of_other[0]["id"], scoped_id);
    let (_, tenant_wide_only, _) =
        get_json(&app, &format!("{base}?tenant_wide=true"), Some(&t)).await;
    assert_eq!(tenant_wide_only.as_array().unwrap().len(), 1);
    assert_eq!(tenant_wide_only[0]["id"], tw_id);

    // Patch: name alone, config alone; the config replaces the document.
    let (status, patched, _) = call(
        &app,
        Method::PATCH,
        &format!("{base}/{tw_id}"),
        Some(&t),
        Some(&json!({"name": "plan"})),
    )
    .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["name"], "plan");
    let (status, patched, _) = call(
        &app,
        Method::PATCH,
        &format!("{base}/{tw_id}"),
        Some(&t),
        Some(&json!({"config": {"type": "hardcoded", "claim": "tier", "value": "silver", "include_in": ["access"]}})),
    )
    .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(access_token(&app, "robot", &secret).await["tier"], "silver");
    let (status, err, _) = call(
        &app,
        Method::PATCH,
        &format!("{base}/{tw_id}"),
        Some(&t),
        Some(&json!({"config": {"type": "hardcoded", "claim": "tier", "value": "x", "include_in": ["nowhere"]}})),
    )
    .await;
    assert_eq!(status, 400, "{err}");
    let (status, got, _) = get_json(&app, &format!("{base}/{tw_id}"), Some(&t)).await;
    assert_eq!(status, 200);
    assert_eq!(got["config"]["value"], "silver", "bad patch left no trace");

    // Delete: the claim disappears from tokens at once.
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{tw_id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
    assert!(
        access_token(&app, "robot", &secret)
            .await
            .get("tier")
            .is_none()
    );
    let (status, _, _) = get_json(&app, &format!("{base}/{tw_id}"), Some(&t)).await;
    assert_eq!(status, 404);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{tw_id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn built_in_roles_map_onto_mapper_routes() {
    let app = TestApp::spawn().await;
    let base = format!("/admin/tenants/{}/claim-mappers", app.tenant.slug);
    for (role, list, create) in [
        (OWNER_ROLE, 200, 201),
        (ADMIN_ROLE, 200, 201),
        (CLIENT_MANAGER_ROLE, 200, 201),
        (USER_MANAGER_ROLE, 403, 403),
        (VIEWER_ROLE, 200, 403),
    ] {
        let t = admin_token(&app, app.tenant.id, role).await;
        let (status, body, _) = get_json(&app, &base, Some(&t)).await;
        assert_eq!(status, list, "{role} list: {body}");
        let (status, body, _) = call(
            &app,
            Method::POST,
            &base,
            Some(&t),
            Some(&json!({"name": role, "config": {"type": "hardcoded", "claim": "a", "value": 1, "include_in": ["access"]}})),
        )
        .await;
        assert_eq!(status, create, "{role} create: {body}");
    }
    let (status, _, _) = get_json(&app, &base, None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn mappers_are_confined_to_the_admins_tenant() {
    let app = TestApp::spawn().await;
    let other = create_tenant(&app.state.db).await;
    let t = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let global = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;
    let (status, theirs, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/claim-mappers", other.slug),
        Some(&global),
        Some(&json!({"name": "theirs", "config": {"type": "hardcoded", "claim": "a", "value": 1, "include_in": ["access"]}})),
    )
    .await;
    assert_eq!(status, 201, "{theirs}");
    let their_id = theirs["id"].as_str().unwrap();
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/claim-mappers/{their_id}", other.slug),
        Some(&t),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = get_json(
        &app,
        &format!(
            "/admin/tenants/{}/claim-mappers/{their_id}",
            app.tenant.slug
        ),
        Some(&t),
    )
    .await;
    assert_eq!(status, 404);
}
