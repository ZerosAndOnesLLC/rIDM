//! Phase 5.5: admin API for scopes.

mod common;

use common::admin::{admin_token, call, get_json};
use common::{TestApp, create_tenant};
use reqwest::Method;
use ridm_api::models::MASTER_TENANT_ID;
use ridm_api::services::admin_access::{
    ADMIN_ROLE, CLIENT_MANAGER_ROLE, OWNER_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE,
};
use serde_json::{Value, json};

async fn discovery_scopes(app: &TestApp) -> Vec<String> {
    let doc: Value = app
        .http
        .get(app.tenant_url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    doc["scopes_supported"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn client_manager_runs_the_scope_lifecycle() {
    let app = TestApp::spawn().await;
    let base = format!("/admin/tenants/{}/scopes", app.tenant.slug);
    let t = admin_token(&app, app.tenant.id, CLIENT_MANAGER_ROLE).await;

    let (status, list, _) = get_json(&app, &base, Some(&t)).await;
    assert_eq!(status, 200, "{list}");
    let openid = list
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "openid")
        .unwrap()
        .clone();
    assert_eq!(openid["is_default"], true);

    for body in [
        json!({"name": "bad scope"}),
        json!({"name": "read:docs", "colour": "red"}),
    ] {
        let (status, err, _) = call(&app, Method::POST, &base, Some(&t), Some(&body)).await;
        assert_eq!(status, 400, "{body} -> {err}");
    }
    let (status, created, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"name": "read:docs", "description": "Read your docs", "claims": ["docs"]})),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_str().unwrap().to_string();
    let (status, dup, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"name": "read:docs"})),
    )
    .await;
    assert_eq!(status, 409, "{dup}");
    assert!(
        discovery_scopes(&app)
            .await
            .contains(&"read:docs".to_string()),
        "discovery reflects the new scope (cache evicted)"
    );

    let (status, got, _) = get_json(&app, &format!("{base}/{id}"), Some(&t)).await;
    assert_eq!(status, 200, "{got}");
    assert_eq!(got["claims"], json!(["docs"]));
    let (status, patched, _) = call(
        &app,
        Method::PATCH,
        &format!("{base}/{id}"),
        Some(&t),
        Some(&json!({"description": null, "claims": ["docs", "docs_count"], "is_default": true})),
    )
    .await;
    assert_eq!(status, 200, "{patched}");
    assert!(patched["description"].is_null());
    assert_eq!(patched["claims"], json!(["docs", "docs_count"]));
    assert_eq!(patched["is_default"], true);
    let (status, err, _) = call(
        &app,
        Method::PATCH,
        &format!("{base}/{id}"),
        Some(&t),
        Some(&json!({"name": "renamed"})),
    )
    .await;
    assert_eq!(status, 400, "name is immutable: {err}");

    // Standard scopes: tunable, not deletable.
    let openid_id = openid["id"].as_str().unwrap();
    let (status, tuned, _) = call(
        &app,
        Method::PATCH,
        &format!("{base}/{openid_id}"),
        Some(&t),
        Some(&json!({"description": "Sign in"})),
    )
    .await;
    assert_eq!(status, 200, "{tuned}");
    assert_eq!(tuned["description"], "Sign in");
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{openid_id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 400);

    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = get_json(&app, &format!("{base}/{id}"), Some(&t)).await;
    assert_eq!(status, 404);
    assert!(
        !discovery_scopes(&app)
            .await
            .contains(&"read:docs".to_string())
    );
}

#[tokio::test]
async fn built_in_roles_map_onto_scope_routes() {
    let app = TestApp::spawn().await;
    let base = format!("/admin/tenants/{}/scopes", app.tenant.slug);
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
            Some(&json!({"name": format!("s:{}", role.replace(':', "-"))})),
        )
        .await;
        assert_eq!(status, create, "{role} create: {body}");
    }
    let (status, _, _) = get_json(&app, &base, None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn scopes_are_confined_to_the_admins_tenant() {
    let app = TestApp::spawn().await;
    let other = create_tenant(&app.state.db).await;
    let t = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let global = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;
    let (_, theirs, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/scopes", other.slug),
        Some(&global),
    )
    .await;
    let their_openid = theirs[0]["id"].as_str().unwrap();
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/scopes/{their_openid}", other.slug),
        Some(&t),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/scopes/{their_openid}", app.tenant.slug),
        Some(&t),
    )
    .await;
    assert_eq!(status, 404);
}
