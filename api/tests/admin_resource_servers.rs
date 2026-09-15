//! Phase 5.5: admin API for resource servers and permissions.

mod common;

use common::admin::{admin_token, call, get_json};
use common::{TestApp, create_tenant};
use reqwest::Method;
use ridm_api::models::MASTER_TENANT_ID;
use ridm_api::services::admin_access::{
    ADMIN_AUDIENCE, ADMIN_ROLE, CLIENT_MANAGER_ROLE, OWNER_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE,
};
use serde_json::json;

#[tokio::test]
async fn client_manager_runs_the_resource_server_lifecycle() {
    let app = TestApp::spawn().await;
    let base = format!("/admin/tenants/{}/resource-servers", app.tenant.slug);
    let t = admin_token(&app, app.tenant.id, CLIENT_MANAGER_ROLE).await;

    for body in [
        json!({"identifier": "https://api.example", "name": "API", "colour": "red"}),
        json!({"identifier": "has space", "name": "API"}),
        json!({"identifier": "https://api.example", "name": "API", "signing_alg": "HS256"}),
        json!({"identifier": "https://api.example", "name": "API", "token_ttl_secs": 5}),
    ] {
        let (status, err, _) = call(&app, Method::POST, &base, Some(&t), Some(&body)).await;
        assert_eq!(status, 400, "{body} -> {err}");
    }
    let (status, api, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"identifier": "https://api.example", "name": "API", "signing_alg": "ES256"})),
    )
    .await;
    assert_eq!(status, 201, "{api}");
    assert_eq!(api["built_in"], false);
    assert_eq!(api["allow_offline_access"], true);
    let id = api["id"].as_str().unwrap().to_string();
    let (status, dup, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"identifier": "https://api.example", "name": "Again"})),
    )
    .await;
    assert_eq!(status, 409, "{dup}");

    let (status, list, _) = get_json(&app, &base, Some(&t)).await;
    assert_eq!(status, 200, "{list}");
    let builtin = list
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["identifier"] == ADMIN_AUDIENCE)
        .expect("admin resource server is listed");
    assert_eq!(builtin["built_in"], true);
    let builtin_id = builtin["id"].as_str().unwrap().to_string();

    let (status, patched, _) = call(
        &app,
        Method::PATCH,
        &format!("{base}/{id}"),
        Some(&t),
        Some(&json!({"name": "Public API", "token_ttl_secs": 600, "signing_alg": null, "allow_offline_access": false})),
    )
    .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["name"], "Public API");
    assert_eq!(patched["token_ttl_secs"], 600);
    assert!(patched["signing_alg"].is_null());
    assert_eq!(patched["allow_offline_access"], false);

    // Permissions.
    let (status, perm, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{id}/permissions"),
        Some(&t),
        Some(&json!({"name": "docs:read", "description": "read docs"})),
    )
    .await;
    assert_eq!(status, 201, "{perm}");
    let perm_id = perm["id"].as_str().unwrap().to_string();
    let (status, dup, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{id}/permissions"),
        Some(&t),
        Some(&json!({"name": "docs:read"})),
    )
    .await;
    assert_eq!(status, 409, "{dup}");
    let (status, err, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{id}/permissions"),
        Some(&t),
        Some(&json!({"name": "has space"})),
    )
    .await;
    assert_eq!(status, 400, "{err}");
    let (status, detail, _) = get_json(&app, &format!("{base}/{id}"), Some(&t)).await;
    assert_eq!(status, 200, "{detail}");
    assert_eq!(detail["permissions"][0]["name"], "docs:read");
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{id}/permissions/{perm_id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{id}/permissions/{perm_id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);

    // The built-in server and its catalogue are read-only.
    let (status, catalogue, _) =
        get_json(&app, &format!("{base}/{builtin_id}/permissions"), Some(&t)).await;
    assert_eq!(status, 200, "{catalogue}");
    let users_read = catalogue
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "ridm:users:read")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, _, _) = call(
        &app,
        Method::PATCH,
        &format!("{base}/{builtin_id}"),
        Some(&t),
        Some(&json!({"name": "x"})),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{builtin_id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{builtin_id}/permissions"),
        Some(&t),
        Some(&json!({"name": "ridm:extra:read"})),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{builtin_id}/permissions/{users_read}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 403);

    // Delete.
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
}

#[tokio::test]
async fn built_in_roles_map_onto_resource_server_routes() {
    let app = TestApp::spawn().await;
    let base = format!("/admin/tenants/{}/resource-servers", app.tenant.slug);
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
            Some(&json!({"identifier": format!("urn:{}", role.replace(':', "-")), "name": "x"})),
        )
        .await;
        assert_eq!(status, create, "{role} create: {body}");
    }
    let (status, _, _) = get_json(&app, &base, None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn resource_servers_are_confined_to_the_admins_tenant() {
    let app = TestApp::spawn().await;
    let other = create_tenant(&app.state.db).await;
    let t = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let global = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;
    let (_, theirs, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/resource-servers", other.slug),
        Some(&global),
    )
    .await;
    let their_admin = theirs[0]["id"].as_str().unwrap();
    let (status, _, _) = get_json(
        &app,
        &format!(
            "/admin/tenants/{}/resource-servers/{their_admin}",
            other.slug
        ),
        Some(&t),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = get_json(
        &app,
        &format!(
            "/admin/tenants/{}/resource-servers/{their_admin}",
            app.tenant.slug
        ),
        Some(&t),
    )
    .await;
    assert_eq!(status, 404);
}
