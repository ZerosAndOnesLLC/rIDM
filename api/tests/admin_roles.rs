//! Phase 5.5: admin API for roles, composites and permission grants.

mod common;

use common::admin::{admin_token, call, get_json, role_id, user_with_role};
use common::{TestApp, create_tenant};
use reqwest::Method;
use ridm_api::models::{MASTER_TENANT_ID, NewClient, NewPermission, NewResourceServer};
use ridm_api::services::admin_access::{
    ADMIN_ROLE, CLIENT_MANAGER_ROLE, OWNER_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE,
};
use ridm_api::services::{clients, resource_servers};
use ridm_core::events::Actor;
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn admin_runs_the_role_lifecycle_with_composites_and_grants() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let base = format!("/admin/tenants/{}/roles", app.tenant.slug);
    let admin = admin_token(&app, tid, ADMIN_ROLE).await;
    let owner = admin_token(&app, tid, OWNER_ROLE).await;

    // Create realm and client roles.
    let (status, err, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&admin),
        Some(&json!({"name": "editor", "colour": "red"})),
    )
    .await;
    assert_eq!(status, 400, "{err}");
    let (status, editor, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&admin),
        Some(&json!({"name": "editor", "description": "edits"})),
    )
    .await;
    assert_eq!(status, 201, "{editor}");
    let editor_id = editor["id"].as_str().unwrap().to_string();
    let client = clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            name: "app".into(),
            client_type: Some(ridm_api::models::ClientType::Machine),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .client;
    let (status, app_admin, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&admin),
        Some(&json!({"name": "app-admin", "client_id": client.id})),
    )
    .await;
    assert_eq!(status, 201, "{app_admin}");
    let (status, dup, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&admin),
        Some(&json!({"name": "editor"})),
    )
    .await;
    assert_eq!(status, 409, "{dup}");

    // List filters.
    let (_, all, _) = get_json(&app, &base, Some(&admin)).await;
    let names = |v: &serde_json::Value| -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect()
    };
    assert!(names(&all).contains(&"editor".into()) && names(&all).contains(&"app-admin".into()));
    assert!(names(&all).contains(&OWNER_ROLE.into()), "built-ins listed");
    let (_, realm, _) = get_json(&app, &format!("{base}?realm_only=true"), Some(&admin)).await;
    assert!(!names(&realm).contains(&"app-admin".into()));
    let (_, of_client, _) = get_json(
        &app,
        &format!("{base}?client_id={}", client.id),
        Some(&admin),
    )
    .await;
    assert_eq!(names(&of_client), vec!["app-admin".to_string()]);

    // Detail and patch; built-ins are immutable.
    let (status, detail, _) = get_json(&app, &format!("{base}/{editor_id}"), Some(&admin)).await;
    assert_eq!(status, 200, "{detail}");
    assert!(detail["composites"].as_array().unwrap().is_empty());
    assert!(detail["permissions"].as_array().unwrap().is_empty());
    let (status, patched, _) = call(
        &app,
        Method::PATCH,
        &format!("{base}/{editor_id}"),
        Some(&admin),
        Some(&json!({"description": null})),
    )
    .await;
    assert_eq!(status, 200, "{patched}");
    assert!(patched["description"].is_null());
    let owner_role = role_id(&app, tid, OWNER_ROLE).await;
    let (status, _, _) = call(
        &app,
        Method::PATCH,
        &format!("{base}/{owner_role}"),
        Some(&owner),
        Some(&json!({"name": "boss"})),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{owner_role}"),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(status, 403);

    // Composites: cycles refused, built-in parents immutable, escalation guarded.
    let (status, reviewer, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&admin),
        Some(&json!({"name": "reviewer"})),
    )
    .await;
    assert_eq!(status, 201, "{reviewer}");
    let reviewer_id = reviewer["id"].as_str().unwrap().to_string();
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{editor_id}/composites/{reviewer_id}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (_, comps, _) = get_json(
        &app,
        &format!("{base}/{editor_id}/composites"),
        Some(&admin),
    )
    .await;
    assert_eq!(comps[0]["name"], "reviewer");
    let (status, err, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{reviewer_id}/composites/{editor_id}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, 400, "cycle: {err}");
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{owner_role}/composites/{editor_id}"),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(status, 403, "built-in parent");
    let (status, err, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{editor_id}/composites/{owner_role}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, 403, "{err}");
    assert!(err["detail"].as_str().unwrap().contains("cannot grant"));
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{editor_id}/composites/{owner_role}"),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{editor_id}/composites/{owner_role}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, 204);

    // Permission grants: custom API permissions freely, admin catalogue within reach.
    let api = resource_servers::create(
        &app.state,
        tid,
        Actor::System,
        NewResourceServer {
            identifier: "https://api.example".into(),
            name: "API".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let read_docs = resource_servers::create_permission(
        &app.state,
        tid,
        Actor::System,
        api.id,
        NewPermission {
            name: "docs:read".into(),
            description: None,
        },
    )
    .await
    .unwrap();
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{editor_id}/permissions/{}", read_docs.id),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (_, perms, _) = get_json(
        &app,
        &format!("{base}/{editor_id}/permissions"),
        Some(&admin),
    )
    .await;
    assert_eq!(perms[0]["name"], "docs:read");
    let admin_rs = resource_servers::list(&app.state, tid)
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.identifier == "urn:ridm:admin")
        .unwrap();
    let catalogue = resource_servers::list_permissions(&app.state, tid, admin_rs.id)
        .await
        .unwrap();
    let tenants_create = catalogue
        .iter()
        .find(|p| p.name == "ridm:tenants:create")
        .unwrap();
    let users_read = catalogue
        .iter()
        .find(|p| p.name == "ridm:users:read")
        .unwrap();
    let (status, err, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{editor_id}/permissions/{}", tenants_create.id),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, 403, "{err}");
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{editor_id}/permissions/{}", users_read.id),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{owner_role}/permissions/{}", read_docs.id),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(status, 403, "built-in role grants are fixed");

    // A holder of `editor` now has ridm:users:read, immediately.
    let holder = user_with_role(&app, tid, Some("editor")).await;
    let tenant = ridm_api::services::tenants::get(&app.state, tid)
        .await
        .unwrap();
    let holder_token =
        common::admin::token(&app, &tenant, holder, common::admin::TokenOpts::default()).await;
    let (status, me, _) = get_json(&app, "/admin/me", Some(&holder_token)).await;
    assert_eq!(status, 200, "{me}");
    assert!(
        me["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "ridm:users:read")
    );
    let (_, holders, _) =
        get_json(&app, &format!("{base}/{editor_id}/holders"), Some(&admin)).await;
    assert!(
        holders["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["user_id"] == holder.to_string() && h["username"].is_string()),
        "{holders}"
    );
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{editor_id}/permissions/{}", users_read.id),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{editor_id}/permissions/{}", users_read.id),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, 404);
    // That was the holder's only admin permission: the same token is now refused.
    let (status, me, _) = get_json(&app, "/admin/me", Some(&holder_token)).await;
    assert_eq!(status, 403, "revocation is immediate: {me}");

    // Delete.
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{editor_id}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = get_json(&app, &format!("{base}/{editor_id}"), Some(&admin)).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn built_in_roles_map_onto_role_routes() {
    let app = TestApp::spawn().await;
    let base = format!("/admin/tenants/{}/roles", app.tenant.slug);
    for (role, list, create) in [
        (OWNER_ROLE, 200, 201),
        (ADMIN_ROLE, 200, 201),
        (USER_MANAGER_ROLE, 200, 403),
        (CLIENT_MANAGER_ROLE, 200, 403),
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
            Some(&json!({"name": format!("r-{}", role.replace(':', "-"))})),
        )
        .await;
        assert_eq!(status, create, "{role} create: {body}");
    }
    let (status, _, _) = get_json(&app, &base, None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn roles_are_confined_to_the_admins_tenant() {
    let app = TestApp::spawn().await;
    let other = create_tenant(&app.state.db).await;
    let t = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let global = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;
    let their_owner = role_id(&app, other.id, OWNER_ROLE).await;
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/roles/{their_owner}", other.slug),
        Some(&t),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/roles/{their_owner}", app.tenant.slug),
        Some(&t),
    )
    .await;
    assert_eq!(status, 404);
    let (status, _, _) = get_json(
        &app,
        &format!(
            "/admin/tenants/{}/roles/{}",
            app.tenant.slug,
            Uuid::new_v4()
        ),
        Some(&global),
    )
    .await;
    assert_eq!(status, 404);
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/roles/{their_owner}", other.slug),
        Some(&global),
    )
    .await;
    assert_eq!(status, 200);
}
