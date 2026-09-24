//! Phase 5.5: admin API for groups.

mod common;

use common::admin::{admin_token, call, get_json, role_id, user_with_role};
use common::{TestApp, create_tenant};
use reqwest::Method;
use ridm_api::models::MASTER_TENANT_ID;
use ridm_api::services::admin_access::{
    ADMIN_ROLE, CLIENT_MANAGER_ROLE, OWNER_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE,
};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn user_manager_runs_the_group_lifecycle_within_reach() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let base = format!("/admin/tenants/{}/groups", app.tenant.slug);
    let manager = admin_token(&app, tid, USER_MANAGER_ROLE).await;
    let owner = admin_token(&app, tid, OWNER_ROLE).await;
    let alice = user_with_role(&app, tid, None).await;
    let bob = user_with_role(&app, tid, None).await;

    let (status, err, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&manager),
        Some(&json!({"name": "staff", "colour": "red"})),
    )
    .await;
    assert_eq!(status, 400, "{err}");
    let (status, staff, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&manager),
        Some(&json!({"name": "staff", "description": "everyone"})),
    )
    .await;
    assert_eq!(status, 201, "{staff}");
    let staff_id = staff["id"].as_str().unwrap().to_string();
    let (status, helpdesk, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&manager),
        Some(&json!({"name": "helpdesk", "parent_id": staff_id})),
    )
    .await;
    assert_eq!(status, 201, "{helpdesk}");
    let helpdesk_id = helpdesk["id"].as_str().unwrap().to_string();
    assert_eq!(helpdesk["parent_id"], staff_id);
    let (status, dup, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&manager),
        Some(&json!({"name": "helpdesk", "parent_id": staff_id})),
    )
    .await;
    assert_eq!(status, 409, "{dup}");

    let (status, list, _) = get_json(&app, &base, Some(&manager)).await;
    assert_eq!(status, 200, "{list}");
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .any(|g| g["id"] == helpdesk_id)
    );

    let (status, detail, _) = get_json(&app, &format!("{base}/{staff_id}"), Some(&manager)).await;
    assert_eq!(status, 200, "{detail}");
    assert_eq!(detail["member_count"], 0);
    assert!(detail["roles"].as_array().unwrap().is_empty());

    // Patch, including the cycle guard.
    let (status, patched, _) = call(
        &app,
        Method::PATCH,
        &format!("{base}/{staff_id}"),
        Some(&manager),
        Some(&json!({"description": null, "name": "Staff"})),
    )
    .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["name"], "Staff");
    assert!(patched["description"].is_null());
    let (status, err, _) = call(
        &app,
        Method::PATCH,
        &format!("{base}/{staff_id}"),
        Some(&manager),
        Some(&json!({"parent_id": helpdesk_id})),
    )
    .await;
    assert_eq!(status, 400, "{err}");

    // Members.
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{helpdesk_id}/members/{alice}"),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, members, _) = get_json(
        &app,
        &format!("{base}/{helpdesk_id}/members"),
        Some(&manager),
    )
    .await;
    assert_eq!(status, 200, "{members}");
    assert_eq!(members["items"][0]["id"], alice.to_string());
    assert!(members["items"][0]["joined_at"].is_string());
    let (_, detail, _) = get_json(&app, &format!("{base}/{helpdesk_id}"), Some(&manager)).await;
    assert_eq!(detail["member_count"], 1);
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{helpdesk_id}/members/{}", Uuid::new_v4()),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 404);

    // Roles on groups: within reach only. Once staff carries ridm:admin, a
    // user manager can no longer add members to it or its children.
    let admin_role = role_id(&app, tid, ADMIN_ROLE).await;
    let (status, err, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{staff_id}/roles/{admin_role}"),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 403, "{err}");
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{staff_id}/roles/{admin_role}"),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (_, roles, _) = get_json(&app, &format!("{base}/{staff_id}/roles"), Some(&manager)).await;
    assert_eq!(roles[0]["name"], ADMIN_ROLE);
    let (status, err, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{helpdesk_id}/members/{bob}"),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 403, "{err}");
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{helpdesk_id}/members/{bob}"),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(status, 204);
    // Removing is always allowed.
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{helpdesk_id}/members/{bob}"),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{staff_id}/roles/{admin_role}"),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (_, roles, _) = get_json(&app, &format!("{base}/{staff_id}/roles"), Some(&manager)).await;
    assert!(roles.as_array().unwrap().is_empty());

    // Delete cascades to children and memberships.
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{staff_id}"),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = get_json(&app, &format!("{base}/{helpdesk_id}"), Some(&manager)).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn built_in_roles_map_onto_group_routes() {
    let app = TestApp::spawn().await;
    let base = format!("/admin/tenants/{}/groups", app.tenant.slug);
    for (role, list, create) in [
        (OWNER_ROLE, 200, 201),
        (ADMIN_ROLE, 200, 201),
        (USER_MANAGER_ROLE, 200, 201),
        (CLIENT_MANAGER_ROLE, 403, 403),
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
            Some(&json!({"name": format!("g-{}", role.replace(':', "-"))})),
        )
        .await;
        assert_eq!(status, create, "{role} create: {body}");
    }
    let (status, _, _) = get_json(&app, &base, None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn groups_are_confined_to_the_admins_tenant() {
    let app = TestApp::spawn().await;
    let other = create_tenant(&app.state.db).await;
    let t = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let global = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;
    let (status, theirs, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/groups", other.slug),
        Some(&global),
        Some(&json!({"name": "theirs"})),
    )
    .await;
    assert_eq!(status, 201, "{theirs}");
    let their_id = theirs["id"].as_str().unwrap();
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/groups/{their_id}", other.slug),
        Some(&t),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/groups/{their_id}", app.tenant.slug),
        Some(&t),
    )
    .await;
    assert_eq!(status, 404);
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/groups/{their_id}", other.slug),
        Some(&global),
    )
    .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn members_come_a_page_at_a_time_in_join_order_and_filter_by_prefix() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let base = format!("/admin/tenants/{}/groups", app.tenant.slug);
    let admin = admin_token(&app, tid, ADMIN_ROLE).await;
    let (status, g, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&admin),
        Some(&json!({"name": "crowd"})),
    )
    .await;
    assert_eq!(status, 201, "{g}");
    let gid = g["id"].as_str().unwrap().to_string();
    let mut joined = vec![];
    for _ in 0..5 {
        let u = user_with_role(&app, tid, None).await;
        let (status, _, _) = call(
            &app,
            Method::PUT,
            &format!("{base}/{gid}/members/{u}"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(status, 204);
        joined.push(u.to_string());
    }

    let mut seen = vec![];
    let mut cursor: Option<String> = None;
    loop {
        let url = match &cursor {
            Some(c) => format!("{base}/{gid}/members?limit=2&cursor={c}"),
            None => format!("{base}/{gid}/members?limit=2"),
        };
        let (status, page, _) = get_json(&app, &url, Some(&admin)).await;
        assert_eq!(status, 200, "{page}");
        let items = page["items"].as_array().unwrap();
        assert!(items.len() <= 2);
        seen.extend(items.iter().map(|m| m["id"].as_str().unwrap().to_string()));
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    assert_eq!(seen, joined, "every member once, in the order they joined");
    let (_, detail, _) = get_json(&app, &format!("{base}/{gid}"), Some(&admin)).await;
    assert_eq!(detail["member_count"], 5);

    // `search` is a prefix of the username or email.
    let (_, one, _) = get_json(&app, &format!("{base}/{gid}/members"), Some(&admin)).await;
    let username = one["items"][2]["username"].as_str().unwrap().to_string();
    let (_, found, _) = get_json(
        &app,
        &format!("{base}/{gid}/members?search={}", &username[..10]),
        Some(&admin),
    )
    .await;
    let found = found["items"].as_array().unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0]["username"], username);
    let (_, none, _) = get_json(
        &app,
        &format!("{base}/{gid}/members?search=zz-nobody"),
        Some(&admin),
    )
    .await;
    assert!(none["items"].as_array().unwrap().is_empty());
}
