//! Phase 5.10: IP rules configuration.

mod common;

use common::admin::{admin_token, call, get_json};
use common::{TestApp, create_tenant};
use reqwest::Method;
use ridm_api::models::{ClientType, MASTER_TENANT_ID, NewClient};
use ridm_api::services::admin_access::{
    ADMIN_ROLE, CLIENT_MANAGER_ROLE, OWNER_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE,
};
use ridm_api::services::clients;
use ridm_core::events::Actor;
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn admin_runs_the_ip_rule_lifecycle() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let base = format!("/admin/tenants/{}/ip-rules", app.tenant.slug);
    let t = admin_token(&app, tid, ADMIN_ROLE).await;
    let client = clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            name: "app".into(),
            client_type: Some(ClientType::Machine),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .client;

    for body in [
        json!({"cidr": "not-an-ip"}),
        json!({"cidr": "10.0.0.0/33"}),
        json!({"cidr": "10.0.0.0/8", "action": "maybe"}),
        json!({"cidr": "10.0.0.0/8", "client_id": Uuid::new_v4()}),
        json!({"cidr": "10.0.0.0/8", "colour": "red"}),
    ] {
        let (status, err, _) = call(&app, Method::POST, &base, Some(&t), Some(&body)).await;
        assert_eq!(status, 400, "{body} -> {err}");
    }

    // Tenant-wide deny (default action) with normalization, plus a client allow.
    let (status, deny, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"cidr": "203.0.113.9/24", "description": "office egress"})),
    )
    .await;
    assert_eq!(status, 201, "{deny}");
    assert_eq!(deny["action"], "deny");
    assert_eq!(deny["cidr"], "203.0.113.0/24");
    assert!(deny["client_id"].is_null());
    let deny_id = deny["id"].as_str().unwrap().to_string();
    let (status, dup, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"cidr": "203.0.113.0/24", "action": "allow"})),
    )
    .await;
    assert_eq!(status, 409, "{dup}");
    let (status, allow, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"cidr": "2001:db8::1", "action": "allow", "client_id": client.id})),
    )
    .await;
    assert_eq!(status, 201, "{allow}");
    assert_eq!(allow["cidr"], "2001:db8::1/128");
    assert_eq!(allow["client_id"], client.id.to_string());

    // Listing: all, tenant-wide, one client's.
    let (_, all, _) = get_json(&app, &base, Some(&t)).await;
    assert_eq!(all.as_array().unwrap().len(), 2);
    let (_, tenant_wide, _) = get_json(&app, &format!("{base}?tenant_wide=true"), Some(&t)).await;
    assert_eq!(tenant_wide.as_array().unwrap().len(), 1);
    assert_eq!(tenant_wide[0]["id"], deny_id);
    let (_, of_client, _) =
        get_json(&app, &format!("{base}?client_id={}", client.id), Some(&t)).await;
    assert_eq!(of_client.as_array().unwrap().len(), 1);

    // Patch and delete.
    let (status, patched, _) = call(
        &app,
        Method::PATCH,
        &format!("{base}/{deny_id}"),
        Some(&t),
        Some(&json!({"action": "allow", "cidr": "203.0.113.0/25", "description": null})),
    )
    .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["action"], "allow");
    assert_eq!(patched["cidr"], "203.0.113.0/25");
    assert!(patched["description"].is_null());
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{deny_id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = get_json(&app, &format!("{base}/{deny_id}"), Some(&t)).await;
    assert_eq!(status, 404);
    // Deleting the client takes its rules along.
    clients::delete(&app.state, tid, Actor::System, client.id)
        .await
        .unwrap();
    let (_, left, _) = get_json(&app, &base, Some(&t)).await;
    assert!(left.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn ip_rules_follow_tenant_permissions_and_confinement() {
    let app = TestApp::spawn().await;
    let base = format!("/admin/tenants/{}/ip-rules", app.tenant.slug);
    for (i, (role, list, create)) in [
        (OWNER_ROLE, 200, 201),
        (ADMIN_ROLE, 200, 201),
        (USER_MANAGER_ROLE, 200, 403),
        (CLIENT_MANAGER_ROLE, 200, 403),
        (VIEWER_ROLE, 200, 403),
    ]
    .into_iter()
    .enumerate()
    {
        let t = admin_token(&app, app.tenant.id, role).await;
        let (status, body, _) = get_json(&app, &base, Some(&t)).await;
        assert_eq!(status, list, "{role} list: {body}");
        let (status, body, _) = call(
            &app,
            Method::POST,
            &base,
            Some(&t),
            Some(&json!({"cidr": format!("10.{i}.0.0/16")})),
        )
        .await;
        assert_eq!(status, create, "{role} create: {body}");
    }
    let other = create_tenant(&app.state.db).await;
    let t = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let global = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;
    let (status, theirs, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/ip-rules", other.slug),
        Some(&global),
        Some(&json!({"cidr": "192.0.2.0/24"})),
    )
    .await;
    assert_eq!(status, 201, "{theirs}");
    let their_id = theirs["id"].as_str().unwrap();
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/ip-rules/{their_id}", other.slug),
        Some(&t),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = get_json(&app, &format!("{base}/{their_id}"), Some(&t)).await;
    assert_eq!(status, 404);
}
