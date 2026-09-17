//! The token path's caches (resource servers by identifier, permissions per
//! role set, a user's groups) reflect every change at once: writes evict the
//! identifier key, and grants and memberships move the roles version.

mod common;

use common::TestApp;
use ridm_api::models::{
    NewGroup, NewPermission, NewResourceServer, NewRole, NewUser, Principal, ResourceServerUpdate,
};
use ridm_api::services::{groups, resource_servers, roles, users};
use ridm_core::events::Actor;

#[tokio::test]
async fn resource_server_and_permission_caches_follow_changes() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    assert!(
        resource_servers::find_by_identifier_cached(&app.state, tid, "https://api.example")
            .await
            .unwrap()
            .is_none()
    );
    let rs = resource_servers::create(
        &app.state,
        tid,
        Actor::System,
        NewResourceServer {
            identifier: "https://api.example".into(),
            name: "API".into(),
            token_ttl_secs: None,
            signing_alg: None,
            allow_offline_access: None,
        },
    )
    .await
    .unwrap();
    let cached =
        resource_servers::find_by_identifier_cached(&app.state, tid, "https://api.example")
            .await
            .unwrap()
            .expect("created server visible (the negative entry was evicted)");
    assert_eq!(cached.name, "API");

    resource_servers::update(
        &app.state,
        tid,
        Actor::System,
        rs.id,
        ResourceServerUpdate {
            name: Some("Orders API".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let cached =
        resource_servers::find_by_identifier_cached(&app.state, tid, "https://api.example")
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        cached.name, "Orders API",
        "an update evicts the identifier key"
    );

    // Permissions per role set move with the roles version.
    let role = roles::create(
        &app.state,
        tid,
        Actor::System,
        NewRole {
            name: "reader".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let none = resource_servers::permissions_for_roles_cached(&app.state, tid, rs.id, &[role.id])
        .await
        .unwrap();
    assert!(none.is_empty());
    let perm = resource_servers::create_permission(
        &app.state,
        tid,
        Actor::System,
        rs.id,
        NewPermission {
            name: "orders:read".into(),
            description: None,
        },
    )
    .await
    .unwrap();
    resource_servers::grant(&app.state, tid, Actor::System, role.id, perm.id)
        .await
        .unwrap();
    let held = resource_servers::permissions_for_roles_cached(&app.state, tid, rs.id, &[role.id])
        .await
        .unwrap();
    assert_eq!(
        held.as_slice(),
        ["orders:read".to_string()],
        "a grant is seen at once"
    );
    resource_servers::revoke(&app.state, tid, Actor::System, role.id, perm.id)
        .await
        .unwrap();
    let held = resource_servers::permissions_for_roles_cached(&app.state, tid, rs.id, &[role.id])
        .await
        .unwrap();
    assert!(held.is_empty(), "a revoke is seen at once");
    // The order of the role ids does not matter for the cache key.
    let other = roles::create(
        &app.state,
        tid,
        Actor::System,
        NewRole {
            name: "other".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    resource_servers::grant(&app.state, tid, Actor::System, other.id, perm.id)
        .await
        .unwrap();
    let a = resource_servers::permissions_for_roles_cached(
        &app.state,
        tid,
        rs.id,
        &[role.id, other.id],
    )
    .await
    .unwrap();
    let b = resource_servers::permissions_for_roles_cached(
        &app.state,
        tid,
        rs.id,
        &[other.id, role.id],
    )
    .await
    .unwrap();
    assert_eq!(a, b);
    assert_eq!(a.as_slice(), ["orders:read".to_string()]);

    resource_servers::delete(&app.state, tid, Actor::System, rs.id)
        .await
        .unwrap();
    assert!(
        resource_servers::find_by_identifier_cached(&app.state, tid, "https://api.example")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn group_membership_cache_follows_changes() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let user = users::create(
        &app.state,
        tid,
        Actor::System,
        NewUser {
            username: "alice".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        groups::groups_of_user(&app.state, tid, user.id, false)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        groups::groups_of_user(&app.state, tid, user.id, true)
            .await
            .unwrap()
            .is_empty()
    );
    let parent = groups::create(
        &app.state,
        tid,
        Actor::System,
        NewGroup {
            name: "staff".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let child = groups::create(
        &app.state,
        tid,
        Actor::System,
        NewGroup {
            name: "engineering".into(),
            parent_id: Some(parent.id),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    groups::add_member(&app.state, tid, Actor::System, child.id, user.id)
        .await
        .unwrap();
    let direct = groups::groups_of_user(&app.state, tid, user.id, false)
        .await
        .unwrap();
    assert_eq!(
        direct.iter().map(|g| g.name.as_str()).collect::<Vec<_>>(),
        ["engineering"]
    );
    let mut effective: Vec<&str> = Vec::new();
    let eff = groups::groups_of_user(&app.state, tid, user.id, true)
        .await
        .unwrap();
    effective.extend(eff.iter().map(|g| g.name.as_str()));
    effective.sort();
    assert_eq!(
        effective,
        ["engineering", "staff"],
        "ancestors are effective"
    );
    groups::remove_member(&app.state, tid, Actor::System, child.id, user.id)
        .await
        .unwrap();
    assert!(
        groups::groups_of_user(&app.state, tid, user.id, true)
            .await
            .unwrap()
            .is_empty(),
        "a removal is seen at once"
    );
    // A role assignment also moves the version; the cache simply reloads.
    let role = roles::create(
        &app.state,
        tid,
        Actor::System,
        NewRole {
            name: "r".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    roles::assign(
        &app.state,
        tid,
        Actor::System,
        role.id,
        Principal::User { id: user.id },
    )
    .await
    .unwrap();
    assert!(
        groups::groups_of_user(&app.state, tid, user.id, false)
            .await
            .unwrap()
            .is_empty()
    );
}
