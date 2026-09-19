//! Phase 12.1: admin API for organizations, their members, their domains and
//! the roles they grant.

mod common;

use common::TestApp;
use common::admin::{admin_token, call, get_json, role_id, user_with_role};
use reqwest::Method;
use ridm_api::models::Principal;
use ridm_api::services::admin_access::{OWNER_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE};
use ridm_api::services::{organizations, roles, users};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn user_manager_runs_the_organization_lifecycle() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let base = format!("/admin/tenants/{}/organizations", app.tenant.slug);
    let manager = admin_token(&app, tid, USER_MANAGER_ROLE).await;

    // A slug that is not a DNS label is refused before anything is written.
    let (status, err, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&manager),
        Some(&json!({"slug": "Acme Corp!", "display_name": "Acme"})),
    )
    .await;
    assert_eq!(status, 400, "{err}");

    let (status, acme, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&manager),
        Some(&json!({"slug": "acme", "display_name": "Acme Corporation"})),
    )
    .await;
    assert_eq!(status, 201, "{acme}");
    let acme_id = acme["id"].as_str().unwrap().to_string();
    assert_eq!(acme["status"], "active");

    let (status, dup, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&manager),
        Some(&json!({"slug": "acme", "display_name": "Acme again"})),
    )
    .await;
    assert_eq!(status, 409, "{dup}");

    let (status, globex, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&manager),
        Some(&json!({"slug": "globex", "display_name": "Globex"})),
    )
    .await;
    assert_eq!(status, 201, "{globex}");

    // Listing pages and filters.
    let (status, page, _) = get_json(&app, &base, Some(&manager)).await;
    assert_eq!(status, 200);
    assert_eq!(page["items"].as_array().unwrap().len(), 2, "{page}");
    let (_, page, _) = get_json(&app, &format!("{base}?search=glob"), Some(&manager)).await;
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["slug"], "globex");
    let (_, page, _) = get_json(&app, &format!("{base}?limit=1"), Some(&manager)).await;
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert!(page["next_cursor"].is_string(), "{page}");

    // Detail, then a rename and a disable.
    let (status, detail, _) = get_json(&app, &format!("{base}/{acme_id}"), Some(&manager)).await;
    assert_eq!(status, 200, "{detail}");
    assert_eq!(detail["member_count"], 0);
    assert_eq!(detail["domains"].as_array().unwrap().len(), 0);

    let (status, patched, _) = call(
        &app,
        Method::PATCH,
        &format!("{base}/{acme_id}"),
        Some(&manager),
        Some(&json!({"display_name": "Acme Ltd", "status": "disabled"})),
    )
    .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["display_name"], "Acme Ltd");
    assert_eq!(patched["status"], "disabled");
    let (_, page, _) = get_json(&app, &format!("{base}?status=disabled"), Some(&manager)).await;
    assert_eq!(page["items"].as_array().unwrap().len(), 1);

    // A slug that another organization holds is a conflict, not a 500.
    let (status, err, _) = call(
        &app,
        Method::PATCH,
        &format!("{base}/{acme_id}"),
        Some(&manager),
        Some(&json!({"slug": "globex"})),
    )
    .await;
    assert_eq!(status, 409, "{err}");

    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{acme_id}"),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = get_json(&app, &format!("{base}/{acme_id}"), Some(&manager)).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn membership_sets_the_primary_organization_once() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let base = format!("/admin/tenants/{}/organizations", app.tenant.slug);
    let manager = admin_token(&app, tid, USER_MANAGER_ROLE).await;
    let alice = user_with_role(&app, tid, None).await;

    let (_, first, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&manager),
        Some(&json!({"slug": "first", "display_name": "First"})),
    )
    .await;
    let (_, second, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&manager),
        Some(&json!({"slug": "second", "display_name": "Second"})),
    )
    .await;
    let first_id = first["id"].as_str().unwrap().to_string();
    let second_id = second["id"].as_str().unwrap().to_string();

    // An unknown user is a 404, not a dangling membership.
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{first_id}/members/{}", Uuid::now_v7()),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 404);

    for org in [&first_id, &second_id] {
        let (status, _, _) = call(
            &app,
            Method::PUT,
            &format!("{base}/{org}/members/{alice}"),
            Some(&manager),
            None,
        )
        .await;
        assert_eq!(status, 204);
    }
    // The first organization became the primary one; the second did not move it.
    let user = users::get(&app.state, tid, alice).await.unwrap();
    assert_eq!(user.org_id.map(|o| o.to_string()), Some(first_id.clone()));
    assert_eq!(
        organizations::of_user(&app.state, tid, alice)
            .await
            .unwrap()
            .len(),
        2
    );

    let (status, members, _) =
        get_json(&app, &format!("{base}/{first_id}/members"), Some(&manager)).await;
    assert_eq!(status, 200);
    assert_eq!(members.as_array().unwrap().len(), 1);

    // Adding twice is idempotent, removing twice is not an error.
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{first_id}/members/{alice}"),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 204);
    for _ in 0..2 {
        let (status, _, _) = call(
            &app,
            Method::DELETE,
            &format!("{base}/{first_id}/members/{alice}"),
            Some(&manager),
            None,
        )
        .await;
        assert_eq!(status, 204);
    }
    assert_eq!(
        organizations::of_user(&app.state, tid, alice)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn an_org_scoped_role_applies_only_in_its_organization() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let base = format!("/admin/tenants/{}/organizations", app.tenant.slug);
    let owner = admin_token(&app, tid, OWNER_ROLE).await;
    let alice = user_with_role(&app, tid, None).await;
    let viewer_role = role_id(&app, tid, VIEWER_ROLE).await;

    let (_, org, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&owner),
        Some(&json!({"slug": "acme", "display_name": "Acme"})),
    )
    .await;
    let org_id = org["id"].as_str().unwrap().to_string();

    // A non-member cannot hold a role in the organization.
    let (status, err, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{org_id}/members/{alice}/roles/{viewer_role}"),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(status, 400, "{err}");

    call(
        &app,
        Method::PUT,
        &format!("{base}/{org_id}/members/{alice}"),
        Some(&owner),
        None,
    )
    .await;
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{org_id}/members/{alice}/roles/{viewer_role}"),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(status, 204);

    let (status, grants, _) = get_json(&app, &format!("{base}/{org_id}/roles"), Some(&owner)).await;
    assert_eq!(status, 200);
    let grants = grants.as_array().unwrap();
    assert_eq!(grants.len(), 1, "{grants:?}");
    assert_eq!(grants[0]["org_id"], org_id);

    // The grant is invisible outside the organization and visible inside it.
    let org_uuid: Uuid = org_id.parse().unwrap();
    let unscoped = roles::effective_roles(&app.state, tid, alice, None)
        .await
        .unwrap();
    assert!(
        !unscoped.iter().any(|r| r.id == viewer_role),
        "an org-scoped grant leaked into a session without an organization"
    );
    let scoped = roles::effective_roles(&app.state, tid, alice, Some(org_uuid))
        .await
        .unwrap();
    assert!(scoped.iter().any(|r| r.id == viewer_role));

    // A group grant reaches the group's members in the same organization only.
    let group = ridm_api::services::groups::create(
        &app.state,
        tid,
        ridm_core::events::Actor::System,
        ridm_api::models::NewGroup {
            name: "staff".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    ridm_api::services::groups::add_member(
        &app.state,
        tid,
        ridm_core::events::Actor::System,
        group.id,
        alice,
    )
    .await
    .unwrap();
    let owner_role = role_id(&app, tid, OWNER_ROLE).await;
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{org_id}/groups/{}/roles/{owner_role}", group.id),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let scoped = roles::effective_roles(&app.state, tid, alice, Some(org_uuid))
        .await
        .unwrap();
    assert!(scoped.iter().any(|r| r.id == owner_role));
    let unscoped = roles::effective_roles(&app.state, tid, alice, None)
        .await
        .unwrap();
    assert!(!unscoped.iter().any(|r| r.id == owner_role));

    // Removing the membership takes the user's org-scoped grant with it.
    call(
        &app,
        Method::DELETE,
        &format!("{base}/{org_id}/members/{alice}/roles/{viewer_role}"),
        Some(&owner),
        None,
    )
    .await;
    let scoped = roles::effective_roles(&app.state, tid, alice, Some(org_uuid))
        .await
        .unwrap();
    assert!(!scoped.iter().any(|r| r.id == viewer_role));
}

#[tokio::test]
async fn a_domain_is_added_checked_and_removed() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let base = format!("/admin/tenants/{}/organizations", app.tenant.slug);
    let manager = admin_token(&app, tid, USER_MANAGER_ROLE).await;

    let (_, org, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&manager),
        Some(&json!({"slug": "acme", "display_name": "Acme"})),
    )
    .await;
    let org_id = org["id"].as_str().unwrap().to_string();
    let domains = format!("{base}/{org_id}/domains");

    let (status, err, _) = call(
        &app,
        Method::POST,
        &domains,
        Some(&manager),
        Some(&json!({"domain": "localhost"})),
    )
    .await;
    assert_eq!(status, 400, "{err}");

    let (status, added, _) = call(
        &app,
        Method::POST,
        &domains,
        Some(&manager),
        Some(&json!({"domain": "Acme.Example.", "auto_join": true})),
    )
    .await;
    assert_eq!(status, 201, "{added}");
    assert_eq!(added["domain"], "acme.example");
    assert!(added["verified_at"].is_null());
    assert_eq!(added["auto_join"], true);
    let verification = added["verification"].as_str().unwrap().to_string();
    assert!(verification.starts_with("ridm-domain-verification="));
    let domain_id = added["id"].as_str().unwrap().to_string();

    // The same domain cannot belong to two organizations of one tenant.
    let (_, other, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&manager),
        Some(&json!({"slug": "globex", "display_name": "Globex"})),
    )
    .await;
    let (status, err, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{}/domains", other["id"].as_str().unwrap()),
        Some(&manager),
        Some(&json!({"domain": "acme.example"})),
    )
    .await;
    assert_eq!(status, 409, "{err}");

    // Nothing publishes the record, so verification does not pass. A host with
    // no resolver answers 503; either way it is not verified.
    let (status, err, _) = call(
        &app,
        Method::POST,
        &format!("{domains}/{domain_id}/verify"),
        Some(&manager),
        None,
    )
    .await;
    assert!(status == 400 || status == 503, "{status}: {err}");
    let (_, listed, _) = get_json(&app, &domains, Some(&manager)).await;
    assert!(listed[0]["verified_at"].is_null());

    let (status, patched, _) = call(
        &app,
        Method::PATCH,
        &format!("{domains}/{domain_id}"),
        Some(&manager),
        Some(&json!({"auto_join": false})),
    )
    .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["auto_join"], false);

    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{domains}/{domain_id}"),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (_, listed, _) = get_json(&app, &domains, Some(&manager)).await;
    assert_eq!(listed.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn auto_join_needs_a_verified_domain_and_a_verified_address() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;

    let org = organizations::create(
        &app.state,
        tid,
        ridm_core::events::Actor::System,
        ridm_api::models::NewOrganization {
            slug: "acme".into(),
            display_name: "Acme".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let domain = organizations::add_domain(
        &app.state,
        tid,
        ridm_core::events::Actor::System,
        org.id,
        ridm_api::models::NewOrganizationDomain {
            domain: "acme.example".into(),
            auto_join: true,
        },
    )
    .await
    .unwrap();

    let user = users::create(
        &app.state,
        tid,
        ridm_core::events::Actor::System,
        ridm_api::models::NewUser {
            username: "joiner".into(),
            email: Some("someone@acme.example".into()),
            email_verified: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // The domain is not verified yet, so nobody joins.
    assert_eq!(
        organizations::ensure_auto_join(&app.state, tid, &user)
            .await
            .unwrap(),
        None
    );

    // Verify it the way a passing DNS lookup would.
    let mut tx = ridm_api::db::tenant_tx(&app.state.db, tid).await.unwrap();
    ridm_api::repos::organizations::mark_domain_verified(&mut *tx, tid, org.id, domain.id)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    assert_eq!(
        organizations::ensure_auto_join(&app.state, tid, &user)
            .await
            .unwrap(),
        Some(org.id)
    );
    let joined = users::get(&app.state, tid, user.id).await.unwrap();
    assert_eq!(joined.org_id, Some(org.id), "primary organization set");
    // Running again is idempotent.
    assert_eq!(
        organizations::ensure_auto_join(&app.state, tid, &user)
            .await
            .unwrap(),
        Some(org.id)
    );
    assert_eq!(
        organizations::of_user(&app.state, tid, user.id)
            .await
            .unwrap()
            .len(),
        1
    );

    // An unverified address proves nothing about the domain.
    let unverified = users::create(
        &app.state,
        tid,
        ridm_core::events::Actor::System,
        ridm_api::models::NewUser {
            username: "unproven".into(),
            email: Some("other@acme.example".into()),
            email_verified: false,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        organizations::ensure_auto_join(&app.state, tid, &unverified)
            .await
            .unwrap(),
        None
    );

    // A disabled organization takes no new members.
    organizations::update(
        &app.state,
        tid,
        ridm_core::events::Actor::System,
        org.id,
        ridm_api::models::OrganizationUpdate {
            status: Some(ridm_api::models::OrganizationStatus::Disabled),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let third = users::create(
        &app.state,
        tid,
        ridm_core::events::Actor::System,
        ridm_api::models::NewUser {
            username: "late".into(),
            email: Some("late@acme.example".into()),
            email_verified: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        organizations::ensure_auto_join(&app.state, tid, &third)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn a_viewer_reads_and_cannot_write() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let base = format!("/admin/tenants/{}/organizations", app.tenant.slug);
    let viewer = admin_token(&app, tid, VIEWER_ROLE).await;
    let owner = admin_token(&app, tid, OWNER_ROLE).await;

    let (_, org, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&owner),
        Some(&json!({"slug": "acme", "display_name": "Acme"})),
    )
    .await;
    let org_id = org["id"].as_str().unwrap().to_string();

    let (status, _, _) = get_json(&app, &base, Some(&viewer)).await;
    assert_eq!(status, 200);
    let (status, _, _) = get_json(&app, &format!("{base}/{org_id}"), Some(&viewer)).await;
    assert_eq!(status, 200);
    for (method, path, body) in [
        (
            Method::POST,
            base.clone(),
            Some(json!({"slug": "nope", "display_name": "Nope"})),
        ),
        (
            Method::PATCH,
            format!("{base}/{org_id}"),
            Some(json!({"display_name": "Changed"})),
        ),
        (Method::DELETE, format!("{base}/{org_id}"), None),
        (
            Method::POST,
            format!("{base}/{org_id}/domains"),
            Some(json!({"domain": "acme.example"})),
        ),
    ] {
        let (status, err, _) = call(&app, method, &path, Some(&viewer), body.as_ref()).await;
        assert_eq!(status, 403, "{path}: {err}");
    }
}

#[tokio::test]
async fn organizations_are_tenant_scoped() {
    let app = TestApp::spawn().await;
    let other = common::create_tenant(&app.state.db).await;
    let owner = admin_token(&app, app.tenant.id, OWNER_ROLE).await;

    let org = organizations::create(
        &app.state,
        other.id,
        ridm_core::events::Actor::System,
        ridm_api::models::NewOrganization {
            slug: "theirs".into(),
            display_name: "Theirs".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // The other tenant's organization is not reachable through this tenant.
    let (status, _, _) = get_json(
        &app,
        &format!(
            "/admin/tenants/{}/organizations/{}",
            app.tenant.slug, org.id
        ),
        Some(&owner),
    )
    .await;
    assert_eq!(status, 404);
    let (_, page, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/organizations", app.tenant.slug),
        Some(&owner),
    )
    .await;
    assert_eq!(page["items"].as_array().unwrap().len(), 0, "{page}");

    // A role grant cannot cross the tenant boundary either.
    let alice = user_with_role(&app, app.tenant.id, None).await;
    let role = role_id(&app, app.tenant.id, VIEWER_ROLE).await;
    let err = organizations::assign_role(
        &app.state,
        app.tenant.id,
        ridm_core::events::Actor::System,
        org.id,
        role,
        Principal::User { id: alice },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, ridm_api::error::AppError::NotFound("organization")),
        "{err:?}"
    );
}
