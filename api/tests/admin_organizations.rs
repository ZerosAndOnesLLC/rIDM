//! Phase 12.1: admin API for organizations, their members, their domains and
//! the roles they grant. Phase 12.2 adds the organization's own administrator
//! (a role granted within it) and the invitations it may send.

mod common;

use common::TestApp;
use common::admin::{admin_token, call, get_json, org_admin_token, role_id, user_with_role};
use reqwest::Method;
use ridm_api::models::Principal;
use ridm_api::services::admin_access::{
    ORG_ADMIN_ROLE, OWNER_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE,
};
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
async fn deleting_an_organization_releases_what_points_at_it() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let base = format!("/admin/tenants/{}/organizations", app.tenant.slug);
    let owner = admin_token(&app, tid, OWNER_ROLE).await;
    let alice = user_with_role(&app, tid, None).await;

    let (_, org, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&owner),
        Some(&json!({"slug": "acme", "display_name": "Acme"})),
    )
    .await;
    let org_id = org["id"].as_str().unwrap().to_string();
    let org_uuid: Uuid = org_id.parse().unwrap();

    // A member (whose primary organization it becomes), an org-scoped grant and
    // an invitation all reference it.
    call(
        &app,
        Method::PUT,
        &format!("{base}/{org_id}/members/{alice}"),
        Some(&owner),
        None,
    )
    .await;
    let role = role_id(&app, tid, VIEWER_ROLE).await;
    call(
        &app,
        Method::PUT,
        &format!("{base}/{org_id}/members/{alice}/roles/{role}"),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(
        users::get(&app.state, tid, alice).await.unwrap().org_id,
        Some(org_uuid)
    );

    // The composite foreign keys must release only org_id: nulling tenant_id
    // as well would break the delete against a NOT NULL column.
    let (status, err, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{org_id}"),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(status, 204, "{err}");
    let after = users::get(&app.state, tid, alice).await.unwrap();
    assert_eq!(after.org_id, None, "the member keeps their account");
    assert!(
        roles::effective_roles(&app.state, tid, alice, Some(org_uuid))
            .await
            .unwrap()
            .iter()
            .all(|r| r.id != role),
        "the org-scoped grant went with the organization"
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

/// Phase 12.2: a role granted *within* an organization makes its holder that
/// organization's administrator, and nothing more.
#[tokio::test]
async fn an_org_admin_runs_its_own_organization_and_no_other() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let base = format!("/admin/tenants/{}/organizations", app.tenant.slug);
    let owner = admin_token(&app, tid, OWNER_ROLE).await;

    let (_, acme, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&owner),
        Some(&json!({"slug": "acme", "display_name": "Acme"})),
    )
    .await;
    let (_, globex, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&owner),
        Some(&json!({"slug": "globex", "display_name": "Globex"})),
    )
    .await;
    let acme_id = acme["id"].as_str().unwrap().to_string();
    let globex_id = globex["id"].as_str().unwrap().to_string();

    let acme_uuid: Uuid = acme_id.parse().unwrap();
    let (admin_user, org_admin) = org_admin_token(&app, tid, acme_uuid, ORG_ADMIN_ROLE).await;

    // Their own organization: read and change what belongs to it.
    let (status, detail, _) = get_json(&app, &format!("{base}/{acme_id}"), Some(&org_admin)).await;
    assert_eq!(status, 200, "{detail}");
    assert_eq!(detail["member_count"], 1, "the administrator is a member");
    let (status, patched, _) = call(
        &app,
        Method::PATCH,
        &format!("{base}/{acme_id}"),
        Some(&org_admin),
        Some(&json!({"display_name": "Acme Ltd"})),
    )
    .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["display_name"], "Acme Ltd");

    // The organization's identity and lifecycle stay with the tenant.
    for body in [
        json!({"slug": "acme-renamed"}),
        json!({"status": "disabled"}),
    ] {
        let (status, err, _) = call(
            &app,
            Method::PATCH,
            &format!("{base}/{acme_id}"),
            Some(&org_admin),
            Some(&body),
        )
        .await;
        assert_eq!(status, 403, "{body} must be refused: {err}");
    }
    let (status, _, _) = get_json(&app, &base, Some(&org_admin)).await;
    assert_eq!(status, 403, "listing every organization is tenant-wide");
    let (status, _, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&org_admin),
        Some(&json!({"slug": "new-one", "display_name": "New"})),
    )
    .await;
    assert_eq!(status, 403, "creating an organization is tenant-wide");
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{acme_id}"),
        Some(&org_admin),
        None,
    )
    .await;
    assert_eq!(status, 403, "deleting an organization is tenant-wide");

    // Another organization is out of reach, whatever the operation.
    for (method, path) in [
        (Method::GET, format!("{base}/{globex_id}")),
        (Method::GET, format!("{base}/{globex_id}/members")),
        (Method::GET, format!("{base}/{globex_id}/domains")),
        (Method::GET, format!("{base}/{globex_id}/roles")),
        (Method::GET, format!("{base}/{globex_id}/invitations")),
    ] {
        let (status, body, _) = call(&app, method.clone(), &path, Some(&org_admin), None).await;
        assert_eq!(status, 403, "{method} {path}: {body}");
    }

    // Membership: an existing user may not be pulled in, but a member can be
    // removed and the member list is theirs to see.
    let stranger = user_with_role(&app, tid, None).await;
    let (status, err, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{acme_id}/members/{stranger}"),
        Some(&org_admin),
        None,
    )
    .await;
    assert_eq!(status, 403, "{err}");
    assert!(
        err["detail"].as_str().unwrap().contains("by invitation"),
        "{err}"
    );
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{acme_id}/members/{stranger}"),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, members, _) =
        get_json(&app, &format!("{base}/{acme_id}/members"), Some(&org_admin)).await;
    assert_eq!(status, 200);
    assert_eq!(members.as_array().unwrap().len(), 2, "{members}");
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{acme_id}/members/{stranger}"),
        Some(&org_admin),
        None,
    )
    .await;
    assert_eq!(status, 204);

    // Domains of their organization, including the verification attempt.
    let (status, domain, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{acme_id}/domains"),
        Some(&org_admin),
        Some(&json!({"domain": "acme.example", "auto_join": true})),
    )
    .await;
    assert_eq!(status, 201, "{domain}");
    let domain_id = domain["id"].as_str().unwrap().to_string();
    let (status, domains, _) =
        get_json(&app, &format!("{base}/{acme_id}/domains"), Some(&org_admin)).await;
    assert_eq!(status, 200);
    assert_eq!(domains.as_array().unwrap().len(), 1);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{acme_id}/domains/{domain_id}"),
        Some(&org_admin),
        None,
    )
    .await;
    assert_eq!(status, 204);

    // `/admin/me` names the organization and what may be done inside it.
    let (status, me, _) = get_json(&app, "/admin/me", Some(&org_admin)).await;
    assert_eq!(status, 200, "{me}");
    assert_eq!(me["user_id"], admin_user.to_string());
    assert_eq!(me["organization"]["id"], acme_id);
    assert_eq!(me["organization"]["slug"], "acme");
    assert!(
        me["permissions"].as_array().unwrap().is_empty(),
        "no tenant-wide permission: {me}"
    );
    let org_perms: Vec<&str> = me["organization_permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(org_perms.contains(&"ridm:orgs:write"), "{me}");
}

/// The only way an organization's administrator adds people: an invitation
/// that carries the organization. They never see the tenant's other ones.
#[tokio::test]
async fn an_org_admin_invites_into_its_own_organization_only() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let slug = app.tenant.slug.clone();
    let base = format!("/admin/tenants/{slug}/organizations");
    let owner = admin_token(&app, tid, OWNER_ROLE).await;

    let (_, acme, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&owner),
        Some(&json!({"slug": "acme", "display_name": "Acme"})),
    )
    .await;
    let (_, globex, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&owner),
        Some(&json!({"slug": "globex", "display_name": "Globex"})),
    )
    .await;
    let acme_id = acme["id"].as_str().unwrap().to_string();
    let globex_id = globex["id"].as_str().unwrap().to_string();
    let (_, org_admin) = org_admin_token(&app, tid, acme_id.parse().unwrap(), ORG_ADMIN_ROLE).await;

    // A tenant-wide invitation belonging to no organization, and one for the
    // other organization: neither may show up in Acme's list.
    for body in [
        json!({"email": "tenant-wide@example.com"}),
        json!({"email": "globex@example.com", "org_id": globex_id}),
    ] {
        let (status, inv, _) = call(
            &app,
            Method::POST,
            &format!("/admin/tenants/{slug}/invitations"),
            Some(&owner),
            Some(&body),
        )
        .await;
        assert_eq!(status, 201, "{inv}");
    }

    let (status, inv, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{acme_id}/invitations"),
        Some(&org_admin),
        Some(&json!({"email": "newcomer@example.com"})),
    )
    .await;
    assert_eq!(status, 201, "{inv}");
    assert_eq!(inv["org_id"], acme_id, "the path decides the organization");
    let invitation_id = inv["id"].as_str().unwrap().to_string();

    let (status, page, _) = get_json(
        &app,
        &format!("{base}/{acme_id}/invitations"),
        Some(&org_admin),
    )
    .await;
    assert_eq!(status, 200, "{page}");
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "only this organization's: {page}");
    assert_eq!(items[0]["email"], "newcomer@example.com");

    // The tenant-wide invitation list stays out of reach.
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{slug}/invitations"),
        Some(&org_admin),
    )
    .await;
    assert_eq!(status, 403);

    // An organization's administrator may not attach tenant roles or groups.
    let viewer_role = role_id(&app, tid, VIEWER_ROLE).await;
    let (status, err, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{acme_id}/invitations"),
        Some(&org_admin),
        Some(&json!({"email": "escalate@example.com", "roles": [viewer_role]})),
    )
    .await;
    assert_eq!(status, 403, "{err}");

    // An org_id in the body that contradicts the path is refused outright.
    let (status, err, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{acme_id}/invitations"),
        Some(&org_admin),
        Some(&json!({"email": "elsewhere@example.com", "org_id": globex_id})),
    )
    .await;
    assert_eq!(status, 400, "{err}");

    // Revoking: their own, yes; another organization's, not found.
    let (_, other, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{globex_id}/invitations"),
        Some(&owner),
        Some(&json!({"email": "other@example.com"})),
    )
    .await;
    let other_id = other["id"].as_str().unwrap().to_string();
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{acme_id}/invitations/{other_id}"),
        Some(&org_admin),
        None,
    )
    .await;
    assert_eq!(status, 404, "another organization's invitation");
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{acme_id}/invitations/{invitation_id}"),
        Some(&org_admin),
        None,
    )
    .await;
    assert_eq!(status, 204);
}
