//! Phase 12.2: an organization's administrator holds `ridm:orgs:*` through a
//! role granted inside one organization. Three ways out of it must stay shut:
//!
//! 1. the grant must not satisfy a tenant-wide check (users, groups, clients,
//!    the tenant's own settings — nothing outside `/organizations/{org}`);
//! 2. it must not follow the user into a session acting elsewhere, so a token
//!    without the `org_id` claim, or with another organization's, is refused
//!    even though the same user holds the role;
//! 3. it must not become a way to hand out permissions the holder lacks: a
//!    role carrying tenant-wide admin permissions cannot be granted inside the
//!    organization, while a peer organization administrator can.

use reqwest::Method;
use ridm_api::models::NewRole;
use ridm_api::services::admin_access::{ORG_ADMIN_ROLE, OWNER_ROLE};
use ridm_api::services::{organizations, roles, tenants};
use ridm_core::events::Actor;
use serde_json::json;
use uuid::Uuid;

use crate::common::TestApp;
use crate::common::admin::{
    TokenOpts, admin_token, call, get_json, org_admin_token, role_id, token, user_with_role,
};

#[tokio::test]
async fn an_org_scoped_grant_reaches_nothing_but_its_organization() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let slug = app.tenant.slug.clone();
    let tenant = tenants::get(&app.state, tid).await.unwrap();
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
    let acme_id: Uuid = acme["id"].as_str().unwrap().parse().unwrap();
    let globex_id: Uuid = globex["id"].as_str().unwrap().parse().unwrap();
    let (admin_user, org_admin) = org_admin_token(&app, tid, acme_id, ORG_ADMIN_ROLE).await;

    // 1. Nothing outside the organization, not even the permissions the role
    //    carries (invitations, roles) when asked for tenant-wide.
    for (method, path) in [
        (Method::GET, format!("/admin/tenants/{slug}/users")),
        (Method::GET, format!("/admin/tenants/{slug}/groups")),
        (Method::GET, format!("/admin/tenants/{slug}/roles")),
        (Method::GET, format!("/admin/tenants/{slug}/clients")),
        (Method::GET, format!("/admin/tenants/{slug}/invitations")),
        (Method::GET, format!("/admin/tenants/{slug}")),
        (Method::GET, base.clone()),
    ] {
        let (status, body, _) = call(&app, method.clone(), &path, Some(&org_admin), None).await;
        assert_eq!(status, 403, "{method} {path}: {body}");
    }

    // 2. The same user, signed in without an organization or in another one:
    //    the grant is not theirs to use there.
    for org in [None, Some(globex_id)] {
        let elsewhere = token(
            &app,
            &tenant,
            admin_user,
            TokenOpts {
                org_id: org,
                ..Default::default()
            },
        )
        .await;
        let (status, body, _) =
            get_json(&app, &format!("{base}/{acme_id}/members"), Some(&elsewhere)).await;
        // No admin permission at all in that context, so the token is refused
        // before any handler runs.
        assert_eq!(status, 403, "org {org:?}: {body}");
    }

    // 3. No escalation through the organization's own role grants. A role
    //    carrying a tenant-wide admin permission cannot be handed out inside
    //    it, while another `ridm:org-admin` can.
    let privileged = roles::create(
        &app.state,
        tid,
        Actor::System,
        NewRole {
            name: "org-then-tenant".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let owner_role = role_id(&app, tid, OWNER_ROLE).await;
    roles::add_composite(&app.state, tid, Actor::System, privileged.id, owner_role)
        .await
        .unwrap();
    let member = user_with_role(&app, tid, None).await;
    organizations::add_member(&app.state, tid, Actor::System, acme_id, member)
        .await
        .unwrap();

    let (status, err, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{acme_id}/members/{member}/roles/{}", privileged.id),
        Some(&org_admin),
        None,
    )
    .await;
    assert_eq!(status, 403, "{err}");
    assert!(
        err["detail"]
            .as_str()
            .unwrap()
            .contains("cannot grant permissions you do not hold"),
        "{err}"
    );
    // The refused grant wrote nothing.
    let held = roles::effective_roles(&app.state, tid, member, Some(acme_id))
        .await
        .unwrap();
    assert!(
        !held.iter().any(|r| r.id == privileged.id),
        "the grant must not have been written"
    );

    let peer = role_id(&app, tid, ORG_ADMIN_ROLE).await;
    let (status, body, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{acme_id}/members/{member}/roles/{peer}"),
        Some(&org_admin),
        None,
    )
    .await;
    assert_eq!(status, 204, "a peer organization administrator: {body}");

    // And the peer's new power stops at Acme: tenant-wide they hold nothing.
    let peer_token = token(
        &app,
        &tenant,
        member,
        TokenOpts {
            org_id: Some(globex_id),
            ..Default::default()
        },
    )
    .await;
    let (status, body, _) = get_json(&app, "/admin/me", Some(&peer_token)).await;
    assert_eq!(
        status, 403,
        "no permissions in another organization: {body}"
    );

    // A group-scoped grant inside the organization is measured the same way.
    let (status, err, _) = call(
        &app,
        Method::PUT,
        &format!(
            "{base}/{acme_id}/groups/{}/roles/{}",
            Uuid::now_v7(),
            privileged.id
        ),
        Some(&org_admin),
        None,
    )
    .await;
    assert_eq!(status, 403, "{err}");

    // The audit trail is the tenant's, not the organization's: reading it was
    // never granted here.
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{slug}/audit"),
        Some(&org_admin),
    )
    .await;
    assert_eq!(status, 403);
}
