//! Phase 12.7: organization auto-join by verified email domain, as a matrix.
//! A user joins at sign-in only when their *verified* address is at a domain
//! that is verified, set to auto-join, and belongs to an active organization
//! of the *same* tenant — matched exactly, whatever the case, never by
//! subdomain, parent domain or look-alike. Joining never moves a primary
//! organization, and removing the domain stops further joins.

mod common;

use common::{TestApp, create_tenant};
use ridm_api::models::{NewOrganization, NewOrganizationDomain, NewUser, User};
use ridm_api::services::{organizations, users};
use ridm_core::events::Actor;
use uuid::Uuid;

async fn org(app: &TestApp, tenant_id: Uuid, slug: &str) -> Uuid {
    organizations::create(
        &app.state,
        tenant_id,
        Actor::System,
        NewOrganization {
            slug: slug.into(),
            display_name: slug.into(),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .id
}

/// Add `domain` to `org_id`, verified (as a passing DNS lookup would) or not.
async fn domain(
    app: &TestApp,
    tenant_id: Uuid,
    org_id: Uuid,
    name: &str,
    auto_join: bool,
    verified: bool,
) -> Uuid {
    let d = organizations::add_domain(
        &app.state,
        tenant_id,
        Actor::System,
        org_id,
        NewOrganizationDomain {
            domain: name.into(),
            auto_join,
        },
    )
    .await
    .unwrap();
    if verified {
        let mut tx = ridm_api::db::tenant_tx(&app.state.db, tenant_id)
            .await
            .unwrap();
        ridm_api::repos::organizations::mark_domain_verified(&mut *tx, tenant_id, org_id, d.id)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        // As the service does after a verification.
        app.state
            .cache
            .invalidate(&[ridm_api::cache::keys::org_auto_join_domains(tenant_id)])
            .await
            .unwrap();
    }
    d.id
}

async fn user(app: &TestApp, email: Option<&str>, verified: bool) -> User {
    users::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewUser {
            username: format!("u-{}", &Uuid::new_v4().simple().to_string()[..10]),
            email: email.map(str::to_string),
            email_verified: verified,
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn who_joins_which_organization() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let acme = org(&app, tid, "acme").await;
    let quiet = org(&app, tid, "quiet").await;
    let pending = org(&app, tid, "pending").await;
    domain(&app, tid, acme, "acme.example", true, true).await;
    // Verified, but its owner did not ask for auto-join.
    domain(&app, tid, quiet, "quiet.example", false, true).await;
    // Asked for auto-join, never verified.
    domain(&app, tid, pending, "pending.example", true, false).await;
    // Another tenant's verified auto-join domain is nothing to this one.
    let other = create_tenant(&app.state.db).await;
    let theirs = org(&app, other.id, "theirs").await;
    domain(&app, other.id, theirs, "theirs.example", true, true).await;

    let cases: &[(Option<&str>, bool, Option<Uuid>, &str)] = &[
        (Some("ann@acme.example"), true, Some(acme), "the plain case"),
        (
            Some("Bob@ACME.Example"),
            true,
            Some(acme),
            "case does not matter",
        ),
        (
            Some("cy@acme.example"),
            false,
            None,
            "an unverified address",
        ),
        (Some("di@mail.acme.example"), true, None, "a subdomain"),
        (Some("ed@example"), true, None, "the parent domain"),
        (
            Some("fay@acme.example.evil"),
            true,
            None,
            "a look-alike suffix",
        ),
        (
            Some("gus@evilacme.example"),
            true,
            None,
            "a look-alike prefix",
        ),
        (Some("hal@quiet.example"), true, None, "auto-join off"),
        (
            Some("ivy@pending.example"),
            true,
            None,
            "an unverified domain",
        ),
        (
            Some("jo@theirs.example"),
            true,
            None,
            "another tenant's domain",
        ),
        (None, true, None, "no email at all"),
    ];
    let mut failures = vec![];
    for (email, verified, want, why) in cases {
        let u = user(&app, *email, *verified).await;
        let got = organizations::ensure_auto_join(&app.state, tid, &u)
            .await
            .unwrap();
        if got != *want {
            failures.push(format!("{why} ({email:?}): expected {want:?}, got {got:?}"));
        }
        let member_of = organizations::of_user(&app.state, tid, u.id)
            .await
            .unwrap()
            .len();
        if member_of != usize::from(want.is_some()) {
            failures.push(format!("{why}: member of {member_of} organizations"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn joining_never_moves_a_primary_organization() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let first = org(&app, tid, "first").await;
    let acme = org(&app, tid, "acme").await;
    domain(&app, tid, acme, "acme.example", true, true).await;
    let u = user(&app, Some("kim@acme.example"), true).await;
    organizations::add_member(&app.state, tid, Actor::System, first, u.id)
        .await
        .unwrap();
    assert_eq!(
        organizations::ensure_auto_join(&app.state, tid, &u)
            .await
            .unwrap(),
        Some(acme)
    );
    let after = users::get(&app.state, tid, u.id).await.unwrap();
    assert_eq!(after.org_id, Some(first), "still the first organization");
    assert_eq!(
        organizations::of_user(&app.state, tid, u.id)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn removing_the_domain_stops_further_joins_but_keeps_members() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let acme = org(&app, tid, "acme").await;
    let d = domain(&app, tid, acme, "acme.example", true, true).await;
    let early = user(&app, Some("lee@acme.example"), true).await;
    assert_eq!(
        organizations::ensure_auto_join(&app.state, tid, &early)
            .await
            .unwrap(),
        Some(acme)
    );
    organizations::delete_domain(&app.state, tid, Actor::System, acme, d)
        .await
        .unwrap();
    let late = user(&app, Some("max@acme.example"), true).await;
    assert_eq!(
        organizations::ensure_auto_join(&app.state, tid, &late)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        organizations::of_user(&app.state, tid, early.id)
            .await
            .unwrap()
            .len(),
        1,
        "who joined stays a member"
    );
}
