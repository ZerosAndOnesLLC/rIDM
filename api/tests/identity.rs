mod common;

use common::TestApp;
use ridm_api::error::AppError;
use ridm_api::models::{
    GroupUpdate, NewGroup, NewRole, NewUser, Principal, TenantStatus, UserFilter, UserUpdate,
};
use ridm_api::services::tenants::{NewTenant, TenantUpdate};
use ridm_api::services::{groups, roles, tenants, users};
use ridm_core::events::Actor;
use uuid::Uuid;

fn new_user(username: &str) -> NewUser {
    NewUser {
        username: username.into(),
        email: Some(format!("{username}@example.com")),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// tenants
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tenant_crud_and_master_protection() {
    let app = TestApp::spawn().await;
    let slug = format!("acme-{}", &Uuid::new_v4().simple().to_string()[..8]);

    let t = tenants::create(
        &app.state,
        Actor::System,
        NewTenant {
            slug: slug.to_uppercase(),
            display_name: "  Acme  ".into(),
            settings: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(t.slug, slug, "slug is normalized to lowercase");
    assert_eq!(t.display_name, "Acme");
    assert_eq!(t.settings.password.min_length, 12);

    let dup = tenants::create(
        &app.state,
        Actor::System,
        NewTenant {
            slug: slug.clone(),
            display_name: "Dup".into(),
            settings: None,
        },
    )
    .await;
    assert!(matches!(dup, Err(AppError::Conflict(_))));

    let bad = tenants::create(
        &app.state,
        Actor::System,
        NewTenant {
            slug: "bad slug!".into(),
            display_name: "x".into(),
            settings: None,
        },
    )
    .await;
    assert!(matches!(bad, Err(AppError::BadRequest(_))));

    let updated = tenants::update(
        &app.state,
        Actor::System,
        t.id,
        TenantUpdate {
            display_name: Some("Acme Corp".into()),
            status: Some(TenantStatus::Disabled),
            settings: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(updated.display_name, "Acme Corp");
    assert_eq!(updated.status, TenantStatus::Disabled);

    let page = tenants::list(&app.state, None, Some(2)).await.unwrap();
    assert_eq!(page.items.len(), 2);
    assert!(page.next_cursor.is_some());
    let page2 = tenants::list(&app.state, page.next_cursor.as_deref(), Some(500))
        .await
        .unwrap();
    assert!(
        page2
            .items
            .iter()
            .all(|x| !page.items.iter().any(|y| y.id == x.id))
    );

    let master = ridm_api::models::MASTER_TENANT_ID;
    assert!(matches!(
        tenants::delete(&app.state, Actor::System, master).await,
        Err(AppError::BadRequest(_))
    ));
    assert!(matches!(
        tenants::update(
            &app.state,
            Actor::System,
            master,
            TenantUpdate {
                status: Some(TenantStatus::Disabled),
                ..Default::default()
            }
        )
        .await,
        Err(AppError::BadRequest(_))
    ));

    tenants::delete(&app.state, Actor::System, t.id)
        .await
        .unwrap();
    assert!(matches!(
        tenants::get(&app.state, t.id).await,
        Err(AppError::NotFound(_))
    ));
}

// ---------------------------------------------------------------------------
// users
// ---------------------------------------------------------------------------

#[tokio::test]
async fn user_crud_normalization_and_conflicts() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;

    let u = users::create(
        &app.state,
        tid,
        Actor::System,
        NewUser {
            username: "  Alice ".into(),
            email: Some("Alice@Example.COM".into()),
            phone: Some("+1 555 000 1111".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(u.username, "alice");
    assert_eq!(u.email.as_deref(), Some("alice@example.com"));
    assert_eq!(u.phone.as_deref(), Some("+15550001111"));
    assert!(!u.has_password());

    for dup in [
        new_user("alice"),
        NewUser {
            username: "alice2".into(),
            email: Some("ALICE@example.com".into()),
            ..Default::default()
        },
    ] {
        let r = users::create(&app.state, tid, Actor::System, dup).await;
        assert!(matches!(r, Err(AppError::Conflict(_))), "{r:?}");
    }

    // PATCH semantics: absent = keep, null = clear, value = set.
    let patch: UserUpdate = serde_json::from_str(r#"{"phone": null, "locale": "de"}"#).unwrap();
    let u2 = users::update(&app.state, tid, Actor::System, u.id, patch)
        .await
        .unwrap();
    assert_eq!(u2.phone, None);
    assert_eq!(u2.email.as_deref(), Some("alice@example.com"));
    assert_eq!(u2.locale.as_deref(), Some("de"));
    // Undeclared attributes are rejected by the (empty) profile schema.
    let undeclared: UserUpdate =
        serde_json::from_str(r#"{"attributes": {"dept": "eng"}}"#).unwrap();
    assert!(matches!(
        users::update(&app.state, tid, Actor::System, u.id, undeclared).await,
        Err(AppError::Validation(_))
    ));

    let bad: UserUpdate = serde_json::from_str(r#"{"attributes": [1,2]}"#).unwrap();
    assert!(matches!(
        users::update(&app.state, tid, Actor::System, u.id, bad).await,
        Err(AppError::BadRequest(_))
    ));

    assert_eq!(
        users::find_by_identifier(&app.state, tid, "ALICE@example.com")
            .await
            .unwrap()
            .map(|x| x.id),
        Some(u.id)
    );

    // Soft delete hides the user and frees the username.
    users::delete(&app.state, tid, Actor::System, u.id)
        .await
        .unwrap();
    assert!(matches!(
        users::get(&app.state, tid, u.id).await,
        Err(AppError::NotFound(_))
    ));
    assert!(
        users::find_by_identifier(&app.state, tid, "alice")
            .await
            .unwrap()
            .is_none()
    );
    let again = users::create(&app.state, tid, Actor::System, new_user("alice")).await;
    assert!(again.is_ok(), "{again:?}");
}

#[tokio::test]
async fn user_list_pagination_and_search() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    for i in 0..7 {
        users::create(
            &app.state,
            tid,
            Actor::System,
            new_user(&format!("pager{i}")),
        )
        .await
        .unwrap();
    }
    users::create(&app.state, tid, Actor::System, new_user("zed"))
        .await
        .unwrap();

    let mut seen = vec![];
    let mut cursor: Option<String> = None;
    loop {
        let page = users::list(
            &app.state,
            tid,
            &UserFilter::default(),
            cursor.as_deref(),
            Some(3),
        )
        .await
        .unwrap();
        seen.extend(page.items.iter().map(|u| u.username.clone()));
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(seen.len(), 8);
    let mut sorted = seen.clone();
    sorted.dedup();
    assert_eq!(seen, sorted, "no duplicates across pages");

    let found = users::list(
        &app.state,
        tid,
        &UserFilter {
            search: Some("PAGER".into()),
            ..Default::default()
        },
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(found.items.len(), 7);
    assert!(matches!(
        users::list(
            &app.state,
            tid,
            &UserFilter::default(),
            Some("garbage"),
            None
        )
        .await,
        Err(AppError::BadRequest(_))
    ));
}

#[tokio::test]
async fn users_are_invisible_across_tenants() {
    let app = TestApp::spawn().await;
    let other = common::create_tenant(&app.state.db).await;
    let u = users::create(&app.state, app.tenant.id, Actor::System, new_user("bob"))
        .await
        .unwrap();
    assert!(matches!(
        users::get(&app.state, other.id, u.id).await,
        Err(AppError::NotFound(_))
    ));
    assert!(matches!(
        users::update(
            &app.state,
            other.id,
            Actor::System,
            u.id,
            UserUpdate {
                locale: Some(Some("fr".into())),
                ..Default::default()
            }
        )
        .await,
        Err(AppError::NotFound(_))
    ));
    assert!(matches!(
        users::delete(&app.state, other.id, Actor::System, u.id).await,
        Err(AppError::NotFound(_))
    ));
    assert_eq!(
        users::list(&app.state, other.id, &UserFilter::default(), None, None)
            .await
            .unwrap()
            .items
            .len(),
        0
    );
}

// ---------------------------------------------------------------------------
// groups
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nested_groups_membership_and_cycle_prevention() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let mk = |name: &str, parent: Option<Uuid>| {
        let st = app.state.clone();
        let name = name.to_string();
        async move {
            groups::create(
                &st,
                tid,
                Actor::System,
                NewGroup {
                    name,
                    parent_id: parent,
                    ..Default::default()
                },
            )
            .await
            .unwrap()
        }
    };
    let root = mk("engineering", None).await;
    let backend = mk("backend", Some(root.id)).await;
    let db_team = mk("db", Some(backend.id)).await;

    // Sibling names must be unique, but the same name under another parent is fine.
    assert!(matches!(
        groups::create(
            &app.state,
            tid,
            Actor::System,
            NewGroup {
                name: "backend".into(),
                parent_id: Some(root.id),
                ..Default::default()
            }
        )
        .await,
        Err(AppError::Conflict(_))
    ));
    mk("backend", None).await;

    // Cycle: cannot move root under its grandchild.
    let cyc = groups::update(
        &app.state,
        tid,
        Actor::System,
        root.id,
        GroupUpdate {
            parent_id: Some(Some(db_team.id)),
            ..Default::default()
        },
    )
    .await;
    assert!(matches!(cyc, Err(AppError::BadRequest(_))), "{cyc:?}");

    let alice = users::create(&app.state, tid, Actor::System, new_user("alice"))
        .await
        .unwrap();
    groups::add_member(&app.state, tid, Actor::System, db_team.id, alice.id)
        .await
        .unwrap();
    // Idempotent.
    groups::add_member(&app.state, tid, Actor::System, db_team.id, alice.id)
        .await
        .unwrap();

    let direct = groups::groups_of_user(&app.state, tid, alice.id, false)
        .await
        .unwrap();
    assert_eq!(
        direct.iter().map(|g| g.id).collect::<Vec<_>>(),
        vec![db_team.id]
    );
    let mut effective: Vec<Uuid> = groups::groups_of_user(&app.state, tid, alice.id, true)
        .await
        .unwrap()
        .into_iter()
        .map(|g| g.id)
        .collect();
    effective.sort();
    let mut expected = vec![root.id, backend.id, db_team.id];
    expected.sort();
    assert_eq!(effective, expected, "membership is inherited by ancestors");

    let members = groups::members(&app.state, tid, db_team.id).await.unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].id, alice.id);

    groups::remove_member(&app.state, tid, Actor::System, db_team.id, alice.id)
        .await
        .unwrap();
    assert!(
        groups::members(&app.state, tid, db_team.id)
            .await
            .unwrap()
            .is_empty()
    );

    // Deleting the root cascades to descendants.
    groups::delete(&app.state, tid, Actor::System, root.id)
        .await
        .unwrap();
    assert!(matches!(
        groups::get(&app.state, tid, db_team.id).await,
        Err(AppError::NotFound(_))
    ));
    assert!(matches!(
        groups::add_member(&app.state, tid, Actor::System, Uuid::now_v7(), alice.id).await,
        Err(AppError::NotFound("group"))
    ));
}

// ---------------------------------------------------------------------------
// roles
// ---------------------------------------------------------------------------

#[tokio::test]
async fn effective_roles_resolve_groups_ancestors_and_composites() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let st = &app.state;
    let role = |name: &str| {
        let name = name.to_string();
        async move {
            roles::create(
                st,
                tid,
                Actor::System,
                NewRole {
                    name,
                    ..Default::default()
                },
            )
            .await
            .unwrap()
        }
    };
    let viewer = role("viewer").await;
    let editor = role("editor").await;
    let admin = role("admin").await;
    let direct = role("direct").await;
    let group_role = role("group-role").await;

    assert!(matches!(
        roles::create(
            st,
            tid,
            Actor::System,
            NewRole {
                name: "viewer".into(),
                ..Default::default()
            }
        )
        .await,
        Err(AppError::Conflict(_))
    ));

    // admin ⊃ editor ⊃ viewer
    roles::add_composite(st, tid, Actor::System, admin.id, editor.id)
        .await
        .unwrap();
    roles::add_composite(st, tid, Actor::System, editor.id, viewer.id)
        .await
        .unwrap();
    // viewer ⊃ admin would be a cycle.
    let cyc = roles::add_composite(st, tid, Actor::System, viewer.id, admin.id).await;
    assert!(matches!(cyc, Err(AppError::BadRequest(_))), "{cyc:?}");
    assert!(matches!(
        roles::add_composite(st, tid, Actor::System, admin.id, admin.id).await,
        Err(AppError::BadRequest(_))
    ));

    let parent = groups::create(
        st,
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
        st,
        tid,
        Actor::System,
        NewGroup {
            name: "team".into(),
            parent_id: Some(parent.id),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let alice = users::create(st, tid, Actor::System, new_user("alice"))
        .await
        .unwrap();

    // Nothing yet, and the empty result is cached.
    assert!(
        roles::effective_roles(st, tid, alice.id, None)
            .await
            .unwrap()
            .is_empty()
    );

    roles::assign(
        st,
        tid,
        Actor::System,
        direct.id,
        Principal::User { id: alice.id },
    )
    .await
    .unwrap();
    roles::assign(
        st,
        tid,
        Actor::System,
        group_role.id,
        Principal::Group { id: parent.id },
    )
    .await
    .unwrap();
    roles::assign(
        st,
        tid,
        Actor::System,
        admin.id,
        Principal::Group { id: parent.id },
    )
    .await
    .unwrap();
    groups::add_member(st, tid, Actor::System, child.id, alice.id)
        .await
        .unwrap();

    let names = roles::effective_role_names(st, tid, alice.id, None)
        .await
        .unwrap();
    assert_eq!(
        names,
        vec!["admin", "direct", "editor", "group-role", "viewer"]
    );

    // Each change invalidates the cached resolution (via the version token).
    roles::remove_composite(st, tid, Actor::System, editor.id, viewer.id)
        .await
        .unwrap();
    let names = roles::effective_role_names(st, tid, alice.id, None)
        .await
        .unwrap();
    assert_eq!(names, vec!["admin", "direct", "editor", "group-role"]);

    groups::remove_member(st, tid, Actor::System, child.id, alice.id)
        .await
        .unwrap();
    assert_eq!(
        roles::effective_role_names(st, tid, alice.id, None)
            .await
            .unwrap(),
        vec!["direct"]
    );

    roles::unassign(
        st,
        tid,
        Actor::System,
        direct.id,
        Principal::User { id: alice.id },
    )
    .await
    .unwrap();
    assert!(
        roles::effective_roles(st, tid, alice.id, None)
            .await
            .unwrap()
            .is_empty()
    );

    // Assigning to unknown principals is rejected.
    assert!(matches!(
        roles::assign(
            st,
            tid,
            Actor::System,
            viewer.id,
            Principal::User { id: Uuid::now_v7() }
        )
        .await,
        Err(AppError::NotFound("user"))
    ));
    assert!(matches!(
        roles::assign(
            st,
            tid,
            Actor::System,
            Uuid::now_v7(),
            Principal::User { id: alice.id }
        )
        .await,
        Err(AppError::NotFound("role"))
    ));

    let assignments = roles::assignments_of(st, tid, Principal::Group { id: parent.id })
        .await
        .unwrap();
    assert_eq!(assignments.len(), 2);
    let children = roles::composites_of(st, tid, admin.id).await.unwrap();
    assert_eq!(
        children.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
        vec!["editor"]
    );

    roles::delete(st, tid, Actor::System, admin.id)
        .await
        .unwrap();
    assert!(
        roles::composites_of(st, tid, admin.id)
            .await
            .unwrap()
            .is_empty()
    );
    let all = roles::list(st, tid, None).await.unwrap();
    // Every tenant also carries the five built-in `ridm:*` admin roles.
    assert_eq!(all.iter().filter(|r| !r.built_in).count(), 4);
    assert_eq!(all.iter().filter(|r| r.built_in).count(), 5);
}
