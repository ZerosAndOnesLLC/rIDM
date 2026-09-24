//! Tenant isolation suite v1.
//!
//! Every repository query, executed inside another tenant's transaction, must
//! return nothing / affect nothing, and the application role must be unable to
//! step around row level security.

mod common;

use common::TestApp;
use ridm_api::db;
use ridm_api::models::{
    GroupUpdate, NewGroup, NewRole, NewUser, Principal, ProfileSchema, RoleUpdate, UserFilter,
    UserUpdate,
};
use ridm_api::repos;
use ridm_api::services::{groups, roles, users};
use ridm_core::events::Actor;
use uuid::Uuid;

struct Fixture {
    app: TestApp,
    a: Uuid,
    b: Uuid,
    user: Uuid,
    group: Uuid,
    role: Uuid,
}

async fn fixture() -> Fixture {
    let app = TestApp::spawn().await;
    let a = app.tenant.id;
    let b = common::create_tenant(&app.state.db).await.id;
    let user = users::create(
        &app.state,
        a,
        Actor::System,
        NewUser {
            username: "alice".into(),
            email: Some("alice@a.example".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .id;
    let group = groups::create(
        &app.state,
        a,
        Actor::System,
        NewGroup {
            name: "g".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .id;
    let role = roles::create(
        &app.state,
        a,
        Actor::System,
        NewRole {
            name: "r".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .id;
    groups::add_member(&app.state, a, Actor::System, group, user)
        .await
        .unwrap();
    roles::assign(
        &app.state,
        a,
        Actor::System,
        role,
        Principal::User { id: user },
    )
    .await
    .unwrap();
    ridm_api::services::profile_schema::set(&app.state, a, Actor::System, ProfileSchema::default())
        .await
        .unwrap();
    Fixture {
        app,
        a,
        b,
        user,
        group,
        role,
    }
}

#[tokio::test]
async fn repo_reads_from_another_tenant_are_empty() {
    let f = fixture().await;
    let mut tx = db::tenant_tx(&f.app.state.db, f.b).await.unwrap();
    let c = &mut *tx;

    assert!(
        repos::users::find_by_id(&mut *c, f.a, f.user)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repos::users::find_by_username(&mut *c, f.a, "alice")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repos::users::find_by_email(&mut *c, f.a, "alice@a.example")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repos::users::find_by_identifier(&mut *c, f.a, "alice")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repos::users::list(&mut *c, f.a, &UserFilter::default(), None, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(repos::users::count(&mut *c, f.a).await.unwrap(), 0);

    assert!(
        repos::groups::find_by_id(&mut *c, f.a, f.group)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repos::groups::list_all(&mut *c, f.a)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repos::groups::ancestor_ids(&mut *c, f.a, f.group)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repos::memberships::page(
            &mut *c,
            f.a,
            repos::memberships::Of::Group(f.group),
            None,
            None,
            50
        )
        .await
        .unwrap()
        .is_empty()
    );
    assert!(
        repos::groups::direct_groups_of_user(&mut *c, f.a, f.user)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repos::groups::effective_groups_of_user(&mut *c, f.a, f.user)
            .await
            .unwrap()
            .is_empty()
    );

    assert!(
        repos::roles::find_by_id(&mut *c, f.a, f.role)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repos::roles::find_by_name(&mut *c, f.a, None, "r")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repos::roles::list_all(&mut *c, f.a, None)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repos::roles::assignments_of(&mut *c, f.a, Principal::User { id: f.user })
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repos::roles::composites_of(&mut *c, f.a, f.role)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repos::roles::effective_roles_of_user(&mut *c, f.a, f.user, None)
            .await
            .unwrap()
            .is_empty()
    );

    assert!(
        repos::password_history::recent(&mut *c, f.a, f.user, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repos::profile_schema::get(&mut *c, f.a)
            .await
            .unwrap()
            .is_none()
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn repo_writes_from_another_tenant_affect_nothing() {
    let f = fixture().await;
    let mut tx = db::tenant_tx(&f.app.state.db, f.b).await.unwrap();
    let c = &mut *tx;

    // Updates and deletes silently match nothing.
    let patch = UserUpdate {
        locale: Some(Some("fr".into())),
        ..Default::default()
    };
    assert!(
        repos::users::update(&mut *c, f.a, f.user, &patch)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !repos::users::soft_delete(&mut *c, f.a, f.user)
            .await
            .unwrap()
    );
    assert!(
        !repos::users::hard_delete(&mut *c, f.a, f.user)
            .await
            .unwrap()
    );
    assert!(
        !repos::users::set_password(&mut *c, f.a, f.user, "$argon2id$x", "argon2id", false, None)
            .await
            .unwrap()
    );
    assert!(!repos::users::unlock(&mut *c, f.a, f.user).await.unwrap());
    let gpatch = GroupUpdate {
        name: Some("renamed".into()),
        ..Default::default()
    };
    assert!(
        repos::groups::update(&mut *c, f.a, f.group, &gpatch)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!repos::groups::delete(&mut *c, f.a, f.group).await.unwrap());
    assert!(
        !repos::groups::remove_member(&mut *c, f.a, f.group, f.user)
            .await
            .unwrap()
    );
    let rpatch = RoleUpdate {
        name: Some("renamed".into()),
        ..Default::default()
    };
    assert!(
        repos::roles::update(&mut *c, f.a, f.role, &rpatch)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!repos::roles::delete(&mut *c, f.a, f.role).await.unwrap());
    assert!(
        !repos::roles::unassign(&mut *c, f.a, f.role, Principal::User { id: f.user }, None)
            .await
            .unwrap()
    );
    assert!(
        !repos::roles::remove_composite(&mut *c, f.a, f.role, f.role)
            .await
            .unwrap()
    );
    tx.rollback().await.unwrap();

    // Inserts that reference tenant A's rows fail outright (RLS / FK). Each
    // runs in its own transaction because Postgres aborts a transaction on error.
    let db = &f.app.state.db;
    let mut tx = db::tenant_tx(db, f.b).await.unwrap();
    assert!(
        repos::groups::add_member(&mut *tx, f.a, f.group, f.user)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let mut tx = db::tenant_tx(db, f.b).await.unwrap();
    assert!(
        repos::roles::assign(&mut *tx, f.a, f.role, Principal::User { id: f.user }, None)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let mut tx = db::tenant_tx(db, f.b).await.unwrap();
    assert!(
        repos::roles::add_composite(&mut *tx, f.a, f.role, f.role)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let mut tx = db::tenant_tx(db, f.b).await.unwrap();
    assert!(
        repos::password_history::insert(&mut *tx, f.a, f.user, "h")
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();

    // Everything in tenant A is untouched.
    let u = users::get(&f.app.state, f.a, f.user).await.unwrap();
    assert_eq!(u.locale, None);
    assert!(!u.has_password());
    assert_eq!(
        groups::get(&f.app.state, f.a, f.group).await.unwrap().name,
        "g"
    );
    assert_eq!(
        roles::get(&f.app.state, f.a, f.role).await.unwrap().name,
        "r"
    );
    assert_eq!(
        groups::members(&f.app.state, f.a, f.group, None, None, None)
            .await
            .unwrap()
            .items
            .len(),
        1
    );
    assert_eq!(
        roles::effective_role_names(&f.app.state, f.a, f.user, None)
            .await
            .unwrap(),
        vec!["r"]
    );
}

#[tokio::test]
async fn service_layer_returns_not_found_across_tenants() {
    use ridm_api::error::AppError;
    let f = fixture().await;
    let s = &f.app.state;
    let nf = |r: Result<(), AppError>| assert!(matches!(r, Err(AppError::NotFound(_))), "{r:?}");

    nf(users::get(s, f.b, f.user).await.map(drop));
    nf(users::delete(s, f.b, Actor::System, f.user).await);
    nf(users::unlock(s, f.b, Actor::System, f.user).await);
    nf(groups::get(s, f.b, f.group).await.map(drop));
    nf(groups::delete(s, f.b, Actor::System, f.group).await);
    nf(groups::members(s, f.b, f.group, None, None, None)
        .await
        .map(drop));
    nf(groups::add_member(s, f.b, Actor::System, f.group, f.user).await);
    nf(roles::get(s, f.b, f.role).await.map(drop));
    nf(roles::delete(s, f.b, Actor::System, f.role).await);
    nf(roles::assign(
        s,
        f.b,
        Actor::System,
        f.role,
        Principal::User { id: f.user },
    )
    .await);
    nf(roles::add_composite(s, f.b, Actor::System, f.role, Uuid::now_v7()).await);
    assert!(
        roles::effective_roles(s, f.b, f.user, None)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        groups::groups_of_user(s, f.b, f.user, true)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn rls_cannot_be_circumvented_by_the_application_role() {
    let f = fixture().await;
    let db = f.app.state.db.home();

    // 1. A tenant_id predicate does not override the bound tenant.
    let mut tx = db::tenant_tx(&f.app.state.db, f.b).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE tenant_id = $1")
        .bind(f.a)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(n, 0);

    // 2. Rebinding app.tenant_id inside the transaction only moves the window;
    //    it never lets rows leak into the wrong tenant.
    db::bind_tenant(&mut tx, f.a).await.unwrap();
    let cross = sqlx::query("INSERT INTO users (tenant_id, username) VALUES ($1, 'mallory')")
        .bind(f.b)
        .execute(&mut *tx)
        .await;
    assert!(cross.is_err());
    tx.rollback().await.unwrap();

    // 3. A garbage tenant binding matches nothing (and cannot inject).
    let mut tx = db.begin().await.unwrap();
    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind("' OR 1=1 --")
        .execute(&mut *tx)
        .await
        .unwrap();
    let r = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM users")
        .fetch_one(&mut *tx)
        .await;
    // Either the cast fails (error) or nothing is visible; never a leak.
    assert!(r.is_err() || r.unwrap() == 0);
    tx.rollback().await.unwrap();

    // 4. Disabling row security as the app role errors instead of bypassing.
    let mut tx = db.begin().await.unwrap();
    sqlx::query("SET LOCAL row_security = off")
        .execute(&mut *tx)
        .await
        .unwrap();
    let r = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM users")
        .fetch_one(&mut *tx)
        .await;
    assert!(
        r.is_err(),
        "row_security=off must not bypass a forced policy"
    );
    tx.rollback().await.unwrap();

    // 5. The app role does not own the tables, so it cannot alter or drop RLS.
    if common::infra().await.migrator_url.is_some() {
        for stmt in [
            "ALTER TABLE users DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE users NO FORCE ROW LEVEL SECURITY",
            "DROP POLICY tenant_isolation ON users",
            "ALTER TABLE users OWNER TO current_user",
            "DROP TABLE users",
        ] {
            let r = sqlx::query(stmt).execute(db).await;
            assert!(r.is_err(), "{stmt} must be refused for the app role");
        }
        // 6. And it cannot grant itself BYPASSRLS.
        let r = sqlx::query("ALTER ROLE current_user BYPASSRLS")
            .execute(db)
            .await;
        assert!(r.is_err());
    }

    // 7. Without any binding the pool sees nothing at all.
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(db)
        .await
        .unwrap();
    assert_eq!(n, 0);
}
