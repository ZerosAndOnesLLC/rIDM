//! Migration suite: apply every migration to a fresh database, check the
//! resulting schema (tables, RLS flags, seeds, constraints), then re-apply to
//! a seeded snapshot and verify it is a no-op.

mod common;

use sqlx::Connection as _;
use sqlx::postgres::PgConnection;
use uuid::Uuid;

const TENANT_TABLES: &[&str] = &[
    "users",
    "user_profile_schema",
    "password_history",
    "credentials",
    "groups",
    "group_members",
    "roles",
    "role_assignments",
    "role_composites",
];

/// Create a throwaway database (needs a superuser/CREATEDB admin URL) and
/// return a URL pointing at it. `None` when we only have an ordinary role.
async fn fresh_database() -> Option<(String, String)> {
    let infra = common::infra().await;
    let mut admin = PgConnection::connect(&infra.admin_url).await.ok()?;
    let can_create: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolcreatedb FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&mut admin)
    .await
    .ok()?;
    if !can_create {
        return None;
    }
    let name = format!(
        "ridm_migtest_{}",
        &Uuid::new_v4().simple().to_string()[..12]
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&mut admin)
        .await
        .ok()?;
    admin.close().await.ok()?;
    let mut url = url::Url::parse(&infra.admin_url).ok()?;
    url.set_path(&format!("/{name}"));
    Some((url.to_string(), name))
}

async fn drop_database(name: &str) {
    let infra = common::infra().await;
    if let Ok(mut admin) = PgConnection::connect(&infra.admin_url).await {
        let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
        )))
        .execute(&mut admin)
        .await;
    }
}

#[tokio::test]
async fn migrations_apply_cleanly_and_are_idempotent() {
    let Some((url, name)) = fresh_database().await else {
        eprintln!("skipping: no CREATEDB-capable admin connection");
        return;
    };
    let result = async move {
        let pool = sqlx::PgPool::connect(&url).await.unwrap();
        ridm_api::db::migrate(&pool).await.unwrap();

        // Every migration file was applied and recorded as successful.
        let applied: i64 =
            sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(applied as usize, ridm_api::db::MIGRATOR.iter().count());

        // Expected tables exist, tenant-scoped ones with forced RLS and a policy.
        for t in TENANT_TABLES {
            let (rls, forced): (bool, bool) = sqlx::query_as(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = $1",
            )
            .bind(t)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("table {t} missing: {e}"));
            assert!(rls && forced, "{t}: rls={rls} forced={forced}");
            let policies: i64 =
                sqlx::query_scalar("SELECT count(*) FROM pg_policies WHERE tablename = $1")
                    .bind(t)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(policies, 1, "{t} must have exactly one policy");
            let has_tenant: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
                 WHERE table_name = $1 AND column_name = 'tenant_id')",
            )
            .bind(t)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert!(has_tenant, "{t} has no tenant_id column");
        }
        // tenants is global: no RLS.
        let (rls, _): (bool, bool) = sqlx::query_as(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'tenants'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!rls);

        // Seed: exactly one master tenant with the fixed id.
        let (count, id): (i64, Option<Uuid>) =
            sqlx::query_as("SELECT count(*), (SELECT id FROM tenants WHERE slug = 'master' LIMIT 1) FROM tenants WHERE slug = 'master'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 1);
        assert_eq!(id, Some(ridm_api::models::MASTER_TENANT_ID));

        // Every tenant-scoped index leads with tenant_id (performance rule).
        let offenders: Vec<String> = sqlx::query_scalar(
            "SELECT indexname FROM pg_indexes WHERE schemaname = 'public' \
             AND tablename = ANY($1) AND indexdef NOT LIKE '%(tenant_id%' \
             AND indexname NOT LIKE '%_pkey'",
        )
        .bind(TENANT_TABLES)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(
            offenders.is_empty(),
            "indexes not leading with tenant_id: {offenders:?}"
        );

        // Seeded snapshot, then re-run: no new migrations, data intact.
        let tid = Uuid::now_v7();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, 'snap', 'Snap')")
            .bind(tid)
            .execute(&mut *tx)
            .await
            .unwrap();
        ridm_api::db::bind_tenant(&mut tx, tid).await.unwrap();
        sqlx::query("INSERT INTO users (tenant_id, username, email) VALUES ($1, 'u1', 'u1@x.io')")
            .bind(tid)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO groups (tenant_id, name) VALUES ($1, 'g1')")
            .bind(tid)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO roles (tenant_id, name) VALUES ($1, 'r1')")
            .bind(tid)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        // Constraint spot checks, each in its own transaction (an error aborts
        // the whole Postgres transaction).
        let mut tx = pool.begin().await.unwrap();
        ridm_api::db::bind_tenant(&mut tx, tid).await.unwrap();
        assert!(
            sqlx::query("INSERT INTO users (tenant_id, username) VALUES ($1, 'MixedCase')")
                .bind(tid)
                .execute(&mut *tx)
                .await
                .is_err(),
            "username must be lowercase"
        );
        tx.rollback().await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        ridm_api::db::bind_tenant(&mut tx, tid).await.unwrap();
        assert!(
            sqlx::query("INSERT INTO users (tenant_id, username) VALUES ($1, 'u1')")
                .bind(tid)
                .execute(&mut *tx)
                .await
                .is_err(),
            "duplicate username"
        );
        tx.rollback().await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        ridm_api::db::bind_tenant(&mut tx, tid).await.unwrap();
        assert!(
            sqlx::query(
                "INSERT INTO users (tenant_id, username, password_hash) VALUES ($1, 'u2', 'h')"
            )
            .bind(tid)
            .execute(&mut *tx)
            .await
            .is_err(),
            "hash without algo"
        );
        tx.rollback().await.unwrap();

        ridm_api::db::migrate(&pool).await.unwrap();
        let applied_again: i64 =
            sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(applied, applied_again);
        let mut tx = pool.begin().await.unwrap();
        ridm_api::db::bind_tenant(&mut tx, tid).await.unwrap();
        let (u, g, r): (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM users), (SELECT count(*) FROM groups), (SELECT count(*) FROM roles)",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!((u, g, r), (1, 1, 1));
        tx.rollback().await.unwrap();
        pool.close().await;
    };
    // Always drop the throwaway database, even when an assertion fails.
    let outcome = tokio::spawn(result).await;
    drop_database(&name).await;
    outcome.unwrap();
}

#[tokio::test]
async fn migration_files_are_well_formed() {
    let mut versions: Vec<i64> = ridm_api::db::MIGRATOR.iter().map(|m| m.version).collect();
    assert!(!versions.is_empty());
    let sorted = {
        let mut s = versions.clone();
        s.sort_unstable();
        s
    };
    assert_eq!(versions, sorted, "migrations must be ordered by version");
    versions.dedup();
    assert_eq!(versions.len(), sorted.len(), "duplicate migration versions");
    for m in ridm_api::db::MIGRATOR.iter() {
        assert!(!m.description.trim().is_empty());
        assert!(
            m.migration_type == sqlx::migrate::MigrationType::Simple,
            "{}: forward-only migrations only",
            m.description
        );
    }
}
