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
    "organizations",
    "organization_members",
    "organization_domains",
    "roles",
    "role_assignments",
    "role_composites",
    "signing_keys",
    "refresh_tokens",
    "clients",
    "resource_servers",
    "permissions",
    "permission_assignments",
    "scopes",
    "claim_mappers",
    "consents",
    "login_attempts",
    "tenant_provider_settings",
    "message_templates",
    "outbound_messages",
    "invitations",
    "sso_sessions",
    "trusted_devices",
    "user_login_locations",
    "audit_chains",
    "audit_events",
    "ciba_requests",
    "dcr_initial_access_tokens",
    "device_codes",
    "federated_identities",
    "identity_providers",
    "ip_rules",
    "kerberos_identity_providers",
    "ldap_group_links",
    "ldap_identity_providers",
    "mtls_trust_anchors",
    "personal_access_tokens",
    "saml_identity_providers",
    "saml_service_providers",
    "saml_signing_keys",
    "scim_tokens",
    "webhook_deliveries",
    "webhooks",
];

/// Indexes on tenant tables that deliberately do not lead with tenant_id.
const GLOBAL_LOOKUP_INDEXES: &[&str] = &[
    // A presented token is found by its hash before its tenant is known.
    "personal_access_tokens_token_hash_key",
    "scim_tokens_token_hash_key",
    // Verification and the sink walk one chain by sequence.
    "audit_events_chain_seq_idx",
    // The hourly cleanup deletes stale rows of every tenant at once.
    "refresh_tokens_purge_idx",
    "sso_sessions_purge_idx",
    "login_attempts_purge_idx",
    "outbound_messages_purge_idx",
    "webhook_deliveries_purge_idx",
    "device_codes_purge_idx",
    "ciba_requests_purge_idx",
    "invitations_purge_idx",
    "trusted_devices_purge_idx",
    "personal_access_tokens_purge_idx",
    "scim_tokens_purge_idx",
    // The delivery jobs poll every tenant's queue for what is due.
    "outbound_messages_live_idx",
    "webhook_deliveries_live_idx",
    // Master-key rotation walks one key generation across every tenant.
    "credentials_key_version_idx",
];

/// The first migration written under the online-migration rules that
/// [`new_migrations_do_not_block_writes`] enforces; older ones predate them
/// and cannot change (their checksums are recorded in every database).
const ONLINE_RULES_SINCE: i64 = 20260923220219;

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
        // Every table with a tenant_id (partitions aside) is in the list, so
        // a new one cannot skip the checks above.
        let mut with_tenant: Vec<String> = sqlx::query_scalar(
            "SELECT c.relname::text FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' \
             WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        with_tenant.sort();
        let mut listed: Vec<String> = TENANT_TABLES.iter().map(|t| t.to_string()).collect();
        listed.sort();
        assert_eq!(listed, with_tenant, "TENANT_TABLES and the schema disagree");
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

        // Every tenant-scoped index leads with tenant_id (performance rule),
        // except lookups that run before the tenant is known.
        let offenders: Vec<String> = sqlx::query_scalar(
            "SELECT indexname FROM pg_indexes WHERE schemaname = 'public' \
             AND tablename = ANY($1) AND indexdef NOT LIKE '%(tenant_id%' \
             AND indexname NOT LIKE '%_pkey' AND indexname <> ALL($2)",
        )
        .bind(TENANT_TABLES)
        .bind(GLOBAL_LOOKUP_INDEXES)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(
            offenders.is_empty(),
            "indexes not leading with tenant_id: {offenders:?}"
        );
        // A concurrent build that failed leaves an INVALID index behind.
        let invalid: Vec<String> = sqlx::query_scalar(
            "SELECT indexrelid::regclass::text FROM pg_index WHERE NOT indisvalid",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(invalid.is_empty(), "invalid indexes: {invalid:?}");

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
        // Superusers bypass RLS, so scope explicitly. Every tenant insert
        // seeds the six built-in admin roles on top of what the test added.
        let (u, g, r, b): (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM users WHERE tenant_id = $1), \
                    (SELECT count(*) FROM groups WHERE tenant_id = $1), \
                    (SELECT count(*) FROM roles WHERE tenant_id = $1 AND NOT built_in), \
                    (SELECT count(*) FROM roles WHERE tenant_id = $1 AND built_in)",
        )
        .bind(tid)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!((u, g, r, b), (1, 1, 1, 6));
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

/// The statements of a migration, comments and dollar-quoted bodies removed,
/// upper-cased and with whitespace collapsed.
fn statements(sql: &str) -> Vec<String> {
    let mut code = String::new();
    for line in sql.lines() {
        code.push_str(line.split("--").next().unwrap_or(""));
        code.push('\n');
    }
    // Function bodies may hold anything; their text is not a statement here.
    let mut outside = String::new();
    for (i, part) in code.split("$$").enumerate() {
        if i % 2 == 0 {
            outside.push_str(part);
        }
    }
    outside
        .split(';')
        .map(|s| {
            s.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_uppercase()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

/// Migrations run while the previous release is serving (see *Upgrading*), so
/// from [`ONLINE_RULES_SINCE`] on none may block writes to an existing table
/// for longer than an instant:
/// - an index on an existing table is built (or dropped) `CONCURRENTLY`, in
///   a `-- no-transaction` migration holding that one statement (Postgres
///   refuses `CONCURRENTLY` inside a transaction, and several statements in
///   one simple query are one); a partitioned table cannot be indexed
///   concurrently, so its migration must say why blocking it is safe;
/// - a foreign key added to an existing table is `NOT VALID`, validated by a
///   later migration (validation does not block writes);
/// - a column added to an existing table has no volatile default, which
///   would rewrite the table.
#[test]
fn new_migrations_do_not_block_writes() {
    const VOLATILE: &[&str] = &[
        "GEN_RANDOM_UUID(",
        "GEN_RANDOM_BYTES(",
        "RANDOM(",
        "CLOCK_TIMESTAMP(",
        "UUID_GENERATE",
    ];
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut checked = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let version: i64 = name.split('_').next().unwrap().parse().unwrap();
        if version < ONLINE_RULES_SINCE {
            continue;
        }
        checked += 1;
        let sql = std::fs::read_to_string(&path).unwrap();
        let no_transaction = sql.starts_with("-- no-transaction");
        let stmts = statements(&sql);
        // Tables this migration creates are new: nothing reads or writes them yet.
        let created: Vec<String> = stmts
            .iter()
            .filter_map(|s| s.strip_prefix("CREATE TABLE "))
            .filter_map(|s| {
                s.trim_start_matches("IF NOT EXISTS ")
                    .split([' ', '('])
                    .next()
            })
            .map(str::to_string)
            .collect();
        let is_new = |table: &str| created.iter().any(|c| c == table);
        let partitioned_ok = sql.contains("partitioned");
        if no_transaction {
            assert_eq!(
                stmts.len(),
                1,
                "{name}: a no-transaction migration holds one statement"
            );
        }
        for s in &stmts {
            if s.starts_with("CREATE INDEX") || s.starts_with("CREATE UNIQUE INDEX") {
                let table = s
                    .split(" ON ")
                    .nth(1)
                    .and_then(|r| r.trim_start_matches("ONLY ").split([' ', '(']).next())
                    .unwrap_or_default();
                if is_new(table) {
                    continue;
                }
                assert!(
                    (s.contains(" INDEX CONCURRENTLY ") && no_transaction) || partitioned_ok,
                    "{name}: `{s}` must be CREATE INDEX CONCURRENTLY in a -- no-transaction migration"
                );
            }
            if s.starts_with("DROP INDEX") {
                assert!(
                    (s.starts_with("DROP INDEX CONCURRENTLY ") && no_transaction) || partitioned_ok,
                    "{name}: `{s}` must be DROP INDEX CONCURRENTLY in a -- no-transaction migration"
                );
            }
            if let Some(rest) = s.strip_prefix("ALTER TABLE ") {
                let table = rest
                    .trim_start_matches("ONLY ")
                    .split(' ')
                    .next()
                    .unwrap_or_default();
                if is_new(table) {
                    continue;
                }
                if s.contains(" FOREIGN KEY ") {
                    assert!(
                        s.contains(" NOT VALID"),
                        "{name}: `{s}` must add the foreign key NOT VALID and validate it in a later migration"
                    );
                }
                if s.contains(" ADD COLUMN ") && s.contains(" DEFAULT ") {
                    assert!(
                        !VOLATILE.iter().any(|v| s.contains(v)),
                        "{name}: `{s}` has a volatile default, which rewrites the table: add the column, then backfill"
                    );
                }
            }
        }
    }
    assert!(checked > 0, "no migration since {ONLINE_RULES_SINCE} found");
}

/// The two-role layout of `deploy/postgres/init-app-role.sh` on a throwaway
/// database: a migrator that owns the schema and a DML-only application role.
/// Returns the URLs of the migrator, the application role and a role with no
/// grants at all, and the role names to drop afterwards.
async fn two_role_layout(url: &str, db_name: &str) -> ([String; 3], [String; 3]) {
    let suffix = &Uuid::new_v4().simple().to_string()[..8];
    let names = [
        format!("mt_migrator_{suffix}"),
        format!("mt_app_{suffix}"),
        format!("mt_other_{suffix}"),
    ];
    let [migrator, app, other] = &names;
    let mut admin = PgConnection::connect(url).await.unwrap();
    for role in &names {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE {role} LOGIN PASSWORD '{role}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"
        )))
        .execute(&mut admin)
        .await
        .unwrap();
    }
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "GRANT CONNECT, CREATE, TEMP ON DATABASE {db_name} TO {migrator};
         GRANT ALL ON SCHEMA public TO {migrator};
         GRANT CONNECT, TEMP ON DATABASE {db_name} TO {app};
         GRANT USAGE ON SCHEMA public TO {app};
         ALTER DEFAULT PRIVILEGES FOR ROLE {migrator} IN SCHEMA public
             GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {app};
         ALTER DEFAULT PRIVILEGES FOR ROLE {migrator} IN SCHEMA public
             GRANT USAGE, SELECT ON SEQUENCES TO {app};
         ALTER DEFAULT PRIVILEGES FOR ROLE {migrator} IN SCHEMA public
             GRANT EXECUTE ON FUNCTIONS TO {app};"
    )))
    .execute(&mut admin)
    .await
    .unwrap();
    admin.close().await.unwrap();
    let as_role = |role: &str| {
        let mut u = url::Url::parse(url).unwrap();
        u.set_username(role).unwrap();
        u.set_password(Some(role)).unwrap();
        u.to_string()
    };
    ([as_role(migrator), as_role(app), as_role(other)], names)
}

async fn drop_roles(names: &[String]) {
    let infra = common::infra().await;
    if let Ok(mut admin) = PgConnection::connect(&infra.admin_url).await {
        for role in names {
            let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP ROLE IF EXISTS {role}")))
                .execute(&mut admin)
                .await;
        }
    }
}

/// Review finding (Phase 10): `audit_ensure_partitions` ran with the caller's
/// rights, and the DML-only application role cannot create tables, so the
/// `audit_retention` job failed once the partitions made at migration time
/// ran out. It is now `SECURITY DEFINER`: the application role creates the
/// next months' partitions, a role without grants cannot call it, and a month
/// that already has rows in the default partition is skipped, not fatal.
/// Also: with every migration applied, the application role sees nothing
/// pending and `migrate_pending` (what `MIGRATE_ON_START` and `ridm-api
/// bootstrap` use) is a no-op instead of failing on `_sqlx_migrations`.
#[tokio::test]
async fn the_application_role_keeps_audit_partitions_coming() {
    let Some((url, name)) = fresh_database().await else {
        eprintln!("skipping: no CREATEDB-capable admin connection");
        return;
    };
    let ([migrator_url, app_url, other_url], roles) = two_role_layout(&url, &name).await;
    let result = async move {
        let migrator = sqlx::PgPool::connect(&migrator_url).await.unwrap();
        ridm_api::db::migrate(&migrator).await.unwrap();
        migrator.close().await;

        let app = sqlx::PgPool::connect(&app_url).await.unwrap();
        assert_eq!(ridm_api::db::pending_migrations(&app).await.unwrap(), 0);
        assert_eq!(ridm_api::db::migrate_pending(&app).await.unwrap(), 0);

        // Months 0..=2 exist from the migration; 3..=5 are the app role's.
        let created: i32 = sqlx::query_scalar("SELECT audit_ensure_partitions(5)")
            .fetch_one(&app)
            .await
            .unwrap();
        assert_eq!(created, 3);
        let third: Option<String> = sqlx::query_scalar(
            "SELECT to_regclass('audit_events_' || \
             to_char(date_trunc('month', now()) + interval '3 month', 'YYYYMM'))::text",
        )
        .fetch_one(&app)
        .await
        .unwrap();
        assert!(
            third.is_some(),
            "the app role created next quarter's partition"
        );

        // A row that fell into the default partition (partitions were missing
        // when it was written) does not stop the rest.
        let admin = sqlx::PgPool::connect(&url).await.unwrap();
        sqlx::query(
            "INSERT INTO audit_events (id, chain_id, seq, occurred_at, name, actor_type, payload, hash) \
             VALUES ($1, $2, 1, date_trunc('month', now()) + interval '7 month', 'x', 'system', '{}', '\\x00')",
        )
        .bind(Uuid::now_v7())
        .bind(Uuid::nil())
        .execute(&admin)
        .await
        .unwrap();
        admin.close().await;
        let created: i32 = sqlx::query_scalar("SELECT audit_ensure_partitions(8)")
            .fetch_one(&app)
            .await
            .unwrap();
        assert_eq!(created, 2, "months 6 and 8; month 7 is skipped");

        // Retention drops a whole month once every chain in it is past its
        // retention, never one holding a chain nobody governs, nor the
        // current month.
        // Partitions belong to the schema owner, as audit_ensure_partitions
        // makes them.
        let migrator = sqlx::PgPool::connect(&migrator_url).await.unwrap();
        sqlx::query(
            "CREATE TABLE audit_events_200001 PARTITION OF audit_events \
             FOR VALUES FROM ('2000-01-01') TO ('2000-02-01')",
        )
        .execute(&migrator)
        .await
        .unwrap();
        migrator.close().await;
        let admin = sqlx::PgPool::connect(&url).await.unwrap();
        let governed = Uuid::now_v7();
        let orphan = Uuid::now_v7();
        for chain in [governed, orphan] {
            sqlx::query(
                "INSERT INTO audit_events (id, chain_id, seq, occurred_at, name, actor_type, payload, hash) \
                 VALUES ($1, $2, 1, '2000-01-15', 'x', 'system', '{}', '\\x00')",
            )
            .bind(Uuid::now_v7())
            .bind(chain)
            .execute(&admin)
            .await
            .unwrap();
        }
        let drop = |chains: Vec<Uuid>| {
            let app = app.clone();
            async move {
                sqlx::query_scalar::<_, i32>(
                    "SELECT audit_drop_partitions_before(current_date + 400, $1)",
                )
                .bind(chains)
                .fetch_one(&app)
                .await
                .unwrap()
            }
        };
        assert_eq!(
            drop(vec![governed]).await,
            0,
            "the orphan chain keeps the month"
        );
        sqlx::query("DELETE FROM audit_events WHERE chain_id = $1")
            .bind(orphan)
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
        assert_eq!(drop(vec![governed]).await, 1, "the month goes whole");
        let gone: Option<String> =
            sqlx::query_scalar("SELECT to_regclass('audit_events_200001')::text")
                .fetch_one(&app)
                .await
                .unwrap();
        assert_eq!(gone, None);
        let current: Option<String> = sqlx::query_scalar(
            "SELECT to_regclass('audit_events_' || to_char(now(), 'YYYYMM'))::text",
        )
        .fetch_one(&app)
        .await
        .unwrap();
        assert!(current.is_some(), "the current month is never dropped");
        app.close().await;

        // Not callable by everyone.
        let other = sqlx::PgPool::connect(&other_url).await.unwrap();
        let err = sqlx::query_scalar::<_, i32>("SELECT audit_ensure_partitions(9)")
            .fetch_one(&other)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("permission denied"), "{err}");
        let err = sqlx::query_scalar::<_, i32>(
            "SELECT audit_drop_partitions_before(current_date, '{}'::uuid[])",
        )
        .fetch_one(&other)
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("permission denied"), "{err}");
        other.close().await;
    };
    let outcome = tokio::spawn(result).await;
    drop_database(&name).await;
    drop_roles(&roles).await;
    outcome.unwrap();
}
