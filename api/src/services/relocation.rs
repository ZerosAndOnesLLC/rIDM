//! Moving a tenant's data between databases (`ridm-api move-tenant`): from
//! the home database to a region, back, or between regions. The move is
//! offline — the tenant is unavailable while it runs — and safe to repeat:
//!
//! 1. the registry marks the tenant `relocating`, and the move waits out
//!    every node's cached placement ([`crate::db::PLACEMENT_TTL`]) plus the
//!    transactions in flight, after which no node writes the tenant anywhere;
//! 2. every tenant-scoped table is copied in foreign-key order, inside one
//!    transaction on the target, from one snapshot of the source; row counts
//!    must match table by table, and the copied audit chain must verify;
//! 3. with a separate Valkey on either side, the tenant's keys (sessions,
//!    flows, cached rows) are copied with their lifetimes;
//! 4. the registry points at the target and clears `relocating`;
//! 5. the source's copy (rows and keys) is deleted.
//!
//! A failure before step 4 deletes what reached the target and leaves the
//! tenant where it was. A failure after it leaves only a stale copy in the
//! source, which running the same move again removes.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::Serialize;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::cache;
use crate::config::HOME_REGION;
use crate::db::{self, Database, PLACEMENT_TTL};
use crate::error::{AppError, AppResult};
use crate::middleware::tenant_cache_keys;
use crate::models::{MASTER_TENANT_ID, Tenant};
use crate::repos;
use crate::services::audit;
use crate::state::AppState;

/// Rows per copied batch.
const BATCH: i64 = 2000;

#[derive(Debug, Clone)]
pub struct MoveOptions {
    /// How long to wait after marking the tenant before copying: longer
    /// than [`PLACEMENT_TTL`] plus the longest transaction a node may still
    /// be running for the tenant.
    pub drain: Duration,
}

impl Default for MoveOptions {
    fn default() -> Self {
        Self {
            drain: Duration::from_secs(20),
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct MoveReport {
    pub tenant: String,
    pub from: String,
    pub to: String,
    /// Rows copied per table (the tenant's `tenants` row not counted).
    pub rows: BTreeMap<String, i64>,
    /// Audit rows whose chain was re-verified in the target.
    pub audit_rows_verified: u64,
    /// Valkey keys copied (0 when both sides share a Valkey).
    pub cache_keys: u64,
    /// Databases a stale copy of the tenant was removed from.
    pub cleaned: Vec<String>,
}

/// A tenant-scoped table, with the columns a copy writes.
#[derive(Debug, Clone)]
struct Table {
    name: String,
    columns: Vec<String>,
    /// It references itself (`groups.parent_id`): copied in one statement,
    /// since a batch could hold a child before its parent.
    self_referencing: bool,
}

/// Move the tenant `slug` to `target` (a region name, or `None`/`home`).
pub async fn move_tenant(
    state: &AppState,
    slug: &str,
    target: Option<&str>,
    opts: &MoveOptions,
) -> AppResult<MoveReport> {
    let target_name = target.filter(|t| *t != HOME_REGION);
    let target = state.db.get(target_name).ok_or_else(|| {
        AppError::BadRequest(format!(
            "unknown data region `{}`; configured: {}",
            target_name.unwrap_or(HOME_REGION),
            region_names(state)
        ))
    })?;
    let tenant = repos::tenants::find_by_slug(state.db.home(), slug)
        .await?
        .ok_or(AppError::NotFound("tenant"))?;
    if tenant.id == MASTER_TENANT_ID {
        return Err(AppError::BadRequest(
            "the master tenant always lives in the home database".into(),
        ));
    }
    let source = state.db.get(tenant.data_region.as_deref()).ok_or_else(|| {
        AppError::Unavailable(format!(
            "the tenant's region `{}` is not configured here",
            tenant.data_region.as_deref().unwrap_or_default()
        ))
    })?;

    // One move per tenant at a time, across every process.
    let mut guard = state.db.home().acquire().await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext($1))")
        .bind(lock_name(tenant.id))
        .fetch_one(&mut *guard)
        .await?;
    if !locked {
        return Err(AppError::Conflict(
            "another move of this tenant is running".into(),
        ));
    }
    let outcome = if source.name == target.name {
        // Already there: an earlier attempt may have died before switching
        // (the data never left, but the tenant is still marked) or after
        // (a stale copy is left elsewhere). Settle both.
        async {
            if tenant.relocating {
                unlock_tenant(state, &tenant).await?;
            }
            clean_up(state, &tenant, target).await
        }
        .await
        .map(|cleaned| MoveReport {
            tenant: tenant.slug.clone(),
            from: source.name.to_string(),
            to: target.name.to_string(),
            cleaned,
            ..Default::default()
        })
    } else {
        relocate(state, &tenant, source, target, opts).await
    };
    let unlocked = sqlx::query("SELECT pg_advisory_unlock(hashtext($1))")
        .bind(lock_name(tenant.id))
        .execute(&mut *guard)
        .await;
    if let Err(err) = unlocked {
        // The session lock goes with the connection.
        tracing::warn!(error = %err, "move lock not released; closing its connection");
        guard.detach();
    }
    outcome
}

fn lock_name(tenant_id: Uuid) -> String {
    format!("ridm:move-tenant:{tenant_id}")
}

fn region_names(state: &AppState) -> String {
    state
        .db
        .all()
        .iter()
        .map(|d| d.name.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

async fn relocate(
    state: &AppState,
    tenant: &Tenant,
    source: &Database,
    target: &Database,
    opts: &MoveOptions,
) -> AppResult<MoveReport> {
    let mut report = MoveReport {
        tenant: tenant.slug.clone(),
        from: source.name.to_string(),
        to: target.name.to_string(),
        ..Default::default()
    };
    check_schemas(source, target).await?;
    let tables = tenant_tables(&source.primary).await?;
    if repos::tenants::set_relocating(state.db.home(), tenant.id, true).await? {
        tracing::info!(tenant = %tenant.slug, from = %source.name, to = %target.name, "tenant marked as moving");
    } else {
        tracing::info!(tenant = %tenant.slug, "resuming a move that did not finish");
    }
    forget_registry_entry(state, tenant).await;
    let drain = opts.drain.max(PLACEMENT_TTL + Duration::from_secs(1));
    tracing::info!(
        seconds = drain.as_secs(),
        "waiting for every node to stop serving the tenant"
    );
    tokio::time::sleep(drain).await;

    let source_cache = state.redis.for_region(source.region());
    let target_cache = state.redis.for_region(target.region());
    let separate_caches = !state.redis.same_backend(source.region(), target.region());
    let mut keys = vec![];
    let copied = async {
        report.rows = copy_everything(state, tenant, source, target, &tables).await?;
        report.audit_rows_verified = verify_copy(target, tenant.id).await?;
        if separate_caches {
            keys = source_cache
                .scan_match(&tenant_key_pattern(tenant.id))
                .await?;
            report.cache_keys = cache::copy_keys(&source_cache, &target_cache, &keys).await?;
        }
        Ok::<_, AppError>(())
    }
    .await;
    if let Err(err) = copied {
        tracing::error!(error = %err, "move failed; removing what reached the target");
        if let Err(e) = purge(target, tenant.id, &tables).await {
            tracing::error!(error = %e, "could not remove the partial copy; run the move again");
        }
        if separate_caches && let Err(e) = cache::delete_keys(&target_cache, &keys).await {
            tracing::error!(error = %e, "could not remove copied Valkey keys");
        }
        unlock_tenant(state, tenant).await?;
        return Err(err);
    }

    repos::tenants::set_placement(state.db.home(), tenant.id, target.region()).await?;
    state.db.forget(tenant.id);
    forget_registry_entry(state, tenant).await;
    tracing::info!(tenant = %tenant.slug, to = %target.name, "tenant now served from its new database");
    state.events.publish(Event::new(
        Some(tenant.id),
        Actor::System,
        EventKind::TenantMoved {
            tenant_id: tenant.id,
            from_region: source.region().map(str::to_string),
            to_region: target.region().map(str::to_string),
        },
    ));

    // The tenant is live in the target; the source only holds a stale copy.
    if separate_caches && let Err(err) = cache::delete_keys(&source_cache, &keys).await {
        tracing::error!(error = %err, "stale Valkey keys left in the source; run the move again");
    }
    match purge(source, tenant.id, &tables).await {
        Ok(()) => report.cleaned.push(source.name.to_string()),
        Err(err) => {
            tracing::error!(error = %err, "stale copy left in the source; run the move again")
        }
    }
    Ok(report)
}

/// Both databases must run the same migrations, so every column matches.
async fn check_schemas(source: &Database, target: &Database) -> AppResult<()> {
    for d in [source, target] {
        let pending = db::pending_migrations(&d.primary).await?;
        let unknown = db::unknown_migrations(&d.primary).await?;
        if pending > 0 || !unknown.is_empty() {
            return Err(AppError::Unavailable(format!(
                "database `{}` is not on this release's schema; run `ridm-api migrate` first",
                d.name
            )));
        }
    }
    Ok(())
}

async fn unlock_tenant(state: &AppState, tenant: &Tenant) -> AppResult<()> {
    repos::tenants::set_relocating(state.db.home(), tenant.id, false).await?;
    state.db.forget(tenant.id);
    forget_registry_entry(state, tenant).await;
    Ok(())
}

/// Evict the cached registry entry (the tenant's `relocating` and region)
/// on every node. Only the deployment-wide keys: the tenant's own keys are
/// unreachable while it moves, and move with it.
async fn forget_registry_entry(state: &AppState, tenant: &Tenant) {
    let keys: Vec<String> = tenant_cache_keys(tenant)
        .into_iter()
        .filter(|k| cache::key_tenant(k.as_bytes()).is_none())
        .collect();
    if let Err(err) = state.cache.invalidate(&keys).await {
        tracing::warn!(error = %err, "tenant cache not invalidated; it expires on its own");
    }
}

fn tenant_key_pattern(tenant_id: Uuid) -> String {
    format!("{}:t:{tenant_id}:*", cache::keys::PREFIX)
}

/// Remove stale copies of the tenant from every database it does not live in.
async fn clean_up(state: &AppState, tenant: &Tenant, home: &Database) -> AppResult<Vec<String>> {
    let tables = tenant_tables(&home.primary).await?;
    let mut cleaned = vec![];
    for d in state.db.all().iter().filter(|d| d.name != home.name) {
        if holds_any(d, tenant.id, &tables).await? {
            purge(d, tenant.id, &tables).await?;
            cleaned.push(d.name.to_string());
        }
    }
    Ok(cleaned)
}

async fn holds_any(d: &Database, tenant_id: Uuid, tables: &[Table]) -> AppResult<bool> {
    let mut tx = db::bypass_tx(&d.primary).await?;
    let mut found = false;
    if !d.is_home() {
        found = repos::tenants::find_by_id(&mut *tx, tenant_id)
            .await?
            .is_some();
    }
    for t in tables {
        if found {
            break;
        }
        let sql = format!(
            "SELECT EXISTS (SELECT 1 FROM {} WHERE tenant_id = $1)",
            ident(&t.name)
        );
        found = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(tenant_id)
            .fetch_one(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(found)
}

/// Every tenant-scoped table of the schema (it has a `tenant_id` column),
/// parents before children. Partitions are reached through their parent.
async fn tenant_tables(pool: &PgPool) -> AppResult<Vec<Table>> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') \
           AND NOT c.relispartition AND c.relname <> 'tenants' \
           AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid \
                       AND a.attname = 'tenant_id' AND NOT a.attisdropped) \
         ORDER BY c.relname",
    )
    .fetch_all(pool)
    .await?;
    let edges: Vec<(String, String)> = sqlx::query_as(
        "SELECT child.relname::text, parent.relname::text FROM pg_constraint k \
         JOIN pg_class child ON child.oid = k.conrelid \
         JOIN pg_class parent ON parent.oid = k.confrelid \
         WHERE k.contype = 'f' AND k.connamespace = current_schema()::regnamespace",
    )
    .fetch_all(pool)
    .await?;
    let order = dependency_order(&names, &edges)?;
    let mut tables = Vec::with_capacity(order.len());
    for name in order {
        let columns: Vec<String> = sqlx::query_scalar(
            "SELECT attname::text FROM pg_attribute \
             WHERE attrelid = (SELECT c.oid FROM pg_class c \
                               JOIN pg_namespace n ON n.oid = c.relnamespace \
                               WHERE n.nspname = current_schema() AND c.relname = $1) \
               AND attnum > 0 AND NOT attisdropped AND attgenerated = '' \
             ORDER BY attnum",
        )
        .bind(&name)
        .fetch_all(pool)
        .await?;
        let self_referencing = edges.iter().any(|(c, p)| *c == name && *p == name);
        tables.push(Table {
            name,
            columns,
            self_referencing,
        });
    }
    Ok(tables)
}

/// `names` ordered so every table comes after the tables it references
/// (Kahn's algorithm; ties by name, so the order is stable).
fn dependency_order(names: &[String], edges: &[(String, String)]) -> AppResult<Vec<String>> {
    let known: BTreeSet<&str> = names.iter().map(String::as_str).collect();
    let mut parents: BTreeMap<&str, BTreeSet<&str>> = names
        .iter()
        .map(|n| (n.as_str(), BTreeSet::new()))
        .collect();
    for (child, parent) in edges {
        if child != parent && known.contains(child.as_str()) && known.contains(parent.as_str()) {
            parents
                .entry(child.as_str())
                .or_default()
                .insert(parent.as_str());
        }
    }
    let mut order = Vec::with_capacity(names.len());
    while !parents.is_empty() {
        let ready: Vec<&str> = parents
            .iter()
            .filter(|(_, p)| p.is_empty())
            .map(|(n, _)| *n)
            .collect();
        if ready.is_empty() {
            let rest: Vec<&str> = parents.keys().copied().collect();
            return Err(AppError::Internal(format!(
                "foreign keys form a cycle among: {}",
                rest.join(", ")
            )));
        }
        for n in ready {
            parents.remove(n);
            for p in parents.values_mut() {
                p.remove(n);
            }
            order.push(n.to_string());
        }
    }
    Ok(order)
}

fn ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Copy the tenant's rows of every table from `source` to `target` in one
/// target transaction, reading one snapshot of the source; returns the rows
/// per table after checking the target holds exactly as many.
async fn copy_everything(
    state: &AppState,
    tenant: &Tenant,
    source: &Database,
    target: &Database,
    tables: &[Table],
) -> AppResult<BTreeMap<String, i64>> {
    let mut src = source.primary.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *src)
        .await?;
    sqlx::query("SELECT set_config('app.bypass_rls', 'on', true)")
        .execute(&mut *src)
        .await?;
    let mut dst = db::bypass_tx(&target.primary).await?;
    sqlx::query("SELECT set_config('app.skip_tenant_seed', 'on', true)")
        .execute(&mut *dst)
        .await?;
    // A stale copy from an attempt that died after committing: replace it.
    delete_rows(&mut dst, tenant.id, tables, !target.is_home()).await?;
    if !target.is_home() {
        let mut copy = repos::tenants::find_by_id(state.db.home(), tenant.id)
            .await?
            .ok_or(AppError::NotFound("tenant"))?;
        copy.data_region = target.region().map(str::to_string);
        repos::tenants::insert_copy(&mut *dst, &copy).await?;
    }
    let mut rows = BTreeMap::new();
    for t in tables {
        let n = copy_table(&mut src, &mut dst, tenant.id, t).await?;
        let expected = count(&mut src, tenant.id, t).await?;
        let landed = count(&mut dst, tenant.id, t).await?;
        if n != expected || landed != expected {
            return Err(AppError::Internal(format!(
                "{}: {expected} rows in the source, {n} copied, {landed} in the target",
                t.name
            )));
        }
        tracing::info!(table = %t.name, rows = n, "copied");
        rows.insert(t.name.clone(), n);
    }
    dst.commit().await?;
    src.commit().await?;
    Ok(rows)
}

async fn count(conn: &mut PgConnection, tenant_id: Uuid, t: &Table) -> AppResult<i64> {
    let sql = format!(
        "SELECT count(*) FROM {} WHERE tenant_id = $1",
        ident(&t.name)
    );
    Ok(sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(tenant_id)
        .fetch_one(conn)
        .await?)
}

/// One table, through a cursor on the source and `jsonb_populate_recordset`
/// on the target: every column round-trips through its JSON form.
async fn copy_table(
    src: &mut PgConnection,
    dst: &mut PgConnection,
    tenant_id: Uuid,
    t: &Table,
) -> AppResult<i64> {
    let columns = t
        .columns
        .iter()
        .map(|c| ident(c))
        .collect::<Vec<_>>()
        .join(", ");
    let table = ident(&t.name);
    // The tenant id is a UUID this process holds, never user input.
    let select = format!(
        "SELECT to_jsonb(x)::text FROM (SELECT {columns} FROM {table} \
         WHERE tenant_id = '{tenant_id}'::uuid) x"
    );
    let insert = format!(
        "INSERT INTO {table} ({columns}) OVERRIDING SYSTEM VALUE \
         SELECT {columns} FROM jsonb_populate_recordset(NULL::{table}, $1::jsonb)"
    );
    if t.self_referencing {
        let rows: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(select))
            .fetch_all(&mut *src)
            .await?;
        insert_batch(dst, &insert, &rows).await?;
        return Ok(rows.len() as i64);
    }
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DECLARE ridm_move NO SCROLL CURSOR FOR {select}"
    )))
    .execute(&mut *src)
    .await?;
    let mut total = 0;
    loop {
        let rows: Vec<String> =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("FETCH {BATCH} FROM ridm_move")))
                .fetch_all(&mut *src)
                .await?;
        insert_batch(dst, &insert, &rows).await?;
        total += rows.len() as i64;
        if (rows.len() as i64) < BATCH {
            break;
        }
    }
    sqlx::query("CLOSE ridm_move").execute(&mut *src).await?;
    Ok(total)
}

async fn insert_batch(dst: &mut PgConnection, insert: &str, rows: &[String]) -> AppResult<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let json = format!("[{}]", rows.join(","));
    sqlx::query(sqlx::AssertSqlSafe(insert.to_string()))
        .bind(json)
        .execute(dst)
        .await?;
    Ok(())
}

/// The copied audit chain must verify where it now is; returns its rows.
async fn verify_copy(target: &Database, tenant_id: Uuid) -> AppResult<u64> {
    match audit::verify_in(&target.primary, tenant_id).await? {
        Ok(n) => Ok(n),
        Err((seq, reason)) => Err(AppError::Internal(format!(
            "the copied audit chain breaks at {seq}: {reason}"
        ))),
    }
}

/// Delete everything of the tenant from `d`, children first; its copy of
/// the `tenants` row too, unless `d` is the home database (the registry).
async fn purge(d: &Database, tenant_id: Uuid, tables: &[Table]) -> AppResult<()> {
    let mut tx = db::bypass_tx(&d.primary).await?;
    delete_rows(&mut tx, tenant_id, tables, !d.is_home()).await?;
    tx.commit().await?;
    Ok(())
}

async fn delete_rows(
    conn: &mut PgConnection,
    tenant_id: Uuid,
    tables: &[Table],
    with_tenant_row: bool,
) -> AppResult<()> {
    for t in tables.iter().rev() {
        let sql = format!("DELETE FROM {} WHERE tenant_id = $1", ident(&t.name));
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(tenant_id)
            .execute(&mut *conn)
            .await?;
    }
    if with_tenant_row {
        repos::tenants::delete(&mut *conn, tenant_id).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parents_come_before_children_and_self_references_are_ignored() {
        let names = s(&["group_members", "groups", "users", "organizations"]);
        let edges = vec![
            ("group_members".into(), "groups".into()),
            ("group_members".into(), "users".into()),
            ("groups".into(), "groups".into()),
            ("users".into(), "organizations".into()),
            ("users".into(), "tenants".into()),
        ];
        let order = dependency_order(&names, &edges).unwrap();
        let at = |n: &str| order.iter().position(|x| x == n).unwrap();
        assert!(at("organizations") < at("users"));
        assert!(at("users") < at("group_members"));
        assert!(at("groups") < at("group_members"));
        assert_eq!(order.len(), 4);
    }

    #[test]
    fn a_cycle_is_refused() {
        let names = s(&["a", "b"]);
        let edges = vec![("a".into(), "b".into()), ("b".into(), "a".into())];
        assert!(dependency_order(&names, &edges).is_err());
    }

    #[test]
    fn identifiers_are_quoted() {
        assert_eq!(ident("users"), "\"users\"");
        assert_eq!(ident("we\"ird"), "\"we\"\"ird\"");
    }
}
