//! Audit rows. Reads run inside a tenant transaction; the writer and the
//! retention job use the bypass (they serve every tenant and the global chain).

use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{AuditEvent, AuditFilter};
use crate::util::cursor::Cursor;

const COLUMNS: &str = "id, tenant_id, seq, occurred_at, recorded_at, name, actor_type, actor_id, \
    subject_id, ip, user_agent, payload, prev_hash, hash";

/// Nil uuid stands for the global chain.
pub fn chain_id(tenant_id: Option<Uuid>) -> Uuid {
    tenant_id.unwrap_or(Uuid::nil())
}

/// Serialize writers of one chain for the transaction.
pub async fn lock_chain<'e>(exec: impl PgExecutor<'e>, chain: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(chain.to_string())
        .execute(exec)
        .await?;
    Ok(())
}

pub async fn chain_head<'e>(
    exec: impl PgExecutor<'e>,
    chain: Uuid,
) -> Result<Option<(i64, Vec<u8>)>, sqlx::Error> {
    sqlx::query_as::<_, (i64, Vec<u8>)>(
        "SELECT seq, hash FROM audit_events WHERE chain_id = $1 ORDER BY seq DESC LIMIT 1",
    )
    .bind(chain)
    .fetch_optional(exec)
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn insert<'e>(exec: impl PgExecutor<'e>, row: &AuditEvent) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_events (id, tenant_id, chain_id, seq, occurred_at, recorded_at, name, \
         actor_type, actor_id, subject_id, ip, user_agent, payload, prev_hash, hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind(row.id)
    .bind(row.tenant_id)
    .bind(chain_id(row.tenant_id))
    .bind(row.seq)
    .bind(row.occurred_at)
    .bind(row.recorded_at)
    .bind(&row.name)
    .bind(&row.actor_type)
    .bind(row.actor_id)
    .bind(row.subject_id)
    .bind(&row.ip)
    .bind(&row.user_agent)
    .bind(&row.payload)
    .bind(&row.prev_hash)
    .bind(&row.hash)
    .execute(exec)
    .await?;
    Ok(())
}

fn push_filters(qb: &mut QueryBuilder<sqlx::Postgres>, f: &AuditFilter) {
    if let Some(from) = f.from {
        qb.push(" AND occurred_at >= ").push_bind(from);
    }
    if let Some(to) = f.to {
        qb.push(" AND occurred_at < ").push_bind(to);
    }
    if let Some(name) = f.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
        if let Some(prefix) = name
            .strip_suffix('*')
            .or_else(|| name.ends_with('.').then_some(name))
        {
            let pattern = format!(
                "{}%",
                prefix
                    .replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_")
            );
            qb.push(" AND name LIKE ").push_bind(pattern);
        } else {
            qb.push(" AND name = ").push_bind(name.to_string());
        }
    }
    if let Some(a) = f.actor_id {
        qb.push(" AND actor_id = ").push_bind(a);
    }
    if let Some(s) = f.subject_id {
        qb.push(" AND subject_id = ").push_bind(s);
    }
    if let Some(u) = f.user_id {
        qb.push(" AND (actor_id = ")
            .push_bind(u)
            .push(" OR subject_id = ")
            .push_bind(u)
            .push(")");
    }
}

/// Newest first, keyset-paginated on `(occurred_at, id)` descending.
/// `tenant_id = None` lists the global chain (needs the bypass).
pub async fn list<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Option<Uuid>,
    filter: &AuditFilter,
    before: Option<Cursor>,
    limit: i64,
) -> Result<Vec<AuditEvent>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS).push(" FROM audit_events WHERE ");
    match tenant_id {
        Some(t) => {
            qb.push("tenant_id = ").push_bind(t);
        }
        None => {
            qb.push("tenant_id IS NULL");
        }
    }
    push_filters(&mut qb, filter);
    if let Some(c) = before {
        qb.push(" AND (occurred_at, id) < (")
            .push_bind(c.created_at)
            .push(", ")
            .push_bind(c.id)
            .push(")");
    }
    qb.push(" ORDER BY occurred_at DESC, id DESC LIMIT ")
        .push_bind(limit + 1);
    qb.build_query_as::<AuditEvent>().fetch_all(exec).await
}

/// Oldest first by chain position, for exports and chain verification.
pub async fn chain_page<'e>(
    exec: impl PgExecutor<'e>,
    chain: Uuid,
    filter: &AuditFilter,
    after_seq: Option<i64>,
    limit: i64,
) -> Result<Vec<AuditEvent>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM audit_events WHERE chain_id = ")
        .push_bind(chain);
    push_filters(&mut qb, filter);
    if let Some(s) = after_seq {
        qb.push(" AND seq > ").push_bind(s);
    }
    qb.push(" ORDER BY seq LIMIT ").push_bind(limit);
    qb.build_query_as::<AuditEvent>().fetch_all(exec).await
}

/// The chain position of the newest row older than `cutoff`: retention
/// removes a prefix of the chain so what remains stays contiguous.
pub async fn expired_head<'e>(
    exec: impl PgExecutor<'e>,
    chain: Uuid,
    cutoff: DateTime<Utc>,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar("SELECT max(seq) FROM audit_events WHERE chain_id = $1 AND occurred_at < $2")
        .bind(chain)
        .bind(cutoff)
        .fetch_one(exec)
        .await
}

/// Delete up to `batch` rows of a chain at or below `up_to_seq`.
pub async fn purge_prefix<'e>(
    exec: impl PgExecutor<'e>,
    chain: Uuid,
    up_to_seq: i64,
    batch: i64,
) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        "DELETE FROM audit_events WHERE (id, occurred_at) IN ( \
            SELECT id, occurred_at FROM audit_events \
            WHERE chain_id = $1 AND seq <= $2 ORDER BY seq LIMIT $3)",
    )
    .bind(chain)
    .bind(up_to_seq)
    .bind(batch)
    .execute(exec)
    .await?;
    Ok(res.rows_affected())
}

pub async fn ensure_partitions<'e>(
    exec: impl PgExecutor<'e>,
    months_ahead: i32,
) -> Result<i32, sqlx::Error> {
    sqlx::query_scalar("SELECT audit_ensure_partitions($1)")
        .bind(months_ahead)
        .fetch_one(exec)
        .await
}
