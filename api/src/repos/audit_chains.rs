//! Bookkeeping per audit chain: its head, how far verification has walked
//! it, and how far the export sink has shipped it. Every query runs with the
//! RLS bypass: the writer, the verification job and the sink serve every
//! tenant and the global chain.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

/// A chain's newest row: its sequence number and hash, as the writer last
/// recorded them (read under the chain's lock).
pub async fn head<'e>(
    exec: impl PgExecutor<'e>,
    chain: Uuid,
) -> Result<Option<(i64, Vec<u8>)>, sqlx::Error> {
    sqlx::query_as("SELECT head_seq, head_hash FROM audit_chains WHERE chain_id = $1")
        .bind(chain)
        .fetch_optional(exec)
        .await
}

/// Record a chain's newest row. Never moves the head backwards, so a row
/// written by an older node during a rolling upgrade cannot confuse it.
/// `appended_from` is when the first row of this append was written: the
/// chain's oldest row when it had none before (`new_chain`, or an emptied
/// chain). A chain first recorded here with older rows gets no oldest time
/// (retention looks it up).
pub async fn advance_head<'e>(
    exec: impl PgExecutor<'e>,
    chain: Uuid,
    tenant_id: Option<Uuid>,
    seq: i64,
    hash: &[u8],
    appended_from: DateTime<Utc>,
    new_chain: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_chains (chain_id, tenant_id, head_seq, head_hash, oldest_at) \
         VALUES ($1, $2, $3, $4, CASE WHEN $6 THEN $5 END) \
         ON CONFLICT (chain_id) DO UPDATE SET head_seq = EXCLUDED.head_seq, head_hash = EXCLUDED.head_hash, \
             oldest_at = CASE WHEN audit_chains.oldest_at = 'infinity' THEN $5 \
                              ELSE audit_chains.oldest_at END \
         WHERE audit_chains.head_seq < EXCLUDED.head_seq",
    )
    .bind(chain)
    .bind(tenant_id)
    .bind(seq)
    .bind(hash)
    .bind(appended_from)
    .bind(new_chain)
    .execute(exec)
    .await?;
    Ok(())
}

/// Where a chain's oldest row stands, for retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Oldest {
    /// Not looked at yet.
    Unknown,
    /// Every row is gone.
    Empty,
    At(DateTime<Utc>),
}

/// Every chain in this database with where its oldest row stands.
pub async fn oldest_all<'e>(exec: impl PgExecutor<'e>) -> Result<Vec<(Uuid, Oldest)>, sqlx::Error> {
    let rows: Vec<(Uuid, bool, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT chain_id, oldest_at = 'infinity' IS TRUE, NULLIF(oldest_at, 'infinity') \
         FROM audit_chains",
    )
    .fetch_all(exec)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(chain, empty, at)| {
            let oldest = match (empty, at) {
                (true, _) => Oldest::Empty,
                (false, Some(at)) => Oldest::At(at),
                (false, None) => Oldest::Unknown,
            };
            (chain, oldest)
        })
        .collect())
}

/// Record where a chain's oldest row now stands (`None`: every row is gone).
pub async fn set_oldest<'e>(
    exec: impl PgExecutor<'e>,
    chain: Uuid,
    oldest: Option<DateTime<Utc>>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE audit_chains SET oldest_at = COALESCE($2, 'infinity'::timestamptz) WHERE chain_id = $1",
    )
    .bind(chain)
    .bind(oldest)
    .execute(exec)
    .await?;
    Ok(())
}

/// A chain with rows the verification job has not walked yet.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Unverified {
    pub chain_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub verified_seq: Option<i64>,
    pub verified_hash: Option<Vec<u8>>,
    pub broken_at_seq: Option<i64>,
}

/// Chains whose head is past their verified checkpoint, or that were found
/// broken (they are checked again every pass until repaired).
pub async fn unverified<'e>(
    exec: impl PgExecutor<'e>,
    after: Option<Uuid>,
    limit: i64,
) -> Result<Vec<Unverified>, sqlx::Error> {
    sqlx::query_as(
        "SELECT chain_id, tenant_id, verified_seq, verified_hash, broken_at_seq FROM audit_chains \
         WHERE (verified_seq IS DISTINCT FROM head_seq OR broken_at_seq IS NOT NULL) \
           AND ($1::uuid IS NULL OR chain_id > $1) \
         ORDER BY chain_id LIMIT $2",
    )
    .bind(after)
    .bind(limit)
    .fetch_all(exec)
    .await
}

/// One chain's verification state, whether or not it has anything new.
pub async fn verification_of<'e>(
    exec: impl PgExecutor<'e>,
    chain: Uuid,
) -> Result<Option<Unverified>, sqlx::Error> {
    sqlx::query_as(
        "SELECT chain_id, tenant_id, verified_seq, verified_hash, broken_at_seq FROM audit_chains \
         WHERE chain_id = $1",
    )
    .bind(chain)
    .fetch_optional(exec)
    .await
}

pub async fn set_verified<'e>(
    exec: impl PgExecutor<'e>,
    chain: Uuid,
    seq: i64,
    hash: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE audit_chains SET verified_seq = $2, verified_hash = $3, verified_at = now(), \
         broken_at_seq = NULL, broken_reason = NULL, broken_at = NULL WHERE chain_id = $1",
    )
    .bind(chain)
    .bind(seq)
    .bind(hash)
    .execute(exec)
    .await?;
    Ok(())
}

/// Record a break. Returns whether it is new (the chain was not already
/// known broken there), which is when it is announced.
pub async fn set_broken<'e>(
    exec: impl PgExecutor<'e>,
    chain: Uuid,
    seq: i64,
    reason: &str,
) -> Result<bool, sqlx::Error> {
    let changed = sqlx::query(
        "UPDATE audit_chains SET broken_at_seq = $2, broken_reason = $3, broken_at = now() \
         WHERE chain_id = $1 AND broken_at_seq IS DISTINCT FROM $2",
    )
    .bind(chain)
    .bind(seq)
    .bind(reason)
    .execute(exec)
    .await?
    .rows_affected();
    Ok(changed > 0)
}

/// How many chains are currently known broken.
pub async fn broken_count<'e>(exec: impl PgExecutor<'e>) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM audit_chains WHERE broken_at_seq IS NOT NULL")
        .fetch_one(exec)
        .await
}

/// A chain's head and verification state, for the verify endpoint.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChainState {
    pub head_seq: i64,
    pub head_hash: Vec<u8>,
    pub verified_seq: Option<i64>,
    pub verified_at: Option<DateTime<Utc>>,
    pub broken_at_seq: Option<i64>,
    pub broken_reason: Option<String>,
    pub sink_seq: Option<i64>,
}

pub async fn state<'e>(
    exec: impl PgExecutor<'e>,
    chain: Uuid,
) -> Result<Option<ChainState>, sqlx::Error> {
    sqlx::query_as(
        "SELECT head_seq, head_hash, verified_seq, verified_at, broken_at_seq, broken_reason, sink_seq \
         FROM audit_chains WHERE chain_id = $1",
    )
    .bind(chain)
    .fetch_optional(exec)
    .await
}

// --- export sink --------------------------------------------------------------

/// The sink the cursors were kept for, if any.
pub async fn sink_target<'e>(exec: impl PgExecutor<'e>) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT target FROM audit_sink_state WHERE id = 1")
        .fetch_optional(exec)
        .await
}

/// Start `target` at the current heads: history before it was configured is
/// not replayed. Chains created afterwards start at their first row.
pub async fn start_sink<'e>(exec: impl PgExecutor<'e>, target: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "WITH marker AS ( \
             INSERT INTO audit_sink_state (id, target, started_at) VALUES (1, $1, now()) \
             ON CONFLICT (id) DO UPDATE SET target = EXCLUDED.target, started_at = now() \
         ) \
         UPDATE audit_chains SET sink_seq = head_seq, sink_at = now()",
    )
    .bind(target)
    .execute(exec)
    .await?;
    Ok(())
}

/// A chain with rows the sink has not shipped.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Pending {
    pub chain_id: Uuid,
    pub sink_seq: i64,
}

pub async fn pending<'e>(
    exec: impl PgExecutor<'e>,
    limit: i64,
) -> Result<Vec<Pending>, sqlx::Error> {
    sqlx::query_as(
        "SELECT chain_id, COALESCE(sink_seq, 0) AS sink_seq FROM audit_chains \
         WHERE head_seq > COALESCE(sink_seq, 0) ORDER BY sink_at NULLS FIRST, chain_id LIMIT $1",
    )
    .bind(limit)
    .fetch_all(exec)
    .await
}

/// The sink shipped the chain through `seq`.
pub async fn advance_sink<'e>(
    exec: impl PgExecutor<'e>,
    chain: Uuid,
    seq: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE audit_chains SET sink_seq = GREATEST(COALESCE(sink_seq, 0), $2), sink_at = now() \
         WHERE chain_id = $1",
    )
    .bind(chain)
    .bind(seq)
    .execute(exec)
    .await?;
    Ok(())
}

/// Rows recorded but not yet shipped, over every chain.
pub async fn sink_lag<'e>(exec: impl PgExecutor<'e>) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COALESCE(sum(head_seq - COALESCE(sink_seq, 0)), 0)::bigint FROM audit_chains \
         WHERE head_seq > COALESCE(sink_seq, 0)",
    )
    .fetch_one(exec)
    .await
}
