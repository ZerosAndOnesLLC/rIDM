//! The audit export sink's worker: ships rows from the database to
//! `AUDIT_SINK_URL` ([`crate::services::audit_sink`]) and remembers, per
//! chain, how far it got (`audit_chains.sink_seq`).
//!
//! One node ships at a time (a leader lock); the others wait their turn. A
//! failed delivery leaves the cursor where it was and backs off, doubling up
//! to a minute, so a receiver that is down for an hour gets the whole hour
//! when it comes back — nothing is dropped. A newly configured destination
//! starts at the chains' current heads rather than replaying history.

use std::time::Duration;

use sqlx::PgPool;

use crate::db;
use crate::error::AppResult;
use crate::jobs::leader;
use crate::models::AuditFilter;
use crate::repos;
use crate::services::audit_sink::{AuditSink, BATCH};
use crate::state::AppState;

pub const JOB_NAME: &str = "audit_sink";
/// Chains looked at per pass.
const CHAINS_PER_PASS: i64 = 50;
const LOCK_TTL: Duration = Duration::from_secs(30);
/// How long one node ships before giving others a chance at the lock.
const TURN: Duration = Duration::from_secs(20);
const IDLE: Duration = Duration::from_secs(1);
/// How long the wait grows to while there is nothing to ship.
const MAX_IDLE: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// What one pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Pass {
    pub shipped: usize,
    /// A delivery failed; the pass stopped there.
    pub failed: bool,
}

/// Run the worker for as long as the process does. `None` without a sink.
pub fn spawn(state: AppState) -> Option<tokio::task::JoinHandle<()>> {
    state.audit_sink.clone()?;
    Some(tokio::spawn(async move {
        let mut backoff = IDLE;
        loop {
            match turn(&state).await {
                Ok(Turn::Failed) => backoff = (backoff * 2).clamp(IDLE * 2, MAX_BACKOFF),
                Ok(Turn::Shipped) => backoff = IDLE,
                // Nothing to ship (or another node's turn): wait a little
                // longer each time, up to MAX_IDLE.
                Ok(Turn::Idle) => backoff = (backoff + IDLE).min(MAX_IDLE),
                Err(err) => {
                    tracing::error!(error = %err, "audit sink pass failed");
                    backoff = (backoff * 2).clamp(IDLE * 2, MAX_BACKOFF);
                }
            }
            tokio::time::sleep(backoff).await;
        }
    }))
}

/// How a turn ended.
enum Turn {
    /// A delivery failed.
    Failed,
    /// Rows went out.
    Shipped,
    /// Nothing was waiting, or another node holds the lock.
    Idle,
}

/// One turn at the lock: ship until caught up, a delivery fails, or the
/// turn is over.
async fn turn(state: &AppState) -> AppResult<Turn> {
    let Some(lock) = leader::try_acquire(&state.redis, JOB_NAME, LOCK_TTL).await? else {
        return Ok(Turn::Idle);
    };
    let started = tokio::time::Instant::now();
    let outcome = async {
        let mut shipped = 0;
        loop {
            let pass = run_pass(state).await?;
            if pass.failed {
                return Ok(Turn::Failed);
            }
            shipped += pass.shipped;
            if pass.shipped == 0 || started.elapsed() > TURN {
                return Ok(if shipped == 0 {
                    Turn::Idle
                } else {
                    Turn::Shipped
                });
            }
        }
    }
    .await;
    lock.release().await?;
    outcome
}

/// Ship one batch of every chain that has rows waiting (up to
/// [`CHAINS_PER_PASS`] chains per database: each region keeps its tenants'
/// chains and its own cursors). Callers hold the leader lock.
pub async fn run_pass(state: &AppState) -> AppResult<Pass> {
    let Some(sink) = state.audit_sink.as_ref() else {
        return Ok(Pass::default());
    };
    let mut pass = Pass::default();
    let mut lag = 0;
    for database in state.db.all() {
        let (shipped, failed, behind) = database_pass(&database.primary, sink).await?;
        pass.shipped += shipped;
        lag += behind;
        if failed {
            pass.failed = true;
            break;
        }
    }
    metrics::gauge!("ridm_audit_sink_lag_rows").set(lag as f64);
    Ok(pass)
}

/// [`run_pass`] over one database: rows shipped, whether a delivery failed,
/// and the rows still waiting.
async fn database_pass(pool: &PgPool, sink: &AuditSink) -> AppResult<(usize, bool, i64)> {
    // One transaction when there is nothing to do, which is most passes.
    let mut tx = db::bypass_tx(pool).await?;
    ensure_started(&mut tx, sink).await?;
    let pending = repos::audit_chains::pending(&mut *tx, CHAINS_PER_PASS).await?;
    tx.commit().await?;
    if pending.is_empty() {
        return Ok((0, false, 0));
    }
    let mut shipped = 0;
    let mut failed = false;
    for chain in pending {
        let mut tx = db::bypass_tx(pool).await?;
        let rows = repos::audit::chain_page(
            &mut *tx,
            chain.chain_id,
            &AuditFilter::default(),
            Some(chain.sink_seq),
            BATCH as i64,
        )
        .await?;
        tx.commit().await?;
        let Some(last) = rows.last().map(|r| r.seq) else {
            // Retention purged what was waiting; move past it.
            let mut tx = db::bypass_tx(pool).await?;
            let head = repos::audit_chains::state(&mut *tx, chain.chain_id)
                .await?
                .map(|s| s.head_seq);
            if let Some(head) = head {
                repos::audit_chains::advance_sink(&mut *tx, chain.chain_id, head).await?;
            }
            tx.commit().await?;
            continue;
        };
        if let Err(err) = sink.deliver(&rows).await {
            metrics::counter!("ridm_audit_sink_failures_total").increment(1);
            tracing::warn!(error = %err, chain = %chain.chain_id, rows = rows.len(), "audit sink delivery failed; will retry");
            failed = true;
            break;
        }
        let mut tx = db::bypass_tx(pool).await?;
        repos::audit_chains::advance_sink(&mut *tx, chain.chain_id, last).await?;
        tx.commit().await?;
        metrics::counter!("ridm_audit_sink_rows_total").increment(rows.len() as u64);
        shipped += rows.len();
    }
    let mut tx = db::bypass_tx(pool).await?;
    let lag = repos::audit_chains::sink_lag(&mut *tx).await?;
    tx.commit().await?;
    Ok((shipped, failed, lag))
}

/// A destination seen for the first time starts at the current heads.
async fn ensure_started(tx: &mut db::Tx, sink: &AuditSink) -> AppResult<()> {
    if repos::audit_chains::sink_target(&mut **tx)
        .await?
        .as_deref()
        != Some(sink.id())
    {
        repos::audit_chains::start_sink(&mut **tx, sink.id()).await?;
        tracing::info!(
            sink = sink.id(),
            "audit sink starts at the current chain heads"
        );
    }
    Ok(())
}
