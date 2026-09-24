//! Periodic delivery of retrying (and any missed) webhook deliveries.
//!
//! New deliveries are sent by the dispatcher as they are queued; this job
//! catches retries after their backoff, rows a crashed node left in
//! `sending`, and anything a node lost. It visits only tenants that have a
//! delivery due, found with one cross-tenant query, so its cost follows the
//! backlog rather than the number of tenants; several tenants are served at
//! once, so one tenant's slow endpoint does not hold up the rest.

use std::time::{Duration, Instant};

use futures::StreamExt as _;

use crate::db;
use crate::error::AppResult;
use crate::jobs::leader;
use crate::repos;
use crate::services::webhooks;
use crate::state::AppState;

pub const JOB_NAME: &str = "webhook_delivery";
/// Deliveries taken per tenant per run.
const BATCH: i64 = 100;
/// Tenants served at the same time.
const TENANTS_AT_ONCE: usize = 4;
/// The lock's lifetime; it is renewed while the pass runs.
const LOCK_TTL: Duration = Duration::from_secs(120);
/// No tenant is started after this much of a pass: the next pass, 30 s on,
/// takes the rest.
const PASS_BUDGET: Duration = Duration::from_secs(90);
/// A delivery `sending` this long belongs to a node that stopped mid-attempt.
const STALE_AFTER: chrono::Duration = chrono::Duration::minutes(10);

pub async fn run_once(state: &AppState) -> AppResult<Option<(usize, usize)>> {
    let Some(lock) = leader::try_acquire(&state.redis, JOB_NAME, LOCK_TTL).await? else {
        return Ok(None);
    };
    let started = Instant::now();
    let mut due = vec![];
    let mut backlog = 0;
    for database in state.db.all() {
        let mut tx = db::bypass_tx(&database.primary).await?;
        let requeued =
            repos::webhooks::requeue_stale_all(&mut *tx, chrono::Utc::now() - STALE_AFTER).await?;
        if requeued > 0 {
            tracing::warn!(requeued, region = %database.name, "webhook deliveries stuck in sending requeued");
        }
        due.extend(repos::webhooks::tenants_with_due(&mut *tx).await?);
        backlog += repos::webhooks::count_pending(&mut *tx).await?;
        tx.commit().await?;
    }
    metrics::gauge!("ridm_webhook_deliveries_pending").set(backlog as f64);
    let relocating = state.db.relocating().await?;
    let pass = futures::stream::iter(due.into_iter().filter(|t| !relocating.contains(t)))
        .map(|tenant_id| async move {
            if started.elapsed() > PASS_BUDGET {
                return None;
            }
            let result = webhooks::deliver_due(state, tenant_id, BATCH).await;
            match result {
                Ok(counts) => Some(counts),
                Err(err) => {
                    tracing::error!(tenant = %tenant_id, error = %err, "webhook delivery failed");
                    None
                }
            }
        })
        .buffer_unordered(TENANTS_AT_ONCE)
        .collect::<Vec<Option<(usize, usize)>>>();
    let outcomes = lock.hold_while(LOCK_TTL, pass).await;
    let totals = outcomes
        .into_iter()
        .flatten()
        .fold((0, 0), |(d, f), (dd, ff)| (d + dd, f + ff));
    lock.release().await?;
    Ok(Some(totals))
}
