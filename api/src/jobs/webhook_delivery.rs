//! Periodic delivery of retrying (and any missed) webhook deliveries.
//!
//! New deliveries are sent by the dispatcher as they are queued; this job
//! catches retries after their backoff, rows a crashed node left in
//! `sending`, and anything a node lost. It visits only tenants that have a
//! delivery due, found with one cross-tenant query, so its cost follows the
//! backlog rather than the number of tenants.

use std::time::Duration;

use crate::db;
use crate::error::AppResult;
use crate::jobs::leader;
use crate::repos;
use crate::services::webhooks;
use crate::state::AppState;

pub const JOB_NAME: &str = "webhook_delivery";
/// Deliveries taken per tenant per run.
const BATCH: i64 = 100;

pub async fn run_once(state: &AppState) -> AppResult<Option<(usize, usize)>> {
    let Some(lock) = leader::try_acquire(&state.redis, JOB_NAME, Duration::from_secs(120)).await?
    else {
        return Ok(None);
    };
    let mut totals = (0, 0);
    let mut due = vec![];
    let mut backlog = 0;
    for database in state.db.all() {
        let mut tx = db::bypass_tx(&database.primary).await?;
        // Stale `sending` rows only become due once requeued, so they are found
        // by their old `next_attempt_at`, which `deliver_due` resets.
        due.extend(repos::webhooks::tenants_with_due(&mut *tx).await?);
        backlog += repos::webhooks::count_pending(&mut *tx).await?;
        tx.commit().await?;
    }
    metrics::gauge!("ridm_webhook_deliveries_pending").set(backlog as f64);
    let relocating = state.db.relocating().await?;
    for tenant_id in due.into_iter().filter(|t| !relocating.contains(t)) {
        match webhooks::deliver_due(state, tenant_id, BATCH).await {
            Ok((d, f)) => {
                totals.0 += d;
                totals.1 += f;
            }
            Err(err) => {
                tracing::error!(tenant = %tenant_id, error = %err, "webhook delivery failed")
            }
        }
    }
    lock.release().await?;
    Ok(Some(totals))
}
