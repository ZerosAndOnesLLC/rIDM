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
    let mut tx = db::bypass_tx(&state.db).await?;
    // Stale `sending` rows only become due once requeued, so they are found
    // by their old `next_attempt_at`, which `deliver_due` resets.
    let due = repos::webhooks::tenants_with_due(&mut *tx).await?;
    tx.commit().await?;
    for tenant_id in due {
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
