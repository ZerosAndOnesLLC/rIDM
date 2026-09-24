//! Periodic delivery of queued and retrying messages. Each message is sent
//! as it is queued; this job catches retries after their backoff, messages a
//! crashed node left in `sending`, and anything a node lost. It visits only
//! the tenants that have a message due, found with one cross-tenant query,
//! so its cost follows the backlog rather than the number of tenants;
//! several tenants are served at once, so one tenant's unreachable mail
//! server does not hold up the rest.

use std::time::{Duration, Instant};

use futures::StreamExt as _;

use crate::db;
use crate::error::AppResult;
use crate::jobs::leader;
use crate::messaging;
use crate::repos;
use crate::state::AppState;

pub const JOB_NAME: &str = "message_delivery";
/// Messages taken per tenant per run.
const BATCH: i64 = 100;
/// Tenants served at the same time.
const TENANTS_AT_ONCE: usize = 4;
/// The lock's lifetime; it is renewed while the pass runs.
const LOCK_TTL: Duration = Duration::from_secs(120);
/// No tenant is started after this much of a pass: the next pass, 30 s on,
/// takes the rest.
const PASS_BUDGET: Duration = Duration::from_secs(90);
/// A message `sending` this long belongs to a node that stopped mid-send.
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
            repos::messages::requeue_stale_all(&mut *tx, chrono::Utc::now() - STALE_AFTER).await?;
        if requeued > 0 {
            tracing::warn!(requeued, region = %database.name, "messages stuck in sending requeued");
        }
        due.extend(repos::messages::tenants_with_due(&mut *tx).await?);
        backlog += repos::messages::count_queued(&mut *tx).await?;
        tx.commit().await?;
    }
    metrics::gauge!("ridm_messages_queued").set(backlog as f64);
    let relocating = state.db.relocating().await?;
    let pass = futures::stream::iter(due.into_iter().filter(|t| !relocating.contains(t)))
        .map(|tenant_id| async move {
            if started.elapsed() > PASS_BUDGET {
                return None;
            }
            let result = messaging::deliver_due(state, tenant_id, BATCH).await;
            match result {
                Ok(counts) => Some(counts),
                Err(err) => {
                    tracing::error!(tenant = %tenant_id, error = %err, "message delivery failed");
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
