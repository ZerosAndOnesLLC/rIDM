//! Periodic delivery of queued and retrying messages. It visits only the
//! tenants that have a message due, found with one cross-tenant query, so
//! its cost follows the backlog rather than the number of tenants.

use std::time::Duration;

use crate::db;
use crate::error::AppResult;
use crate::jobs::leader;
use crate::messaging;
use crate::repos;
use crate::state::AppState;

pub const JOB_NAME: &str = "message_delivery";
const BATCH: i64 = 100;

pub async fn run_once(state: &AppState) -> AppResult<Option<(usize, usize)>> {
    let Some(lock) = leader::try_acquire(&state.redis, JOB_NAME, Duration::from_secs(120)).await?
    else {
        return Ok(None);
    };
    let mut totals = (0, 0);
    let mut tx = db::bypass_tx(&state.db).await?;
    let due = repos::messages::tenants_with_due(&mut *tx).await?;
    let backlog = repos::messages::count_queued(&mut *tx).await?;
    tx.commit().await?;
    metrics::gauge!("ridm_messages_queued").set(backlog as f64);
    for tenant_id in due {
        match messaging::deliver_due(state, tenant_id, BATCH).await {
            Ok((s, f)) => {
                totals.0 += s;
                totals.1 += f;
            }
            Err(err) => {
                tracing::error!(tenant = %tenant_id, error = %err, "message delivery failed")
            }
        }
    }
    lock.release().await?;
    Ok(Some(totals))
}
