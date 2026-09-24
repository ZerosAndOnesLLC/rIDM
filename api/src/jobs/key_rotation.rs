//! Periodic signing-key housekeeping across all tenants.

use std::time::Duration;

use crate::db;
use crate::error::AppResult;
use crate::jobs::leader;
use crate::repos;
use crate::services::{keys, tenants};
use crate::state::AppState;

pub const JOB_NAME: &str = "key_rotation";

/// One pass over the tenants whose keys need housekeeping. Returns the
/// number of tenants processed.
/// Safe to call from any node: a Redis lock ensures a single runner.
pub async fn run_once(state: &AppState) -> AppResult<Option<usize>> {
    let Some(lock) = leader::try_acquire(&state.redis, JOB_NAME, Duration::from_secs(600)).await?
    else {
        return Ok(None);
    };
    let result = process_all(state).await;
    lock.release().await?;
    result.map(Some)
}

/// Every database's tenants whose keys need something (a retiring key
/// past its expiry, an active one past the rotation interval), found in one
/// read per database; the others are not visited.
async fn process_all(state: &AppState) -> AppResult<usize> {
    let mut processed = 0;
    let now = chrono::Utc::now();
    for database in state.db.all() {
        let states = {
            let mut tx = db::bypass_tx(&database.primary).await?;
            let rows = repos::signing_keys::housekeeping(&mut *tx).await?;
            tx.commit().await?;
            rows
        };
        for key_state in states {
            // Settings and placement come from the registry (home database).
            let tenant = match tenants::get_cached(state, key_state.tenant_id).await {
                Ok(Some(tenant)) => tenant,
                Ok(None) => continue,
                Err(err) => {
                    tracing::error!(tenant = %key_state.tenant_id, error = %err, "key housekeeping skipped a tenant");
                    continue;
                }
            };
            // A tenant being moved is unreachable until the move is over.
            if !tenant.is_active() || tenant.relocating {
                continue;
            }
            let policy = &tenant.settings.keys;
            let rotation_due = policy.rotation_interval_days > 0
                && key_state.oldest_active.is_some_and(|since| {
                    since + chrono::Duration::days(i64::from(policy.rotation_interval_days)) <= now
                });
            if !key_state.retiring_expired && !rotation_due {
                continue;
            }
            match keys::maintain(state, tenant.id, policy).await {
                Ok((revoked, rotated)) => {
                    if revoked > 0 || rotated {
                        tracing::info!(tenant = %tenant.slug, revoked, rotated, "key housekeeping");
                    }
                }
                Err(err) => {
                    tracing::error!(tenant = %tenant.slug, error = %err, "key housekeeping failed")
                }
            }
            processed += 1;
        }
    }
    Ok(processed)
}
