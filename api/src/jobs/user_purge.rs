//! Daily purge of soft-deleted users past their tenant's retention period.

use std::time::Duration;

use crate::db;
use crate::error::AppResult;
use crate::jobs::leader;
use crate::repos;
use crate::services::{account, tenants};
use crate::state::AppState;

pub const JOB_NAME: &str = "user_purge";
/// How long the lock is held without renewal; every tenant renews it.
const LOCK_TTL: Duration = Duration::from_secs(1800);

/// One pass over every tenant with a soft-deleted user. Returns rows purged,
/// or `None` when another node holds the lock.
pub async fn run_once(state: &AppState) -> AppResult<Option<u64>> {
    let Some(lock) = leader::try_acquire(&state.redis, JOB_NAME, LOCK_TTL).await? else {
        return Ok(None);
    };
    let result = process_all(state, &lock).await;
    lock.release().await?;
    result.map(Some)
}

/// Only tenants that have a soft-deleted user are visited: one index-only
/// read per database finds them, instead of a transaction per tenant.
async fn process_all(state: &AppState, lock: &leader::LeaderLock) -> AppResult<u64> {
    let mut purged = 0;
    for database in state.db.all() {
        let tenant_ids = {
            let mut tx = db::bypass_tx(&database.primary).await?;
            let ids = repos::users::tenants_with_deleted(&mut *tx).await?;
            tx.commit().await?;
            ids
        };
        for tenant_id in tenant_ids {
            // Settings and placement come from the registry (home database).
            let tenant = match tenants::get_cached(state, tenant_id).await {
                Ok(Some(tenant)) => tenant,
                // Deleted since: its rows went with it.
                Ok(None) => continue,
                Err(err) => {
                    tracing::error!(tenant = %tenant_id, error = %err, "user purge skipped a tenant");
                    continue;
                }
            };
            // A tenant being moved is unreachable until the move is over.
            if tenant.relocating {
                continue;
            }
            match account::purge_deleted(
                state,
                tenant.id,
                tenant.settings.account.deletion_retention_days,
            )
            .await
            {
                Ok(n) => {
                    if n > 0 {
                        tracing::info!(tenant = %tenant.slug, purged = n, "deleted users purged");
                    }
                    purged += n;
                }
                Err(err) => {
                    tracing::error!(tenant = %tenant.slug, error = %err, "user purge failed")
                }
            }
            if !lock.extend(LOCK_TTL).await? {
                tracing::warn!("user purge lost its lock; stopping");
                return Ok(purged);
            }
        }
    }
    Ok(purged)
}
