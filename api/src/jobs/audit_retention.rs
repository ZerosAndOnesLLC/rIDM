//! Daily audit housekeeping: upcoming partitions and per-tenant retention.

use std::time::Duration;

use crate::error::AppResult;
use crate::jobs::leader;
use crate::models::MASTER_TENANT_ID;
use crate::repos;
use crate::services::{audit, tenants};
use crate::state::AppState;

pub const JOB_NAME: &str = "audit_retention";

/// One pass: create partitions, then purge every tenant's chain by its
/// policy (the global chain follows the master tenant's). Returns rows purged.
pub async fn run_once(state: &AppState) -> AppResult<Option<u64>> {
    let Some(lock) = leader::try_acquire(&state.redis, JOB_NAME, Duration::from_secs(1800)).await?
    else {
        return Ok(None);
    };
    let result = process_all(state).await;
    lock.release().await?;
    result.map(Some)
}

async fn process_all(state: &AppState) -> AppResult<u64> {
    // A failure here must not cost the purge: rows then land in the default
    // partition, where the purge still reaches them.
    match audit::ensure_partitions(state).await {
        Ok(0) => {}
        Ok(created) => tracing::info!(created, "audit: partitions created"),
        Err(err) => tracing::error!(error = %err, "audit: creating partitions failed"),
    }
    let mut purged = 0;
    let mut cursor = None;
    loop {
        let page = repos::tenants::list(state.db.home(), None, cursor, 200).await?;
        let has_more = page.len() > 200;
        for tenant in page.iter().take(200) {
            // A tenant being moved is unreachable until the move is over.
            if tenant.relocating {
                continue;
            }
            match audit::purge(state, Some(tenant.id), tenant.settings.audit.retention_days).await {
                Ok(n) => purged += n,
                Err(err) => {
                    tracing::error!(tenant = %tenant.slug, error = %err, "audit purge failed")
                }
            }
        }
        if !has_more {
            break;
        }
        cursor = page.get(199).map(|t| crate::util::cursor::Cursor {
            created_at: t.created_at,
            id: t.id,
        });
    }
    let master = tenants::get(state, MASTER_TENANT_ID).await?;
    purged += audit::purge(state, None, master.settings.audit.retention_days).await?;
    Ok(purged)
}
