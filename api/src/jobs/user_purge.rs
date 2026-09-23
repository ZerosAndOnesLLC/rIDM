//! Daily purge of soft-deleted users past their tenant's retention period.

use std::time::Duration;

use crate::error::AppResult;
use crate::jobs::leader;
use crate::repos;
use crate::services::account;
use crate::state::AppState;

pub const JOB_NAME: &str = "user_purge";

/// One pass over every tenant. Returns rows purged, or `None` when another
/// node holds the lock.
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
    let mut purged = 0;
    let mut cursor = None;
    loop {
        let page = repos::tenants::list(state.db.home(), cursor, 200).await?;
        let has_more = page.len() > 200;
        for tenant in page.iter().take(200) {
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
        }
        if !has_more {
            break;
        }
        cursor = page.get(199).map(|t| crate::util::cursor::Cursor {
            created_at: t.created_at,
            id: t.id,
        });
    }
    Ok(purged)
}
