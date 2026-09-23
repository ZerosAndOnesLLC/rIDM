//! Periodic signing-key housekeeping across all tenants.

use std::time::Duration;

use crate::error::AppResult;
use crate::jobs::leader;
use crate::repos;
use crate::services::keys;
use crate::state::AppState;

pub const JOB_NAME: &str = "key_rotation";

/// One pass over every active tenant. Returns the number of tenants processed.
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

async fn process_all(state: &AppState) -> AppResult<usize> {
    let mut processed = 0;
    let mut cursor = None;
    loop {
        let page = repos::tenants::list(state.db.home(), cursor, 200).await?;
        let has_more = page.len() > 200;
        for tenant in page.iter().take(200) {
            // A tenant being moved is unreachable until the move is over.
            if !tenant.is_active() || tenant.relocating {
                continue;
            }
            match keys::maintain(state, tenant.id, &tenant.settings.keys).await {
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
        if !has_more {
            break;
        }
        cursor = page.get(199).map(|t| crate::util::cursor::Cursor {
            created_at: t.created_at,
            id: t.id,
        });
    }
    Ok(processed)
}
