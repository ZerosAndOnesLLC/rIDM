//! Periodic delivery of queued/retrying messages across all tenants.

use std::time::Duration;

use crate::error::AppResult;
use crate::jobs::leader;
use crate::messaging;
use crate::repos;
use crate::state::AppState;

pub const JOB_NAME: &str = "message_delivery";

pub async fn run_once(state: &AppState) -> AppResult<Option<(usize, usize)>> {
    let Some(lock) = leader::try_acquire(&state.redis, JOB_NAME, Duration::from_secs(120)).await?
    else {
        return Ok(None);
    };
    let mut totals = (0, 0);
    let mut cursor = None;
    loop {
        let page = repos::tenants::list(&state.db, cursor, 200).await?;
        let has_more = page.len() > 200;
        for tenant in page.iter().take(200) {
            match messaging::deliver_due(state, tenant.id, 100).await {
                Ok((s, f)) => {
                    totals.0 += s;
                    totals.1 += f;
                }
                Err(err) => {
                    tracing::error!(tenant = %tenant.slug, error = %err, "message delivery failed")
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
    lock.release().await?;
    Ok(Some(totals))
}
