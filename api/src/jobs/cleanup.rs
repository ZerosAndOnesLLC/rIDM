//! Hourly housekeeping across every tenant: rows that only ever grow and
//! that nothing reads after a while — expired or spent refresh tokens and
//! sessions, login attempts, sent messages, delivered and dead webhook
//! deliveries, device-code audit rows, spent invitations and trusted
//! devices, expired or revoked personal and provisioning tokens — go once
//! they are older than `RETENTION_DAYS` (sessions: a week at most). Deletes
//! run in batches so no table is held for long.

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::Utc;

use crate::db;
use crate::error::AppResult;
use crate::jobs::leader;
use crate::repos::cleanup::{self, Keep};
use crate::state::AppState;

pub const JOB_NAME: &str = "cleanup";
/// Sessions are never kept longer than this after they end.
const SESSION_DAYS: u32 = 7;

/// Rows deleted per table.
pub type Report = BTreeMap<&'static str, u64>;

pub async fn run_once(state: &AppState) -> AppResult<Option<Report>> {
    let Some(lock) = leader::try_acquire(&state.redis, JOB_NAME, Duration::from_secs(600)).await?
    else {
        return Ok(None);
    };
    let retention = state.config.retention_days;
    let mut report = Report::new();
    for target in cleanup::TARGETS {
        let days = match target.keep {
            Keep::Retention => retention,
            Keep::Sessions => retention.min(SESSION_DAYS),
        };
        let cutoff = Utc::now() - chrono::Duration::days(i64::from(days));
        let mut total = 0u64;
        for database in state.db.all() {
            loop {
                let mut tx = db::bypass_tx(&database.primary).await?;
                let n = cleanup::purge_batch(&mut *tx, target, cutoff).await?;
                tx.commit().await?;
                total += n;
                if n < cleanup::BATCH as u64 {
                    break;
                }
            }
        }
        if total > 0 {
            tracing::info!(table = target.table, deleted = total, "cleanup");
            metrics::counter!("ridm_cleanup_rows_total", "table" => target.table).increment(total);
        }
        report.insert(target.table, total);
    }
    lock.release().await?;
    Ok(Some(report))
}
