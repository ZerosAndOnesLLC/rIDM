//! The last run of every job, kept in Valkey for operators (`/readyz`
//! details and the admin stats) so a stuck scheduler is visible.

use chrono::{DateTime, Utc};
use redis::AsyncCommands as _;
use serde::{Deserialize, Serialize};

use crate::error::AppResult;
use crate::state::AppState;

const KEY: &str = "ridm:jobs:last_run";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct LastRun {
    pub job: String,
    pub at: DateTime<Utc>,
    pub ok: bool,
    pub duration_ms: u64,
    /// The failure, when `ok` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn record(state: &AppState, run: &LastRun) -> AppResult<()> {
    let mut conn = state.redis.get().await?;
    let json = serde_json::to_string(run)?;
    let _: () = conn.hset(KEY, &run.job, json).await?;
    Ok(())
}

/// Every job's last run, by name.
pub async fn all(state: &AppState) -> AppResult<Vec<LastRun>> {
    let mut conn = state.redis.get().await?;
    let raw: Vec<(String, String)> = conn.hgetall(KEY).await?;
    let mut runs: Vec<LastRun> = raw
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_str(&v).ok())
        .collect();
    runs.sort_by(|a, b| a.job.cmp(&b.job));
    Ok(runs)
}
