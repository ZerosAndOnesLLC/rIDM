//! LDAP directory sync: every five minutes, the directories whose sync
//! interval has passed are synced (see [`crate::services::ldap::sync_due`];
//! each directory also takes its own lock, so an administrator's "sync
//! now" and the job never run the same directory at once).

use std::time::Duration;

use crate::error::AppResult;
use crate::jobs::leader;
use crate::services::ldap;
use crate::state::AppState;

pub const JOB_NAME: &str = "ldap_sync";

/// One pass on the node holding the lock. Returns the directories synced.
pub async fn run_once(state: &AppState) -> AppResult<Option<usize>> {
    let Some(lock) = leader::try_acquire(&state.redis, JOB_NAME, Duration::from_secs(3600)).await?
    else {
        return Ok(None);
    };
    let result = ldap::sync_due(state).await;
    lock.release().await?;
    result.map(Some)
}
