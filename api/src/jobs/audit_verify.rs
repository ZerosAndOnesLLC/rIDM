//! Daily audit chain verification: walk every chain that grew since it was
//! last found intact (see [`crate::services::audit::verify_pending`]).

use std::time::Duration;

use crate::error::AppResult;
use crate::jobs::leader;
use crate::services::audit;
use crate::state::AppState;

pub const JOB_NAME: &str = "audit_verify";

/// One pass on the node holding the lock. Returns the rows checked.
pub async fn run_once(state: &AppState) -> AppResult<Option<u64>> {
    let Some(lock) = leader::try_acquire(&state.redis, JOB_NAME, Duration::from_secs(3600)).await?
    else {
        return Ok(None);
    };
    let result = audit::verify_pending(state).await;
    lock.release().await?;
    result.map(Some)
}
