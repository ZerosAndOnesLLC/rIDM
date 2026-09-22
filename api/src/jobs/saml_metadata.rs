//! SAML metadata refresh: every hour, the IdPs whose metadata URL was not
//! read successfully in the last day are fetched again (see
//! [`crate::services::saml_sp::refresh_due`]), so an upstream certificate
//! rollover reaches rIDM without an administrator.

use std::time::Duration;

use crate::error::AppResult;
use crate::jobs::leader;
use crate::services::saml_sp;
use crate::state::AppState;

pub const JOB_NAME: &str = "saml_metadata_refresh";

/// One pass on the node holding the lock. Returns the providers refreshed.
pub async fn run_once(state: &AppState) -> AppResult<Option<usize>> {
    let Some(lock) = leader::try_acquire(&state.redis, JOB_NAME, Duration::from_secs(3600)).await?
    else {
        return Ok(None);
    };
    let result = saml_sp::refresh_due(state).await;
    lock.release().await?;
    result.map(Some)
}
