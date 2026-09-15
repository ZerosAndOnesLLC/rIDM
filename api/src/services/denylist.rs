//! Access-token `jti` denylist (Redis, TTL = remaining token lifetime) so a
//! short-lived JWT can be revoked before it expires (logout, admin revoke).

use chrono::{DateTime, Utc};
use redis::AsyncCommands as _;
use uuid::Uuid;

use crate::cache::keys;
use crate::error::AppResult;
use crate::state::AppState;

pub async fn deny(
    state: &AppState,
    tenant_id: Uuid,
    jti: &str,
    expires_at: DateTime<Utc>,
) -> AppResult<()> {
    let ttl = (expires_at - Utc::now()).num_seconds();
    if ttl <= 0 {
        return Ok(());
    }
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(keys::jti_denied(tenant_id, jti), 1u8, ttl as u64)
        .await?;
    Ok(())
}

pub async fn is_denied(state: &AppState, tenant_id: Uuid, jti: &str) -> AppResult<bool> {
    let mut conn = state.redis.get().await?;
    Ok(conn.exists(keys::jti_denied(tenant_id, jti)).await?)
}
