//! Initial access tokens for dynamic client registration (RFC 7591 §1.2):
//! admin-issued bearer tokens with a use budget, stored hashed in Redis.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use redis::AsyncCommands as _;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cache::keys;
use crate::error::AppResult;
use crate::state::AppState;

const PREFIX: &str = "iat_";

fn hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

/// Create a token allowing `max_uses` registrations within `ttl_secs`.
pub async fn issue_initial_access_token(
    state: &AppState,
    tenant_id: Uuid,
    ttl_secs: u64,
    max_uses: u32,
) -> AppResult<Zeroizing<String>> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let token = Zeroizing::new(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)));
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(
            keys::dcr_initial_token(tenant_id, &hash(&token)),
            max_uses.max(1),
            ttl_secs.max(1),
        )
        .await?;
    Ok(token)
}

/// Spend one use of an initial access token. `false` when unknown, expired
/// or exhausted.
pub async fn consume_initial_access_token(
    state: &AppState,
    tenant_id: Uuid,
    presented: &str,
) -> AppResult<bool> {
    if !presented.starts_with(PREFIX) || presented.len() > 128 {
        return Ok(false);
    }
    let key = keys::dcr_initial_token(tenant_id, &hash(presented));
    let mut conn = state.redis.get().await?;
    // Decrement atomically; delete when the budget hits zero. A missing key
    // decrements to -1, which we treat as unknown and clean up.
    let remaining: i64 = conn.decr(&key, 1).await?;
    if remaining < 0 {
        let _: () = conn.del(&key).await?;
        return Ok(false);
    }
    if remaining == 0 {
        let _: () = conn.del(&key).await?;
    }
    Ok(true)
}

pub async fn revoke_initial_access_token(
    state: &AppState,
    tenant_id: Uuid,
    presented: &str,
) -> AppResult<()> {
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .del(keys::dcr_initial_token(tenant_id, &hash(presented)))
        .await?;
    Ok(())
}
