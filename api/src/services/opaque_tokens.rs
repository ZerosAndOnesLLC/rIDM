//! Opaque access tokens, for clients registered with
//! `access_token_format: opaque` (introspection-only tokens).
//!
//! The client receives `at_<random>`; the claims the JWT would have carried
//! are kept in Valkey under SHA-256(token) until the token expires, so the
//! entry's TTL is the token's lifetime and nothing needs cleaning up.
//! Resource servers learn the claims from `/introspect`; rIDM's own endpoints
//! (userinfo, revocation, token exchange, the account and admin APIs) read
//! them here through [`crate::services::tokens::verify_access`]. Access
//! tokens are short-lived and read on every call, which is what Valkey is
//! for; losing the cache ends them early, the same way it ends SSO sessions.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use redis::AsyncCommands as _;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::cache::keys;
use crate::error::AppResult;
use crate::state::AppState;

pub const PREFIX: &str = "at_";

/// Whether `token` has the shape of an opaque access token. JWTs never do
/// (they start with a base64url JOSE header, `eyJ`).
pub fn looks_like(token: &str) -> bool {
    token.starts_with(PREFIX) && token.len() <= 128
}

fn hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Mint a token standing for `claims` until `expires_at`.
pub async fn issue(
    state: &AppState,
    claims: &Map<String, Value>,
    expires_at: DateTime<Utc>,
) -> AppResult<String> {
    let ttl_ms = (expires_at - Utc::now()).num_milliseconds().max(1) as u64;
    let token = random_token();
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .pset_ex(
            keys::opaque_access_token(&hash(&token)),
            serde_json::to_string(claims)?,
            ttl_ms,
        )
        .await?;
    Ok(token)
}

/// The claims and tenant of a live token; `None` when unknown, expired
/// (the entry is gone) or revoked.
pub async fn lookup(
    state: &AppState,
    token: &str,
) -> AppResult<Option<(Uuid, Map<String, Value>)>> {
    if !looks_like(token) {
        return Ok(None);
    }
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = conn.get(keys::opaque_access_token(&hash(token))).await?;
    let Some(claims) = raw.and_then(|r| serde_json::from_str::<Map<String, Value>>(&r).ok()) else {
        return Ok(None);
    };
    let Some(tenant_id) = claims
        .get("tid")
        .and_then(Value::as_str)
        .and_then(|t| Uuid::parse_str(t).ok())
    else {
        return Ok(None);
    };
    Ok(Some((tenant_id, claims)))
}

/// Forget a token: every later lookup misses (RFC 7009 revocation).
pub async fn revoke(state: &AppState, token: &str) -> AppResult<()> {
    if !looks_like(token) {
        return Ok(());
    }
    let mut conn = state.redis.get().await?;
    let _: () = conn.del(keys::opaque_access_token(&hash(token))).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_prefixed_random_and_distinguishable_from_jwts() {
        let a = random_token();
        let b = random_token();
        assert!(a.starts_with("at_") && a.len() > 40);
        assert_ne!(a, b);
        assert!(looks_like(&a));
        assert!(!looks_like("eyJhbGciOiJFUzI1NiJ9.e30.sig"));
        assert!(!looks_like(&format!("at_{}", "x".repeat(200))));
        assert_eq!(hash(&a).len(), 43, "base64url SHA-256");
        assert_ne!(hash(&a), hash(&b));
    }
}
