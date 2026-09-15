//! Redis-held leader lock so that a job runs on one node at a time.

use std::time::Duration;

use uuid::Uuid;

use crate::cache::Cache;
use crate::error::AppError;

/// Try to take the lock `name` for `ttl`. Returns a guard on success; the
/// lock is released when the guard's `release` is awaited or expires.
pub async fn try_acquire(
    redis: &Cache,
    name: &str,
    ttl: Duration,
) -> Result<Option<LeaderLock>, AppError> {
    let key = format!("ridm:lock:{name}");
    let token = Uuid::now_v7().simple().to_string();
    let mut conn = redis.get().await?;
    let acquired: bool = redis::cmd("SET")
        .arg(&key)
        .arg(&token)
        .arg("NX")
        .arg("PX")
        .arg(ttl.as_millis() as u64)
        .query_async(&mut conn)
        .await?;
    Ok(acquired.then_some(LeaderLock {
        redis: redis.clone(),
        key,
        token,
    }))
}

pub struct LeaderLock {
    redis: Cache,
    key: String,
    token: String,
}

impl LeaderLock {
    /// Release only if we still hold it (compare-and-delete).
    pub async fn release(self) -> Result<(), AppError> {
        const SCRIPT: &str = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end";
        let mut conn = self.redis.get().await?;
        let _: i64 = redis::Script::new(SCRIPT)
            .key(&self.key)
            .arg(&self.token)
            .invoke_async(&mut conn)
            .await?;
        Ok(())
    }
}
