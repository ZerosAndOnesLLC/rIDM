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
    /// Push the expiry out to `ttl` from now if we still hold the lock
    /// (compare-and-expire). A long pass calls this as it goes, so the lock
    /// never lapses under it and lets a second node start the same work.
    /// `false`: the lock was lost, and the caller should stop.
    pub async fn extend(&self, ttl: Duration) -> Result<bool, AppError> {
        const SCRIPT: &str = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('PEXPIRE', KEYS[1], ARGV[2]) else return 0 end";
        let mut conn = self.redis.get().await?;
        let extended: i64 = redis::Script::new(SCRIPT)
            .key(&self.key)
            .arg(&self.token)
            .arg(ttl.as_millis() as u64)
            .invoke_async(&mut conn)
            .await?;
        Ok(extended == 1)
    }

    /// Run `work` while renewing the lock every third of `ttl`, so it holds
    /// however long the work takes. Losing the lock is logged; the work is
    /// not interrupted (what it claims is claimed atomically).
    pub async fn hold_while<F: std::future::Future>(&self, ttl: Duration, work: F) -> F::Output {
        let mut work = std::pin::pin!(work);
        let mut renew = tokio::time::interval(ttl / 3);
        renew.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick is immediate; the lock was just taken.
        renew.tick().await;
        loop {
            tokio::select! {
                out = &mut work => return out,
                _ = renew.tick() => match self.extend(ttl).await {
                    Ok(true) => {}
                    Ok(false) => tracing::warn!(lock = %self.key, "leader lock lost while its job ran"),
                    Err(err) => tracing::warn!(lock = %self.key, error = %err, "leader lock not renewed"),
                },
            }
        }
    }

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
