//! Redis / Valkey connection pool.

use std::time::Duration;

use deadpool_redis::{Config as RedisConfig, Pool, PoolConfig, Runtime, Timeouts};
use redis::AsyncCommands;

use crate::config::Config;
use crate::error::AppError;

pub type Cache = Pool;

pub fn connect(config: &Config) -> Result<Cache, AppError> {
    let mut cfg = RedisConfig::from_url(&config.redis_url);
    cfg.pool = Some(PoolConfig {
        max_size: 32,
        timeouts: Timeouts {
            wait: Some(Duration::from_secs(5)),
            create: Some(Duration::from_secs(5)),
            recycle: Some(Duration::from_secs(5)),
        },
        ..Default::default()
    });
    cfg.create_pool(Some(Runtime::Tokio1))
        .map_err(|e| AppError::Cache(e.to_string()))
}

/// Cheap liveness probe used by `/readyz`.
pub async fn ping(cache: &Cache) -> Result<(), AppError> {
    let mut conn = cache.get().await?;
    let pong: String = redis::cmd("PING").query_async(&mut conn).await?;
    if pong != "PONG" {
        return Err(AppError::Cache(format!("unexpected PING reply: {pong}")));
    }
    Ok(())
}

/// Set a key with a TTL. Values are JSON-encoded by the caller.
pub async fn set_ex(cache: &Cache, key: &str, value: &str, ttl: Duration) -> Result<(), AppError> {
    let mut conn = cache.get().await?;
    let _: () = conn.set_ex(key, value, ttl.as_secs()).await?;
    Ok(())
}

pub async fn get(cache: &Cache, key: &str) -> Result<Option<String>, AppError> {
    let mut conn = cache.get().await?;
    Ok(conn.get(key).await?)
}

pub async fn del(cache: &Cache, key: &str) -> Result<(), AppError> {
    let mut conn = cache.get().await?;
    let _: () = conn.del(key).await?;
    Ok(())
}
