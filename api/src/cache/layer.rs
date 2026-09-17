//! Two-tier read-through cache: L1 (in-process, seconds) → Redis (minutes) → loader.
//!
//! Writes call [`CacheLayer::invalidate`], which evicts L1 locally, deletes the
//! Redis keys, and publishes the keys on [`keys::INVALIDATION_CHANNEL`] so every
//! other node evicts its L1 too. Missing values are negatively cached for a
//! short time so unknown slugs cannot hammer the database.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use redis::AsyncCommands;
use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use super::keys;
use super::l1::L1Cache;
use super::pool::Cache as RedisPool;
use crate::error::AppError;

/// Sentinel stored in Redis for "looked up, does not exist".
const NEGATIVE: &str = "\u{0}null";

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct InvalidationMessage {
    pub node_id: Uuid,
    pub keys: Vec<String>,
}

#[derive(Clone)]
pub struct CacheLayer {
    redis: RedisPool,
    l1: Arc<L1Cache>,
    node_id: Uuid,
    pub l1_ttl: Duration,
    pub negative_ttl: Duration,
}

/// Cached lookup result: distinguishes "cached absent" from "cache miss".
enum Lookup<T> {
    Hit(Arc<T>),
    Absent,
    Miss,
}

impl CacheLayer {
    pub fn new(redis: RedisPool) -> Self {
        Self {
            redis,
            l1: Arc::new(L1Cache::default()),
            node_id: Uuid::now_v7(),
            l1_ttl: Duration::from_secs(15),
            negative_ttl: Duration::from_secs(30),
        }
    }

    pub fn node_id(&self) -> Uuid {
        self.node_id
    }

    pub fn l1(&self) -> &L1Cache {
        &self.l1
    }

    /// Read-through get. `ttl` is the Redis TTL for positive entries.
    pub async fn get_or_load<T, F, Fut>(
        &self,
        key: &str,
        ttl: Duration,
        loader: F,
    ) -> Result<Option<Arc<T>>, AppError>
    where
        T: Serialize + DeserializeOwned + Send + Sync + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<T>, AppError>>,
    {
        if let Some(v) = self.l1.get::<T>(key) {
            return Ok(Some(v));
        }
        if let Some(v) = self.l1.get::<NegativeMarker>(key) {
            let _ = v;
            return Ok(None);
        }

        match self.redis_get::<T>(key).await {
            Ok(Lookup::Hit(v)) => {
                self.l1.insert(key.to_string(), v.clone(), self.l1_ttl);
                return Ok(Some(v));
            }
            Ok(Lookup::Absent) => {
                self.l1
                    .insert(key.to_string(), Arc::new(NegativeMarker), self.l1_ttl);
                return Ok(None);
            }
            Ok(Lookup::Miss) => {}
            // Redis trouble must not take the service down: fall through to the loader.
            Err(err) => tracing::warn!(key, error = %err, "cache read failed; loading from source"),
        }

        let loaded = loader().await?;
        match loaded {
            Some(value) => {
                let value = Arc::new(value);
                if let Ok(json) = serde_json::to_string(&*value)
                    && let Err(err) = self.redis_set(key, &json, ttl).await
                {
                    tracing::warn!(key, error = %err, "cache write failed");
                }
                self.l1.insert(key.to_string(), value.clone(), self.l1_ttl);
                Ok(Some(value))
            }
            None => {
                if let Err(err) = self.redis_set(key, NEGATIVE, self.negative_ttl).await {
                    tracing::warn!(key, error = %err, "negative cache write failed");
                }
                self.l1
                    .insert(key.to_string(), Arc::new(NegativeMarker), self.l1_ttl);
                Ok(None)
            }
        }
    }

    /// Evict everywhere: local L1, Redis, and every other node's L1 via pub/sub.
    pub async fn invalidate(&self, keys: &[String]) -> Result<(), AppError> {
        if keys.is_empty() {
            return Ok(());
        }
        for k in keys {
            self.l1.remove(k);
        }
        let mut conn = self.redis.get().await?;
        // One key per DEL: a cluster refuses multi-key commands across slots.
        for k in keys {
            let _: () = conn.del(k).await?;
        }
        let msg = serde_json::to_string(&InvalidationMessage {
            node_id: self.node_id,
            keys: keys.to_vec(),
        })?;
        let _: () = conn.publish(keys::INVALIDATION_CHANNEL, msg).await?;
        Ok(())
    }

    /// Run the pub/sub listener until the returned handle is dropped or aborted.
    /// Reconnects with backoff; on (re)connect the whole L1 is cleared because
    /// invalidations may have been missed.
    pub fn spawn_invalidation_listener(&self) -> tokio::task::JoinHandle<()> {
        let l1 = self.l1.clone();
        let node_id = self.node_id;
        let redis = self.redis.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_millis(200);
            loop {
                match Self::listen(&redis, node_id, &l1).await {
                    Ok(()) => backoff = Duration::from_millis(200),
                    Err(err) => {
                        tracing::warn!(error = %err, "cache invalidation listener disconnected");
                    }
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(10));
            }
        })
    }

    async fn listen(
        redis: &RedisPool,
        node_id: Uuid,
        l1: &L1Cache,
    ) -> Result<(), redis::RedisError> {
        use futures::StreamExt as _;

        let client = redis.pubsub_client().await?;
        let mut pubsub = client.get_async_pubsub().await?;
        pubsub.subscribe(keys::INVALIDATION_CHANNEL).await?;
        // Anything cached before we were listening may be stale.
        l1.clear();
        tracing::debug!("cache invalidation listener connected");
        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            let payload: String = match msg.get_payload() {
                Ok(p) => p,
                Err(err) => {
                    tracing::warn!(error = %err, "bad invalidation payload");
                    continue;
                }
            };
            match serde_json::from_str::<InvalidationMessage>(&payload) {
                Ok(m) if m.node_id == node_id => {} // already evicted locally
                Ok(m) => {
                    for k in &m.keys {
                        l1.remove(k);
                    }
                }
                Err(err) => tracing::warn!(error = %err, "bad invalidation message"),
            }
        }
        Ok(())
    }

    async fn redis_get<T: DeserializeOwned>(&self, key: &str) -> Result<Lookup<T>, AppError> {
        let mut conn = self.redis.get().await?;
        let raw: Option<String> = conn.get(key).await?;
        Ok(match raw {
            None => Lookup::Miss,
            Some(s) if s == NEGATIVE => Lookup::Absent,
            Some(s) => match serde_json::from_str::<T>(&s) {
                Ok(v) => Lookup::Hit(Arc::new(v)),
                Err(err) => {
                    // Schema changed underneath us: treat as a miss and overwrite.
                    tracing::warn!(key, error = %err, "cached value unreadable; reloading");
                    Lookup::Miss
                }
            },
        })
    }

    async fn redis_set(&self, key: &str, value: &str, ttl: Duration) -> Result<(), AppError> {
        let mut conn = self.redis.get().await?;
        let _: () = conn.set_ex(key, value, ttl.as_secs().max(1)).await?;
        Ok(())
    }
}

/// L1 marker for a negatively cached key.
struct NegativeMarker;
