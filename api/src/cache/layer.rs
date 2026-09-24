//! Two-tier read-through cache: L1 (in-process, seconds) → Redis (minutes) → loader.
//!
//! Writes call [`CacheLayer::invalidate`], which evicts L1 locally, deletes the
//! Redis keys, and publishes the keys on [`keys::INVALIDATION_CHANNEL`] so every
//! other node evicts its L1 too. Missing values are negatively cached for a
//! short time so unknown slugs cannot hammer the database.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use redis::AsyncCommands;
use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use super::keys;
use super::l1::L1Cache;
use super::pool::Cache as RedisPool;
use crate::error::AppError;

/// How long a node trusts a version token it read. A bump reaches every node
/// through pub/sub well before this; the limit bounds how long a node that
/// missed the message (its listener reconnecting clears L1 anyway) or read
/// the old token while the bump was on its way can use it.
pub const VERSION_L1_TTL: Duration = Duration::from_secs(2);

/// Key material entries a node keeps: a few per tenant.
const MATERIAL_ENTRIES: u64 = 20_000;

/// Sentinel stored in Redis for "looked up, does not exist".
const NEGATIVE: &str = "\u{0}null";

/// Sentinel an invalidation leaves in place of a key for
/// [`INVALIDATION_HOLD`]: read as a miss, and no loader may overwrite it. A
/// loader that read its source before the write behind the invalidation
/// would otherwise put the old value back after the delete, for a full TTL.
const INVALIDATED: &str = "\u{0}invalidated";

/// How long an invalidated key refuses loaders' writes: longer than a load.
const INVALIDATION_HOLD: Duration = Duration::from_secs(5);

/// A loader's write: only while the key is not held by an invalidation.
static SET_UNLESS_INVALIDATED: std::sync::LazyLock<redis::Script> =
    std::sync::LazyLock::new(|| {
        redis::Script::new(
            r"
if redis.call('GET', KEYS[1]) == ARGV[3] then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return 1
",
        )
    });

/// `ttl` spread by up to a tenth either way, so entries cached together
/// (a tenant's objects after a restart, every user's roles after a change)
/// do not all expire, and reload, in the same second.
pub fn jittered(ttl: Duration) -> Duration {
    let spread = ttl.as_millis() as u64 / 10;
    if spread == 0 {
        return ttl;
    }
    ttl - Duration::from_millis(spread) + Duration::from_millis(rand::random_range(0..=2 * spread))
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct InvalidationMessage {
    pub node_id: Uuid,
    pub keys: Vec<String>,
}

/// One lock per key being loaded on this node.
type Loading = Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>;

#[derive(Clone)]
pub struct CacheLayer {
    redis: RedisPool,
    l1: Arc<L1Cache>,
    /// Parsed and decrypted key material (signing keys, verification key
    /// sets, SAML signers). Kept apart from `l1`, which holds an entry per
    /// active user: those must never push out a key, whose reload may be a
    /// round trip to a key custody backend.
    material: Arc<L1Cache>,
    loading: Loading,
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
            material: Arc::new(L1Cache::with_capacity(MATERIAL_ENTRIES)),
            loading: Loading::default(),
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

    /// The cache for key material (see the field).
    pub fn material(&self) -> &L1Cache {
        &self.material
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
        if self.l1.get::<NegativeMarker>(key).is_some() {
            return Ok(None);
        }

        // Taken before anything is read: a value read before an eviction
        // that arrives meanwhile must not be cached (it may be the old one).
        let ticket = self.l1.ticket(key);
        match self.redis_get::<T>(key).await {
            Ok(Lookup::Hit(v)) => {
                self.l1
                    .insert_fresh(key.to_string(), v.clone(), jittered(self.l1_ttl), ticket);
                return Ok(Some(v));
            }
            Ok(Lookup::Absent) => {
                self.l1.insert_fresh(
                    key.to_string(),
                    Arc::new(NegativeMarker),
                    self.l1_ttl,
                    ticket,
                );
                return Ok(None);
            }
            Ok(Lookup::Miss) => {}
            // Redis trouble must not take the service down: fall through to the loader.
            Err(err) => tracing::warn!(key, error = %err, "cache read failed; loading from source"),
        }

        // One load per key per node: concurrent misses (a hot tenant or
        // client just invalidated) wait for it and read what it stored.
        let gate = self.gate(key);
        let loading = gate.lock().await;
        let result = self.load_after_wait(key, ttl, loader, ticket).await;
        drop(loading);
        self.release_gate(key, &gate);
        result
    }

    async fn load_after_wait<T, F, Fut>(
        &self,
        key: &str,
        ttl: Duration,
        loader: F,
        ticket: super::l1::Ticket,
    ) -> Result<Option<Arc<T>>, AppError>
    where
        T: Serialize + DeserializeOwned + Send + Sync + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<T>, AppError>>,
    {
        if let Some(v) = self.l1.get::<T>(key) {
            return Ok(Some(v));
        }
        if self.l1.get::<NegativeMarker>(key).is_some() {
            return Ok(None);
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
                self.l1.insert_fresh(
                    key.to_string(),
                    value.clone(),
                    jittered(self.l1_ttl),
                    ticket,
                );
                Ok(Some(value))
            }
            None => {
                if let Err(err) = self.redis_set(key, NEGATIVE, self.negative_ttl).await {
                    tracing::warn!(key, error = %err, "negative cache write failed");
                }
                self.l1.insert_fresh(
                    key.to_string(),
                    Arc::new(NegativeMarker),
                    self.l1_ttl,
                    ticket,
                );
                Ok(None)
            }
        }
    }

    fn gate(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.loading
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.to_string())
            .or_default()
            .clone()
    }

    /// Drop the key's lock once nobody else holds or waits on it.
    fn release_gate(&self, key: &str, gate: &Arc<tokio::sync::Mutex<()>>) {
        let mut loading = self.loading.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(current) = loading.get(key)
            && Arc::ptr_eq(current, gate)
            && Arc::strong_count(gate) == 2
        {
            loading.remove(key);
        }
    }

    /// A version token (a tenant's keys, role graph, claim mappers): the value
    /// cached entries of that kind hang off, created on first read. Held in
    /// L1 for [`VERSION_L1_TTL`], so the hot paths that read one per token or
    /// per request do not ask Valkey each time; [`CacheLayer::bump_version`]
    /// evicts it on every node at once.
    pub async fn version(&self, key: &str, ttl: Duration) -> Result<String, AppError> {
        if let Some(v) = self.l1.get::<String>(key) {
            return Ok((*v).clone());
        }
        let mut conn = self.redis.get().await?;
        let version = match conn.get::<_, Option<String>>(key).await? {
            Some(v) => v,
            None => {
                let fresh = Uuid::now_v7().simple().to_string();
                // SET NX so concurrent initialisers agree on one token.
                let set: bool = redis::cmd("SET")
                    .arg(key)
                    .arg(&fresh)
                    .arg("NX")
                    .arg("EX")
                    .arg(ttl.as_secs().max(1))
                    .query_async(&mut conn)
                    .await?;
                if set {
                    fresh
                } else {
                    conn.get::<_, Option<String>>(key).await?.unwrap_or(fresh)
                }
            }
        };
        self.l1
            .insert(key.to_string(), Arc::new(version.clone()), VERSION_L1_TTL);
        Ok(version)
    }

    /// Replace a version token, orphaning every entry cached under the old
    /// one, and evict it from every node's L1. The key is overwritten, never
    /// deleted: a node reading between a delete and the next write would
    /// otherwise mint a version of its own.
    pub async fn bump_version(&self, key: &str, ttl: Duration) -> Result<(), AppError> {
        self.bump_versions(&[key.to_string()], ttl).await
    }

    /// [`CacheLayer::bump_version`] for several tokens, with one eviction
    /// message for all of them.
    pub async fn bump_versions(&self, keys: &[String], ttl: Duration) -> Result<(), AppError> {
        if keys.is_empty() {
            return Ok(());
        }
        let mut conn = self.redis.get().await?;
        for key in keys {
            let _: () = conn
                .set_ex(
                    key,
                    Uuid::now_v7().simple().to_string(),
                    ttl.as_secs().max(1),
                )
                .await?;
            self.l1.remove(key);
        }
        let msg = serde_json::to_string(&InvalidationMessage {
            node_id: self.node_id,
            keys: keys.to_vec(),
        })?;
        let _: () = conn.publish(keys::INVALIDATION_CHANNEL, msg).await?;
        Ok(())
    }

    /// Evict everywhere: local L1, Redis, and every other node's L1 via pub/sub.
    pub async fn invalidate(&self, keys: &[String]) -> Result<(), AppError> {
        if keys.is_empty() {
            return Ok(());
        }
        for k in keys {
            self.l1.remove(k);
            self.material.remove(k);
        }
        let mut conn = self.redis.get().await?;
        // One key per command (a cluster refuses multi-key commands across
        // slots), sent together as one pipeline where the keys share a
        // backend. The key is held, not deleted: see [`INVALIDATED`].
        let hold = INVALIDATION_HOLD.as_millis() as u64;
        let pipelined = !matches!(
            self.redis.topology(),
            crate::cache::Topology::Cluster { .. }
        ) && keys.iter().all(|k| {
            crate::cache::key_tenant(k.as_bytes()) == crate::cache::key_tenant(keys[0].as_bytes())
        });
        if pipelined {
            let mut pipe = redis::pipe();
            for k in keys {
                pipe.cmd("SET")
                    .arg(k)
                    .arg(INVALIDATED)
                    .arg("PX")
                    .arg(hold)
                    .ignore();
            }
            let _: () = pipe.query_async(&mut conn).await?;
        } else {
            for k in keys {
                let _: () = redis::cmd("SET")
                    .arg(k)
                    .arg(INVALIDATED)
                    .arg("PX")
                    .arg(hold)
                    .query_async(&mut conn)
                    .await?;
            }
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
        let caches = [self.l1.clone(), self.material.clone()];
        let node_id = self.node_id;
        let redis = self.redis.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_millis(200);
            loop {
                match Self::listen(&redis, node_id, &caches).await {
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
        caches: &[Arc<L1Cache>],
    ) -> Result<(), redis::RedisError> {
        use futures::StreamExt as _;

        let client = redis.pubsub_client().await?;
        let mut pubsub = client.get_async_pubsub().await?;
        pubsub.subscribe(keys::INVALIDATION_CHANNEL).await?;
        // Anything cached before we were listening may be stale.
        for cache in caches {
            cache.clear();
        }
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
                        for cache in caches {
                            cache.remove(k);
                        }
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
            Some(s) if s == INVALIDATED => Lookup::Miss,
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

    /// A loader's write, refused while an invalidation holds the key.
    async fn redis_set(&self, key: &str, value: &str, ttl: Duration) -> Result<(), AppError> {
        let mut conn = self.redis.get().await?;
        let _: i64 = SET_UNLESS_INVALIDATED
            .key(key)
            .arg(value)
            .arg(jittered(ttl).as_secs().max(1))
            .arg(INVALIDATED)
            .invoke_async(&mut conn)
            .await?;
        Ok(())
    }
}

/// L1 marker for a negatively cached key.
struct NegativeMarker;
