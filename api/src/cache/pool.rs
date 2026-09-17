//! Valkey / Redis connection pool over one of three topologies, chosen by
//! the shape of `REDIS_URL`:
//!
//! * `redis://host:port[/db]` — one server;
//! * `redis+cluster://host1:port,host2:port,...` — a cluster (keys are
//!   routed by slot, so every command here touches one key at a time);
//! * `redis+sentinel://sentinel1:26379,sentinel2:26379/<master name>` —
//!   Sentinel-managed replication, the pool following the current master.
//!
//! Callers get a [`CacheConn`] that speaks the redis `ConnectionLike`
//! protocol whatever the topology, so services never know which one runs.

use std::time::Duration;

use deadpool_redis::{PoolConfig, Runtime, Timeouts};
use redis::aio::ConnectionLike;
use redis::{AsyncCommands, Cmd, Pipeline, RedisFuture, Value};

use crate::config::Config;
use crate::error::AppError;

/// How `REDIS_URL` was understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Topology {
    Single { url: String },
    Cluster { urls: Vec<String> },
    Sentinel { urls: Vec<String>, master: String },
}

impl Topology {
    /// Parse `REDIS_URL` (see the module doc for the forms).
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if let Some(rest) = raw.strip_prefix("redis+cluster://") {
            let (hosts, _) = rest.split_once('/').unwrap_or((rest, ""));
            let urls = split_hosts(hosts, "redis")?;
            return Ok(Self::Cluster { urls });
        }
        if let Some(rest) = raw.strip_prefix("redis+sentinel://") {
            let (hosts, master) = rest
                .split_once('/')
                .ok_or("redis+sentinel:// needs /<master name> at the end")?;
            let master = master.trim_matches('/').to_string();
            if master.is_empty() {
                return Err("redis+sentinel:// needs a master name".into());
            }
            let urls = split_hosts(hosts, "redis")?;
            return Ok(Self::Sentinel { urls, master });
        }
        if raw.starts_with("redis://") || raw.starts_with("rediss://") {
            return Ok(Self::Single {
                url: raw.to_string(),
            });
        }
        Err("expected redis://, rediss://, redis+cluster:// or redis+sentinel://".into())
    }

    /// A single node any pub/sub subscription may use (cluster pub/sub
    /// reaches every node; Sentinel resolves the master when connecting).
    fn first_url(&self) -> String {
        match self {
            Self::Single { url } => url.clone(),
            Self::Cluster { urls } | Self::Sentinel { urls, .. } => {
                urls.first().cloned().unwrap_or_default()
            }
        }
    }
}

/// `a:1,b:2` → `["redis://a:1", "redis://b:2"]`; credentials before an `@` apply to each.
fn split_hosts(hosts: &str, scheme: &str) -> Result<Vec<String>, String> {
    let (auth, hosts) = match hosts.rsplit_once('@') {
        Some((a, h)) => (Some(a), h),
        None => (None, hosts),
    };
    let urls: Vec<String> = hosts
        .split(',')
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .map(|h| match auth {
            Some(a) => format!("{scheme}://{a}@{h}"),
            None => format!("{scheme}://{h}"),
        })
        .collect();
    if urls.is_empty() {
        return Err("at least one host is required".into());
    }
    Ok(urls)
}

#[derive(Clone)]
enum Inner {
    Single(deadpool_redis::Pool),
    Cluster(deadpool_redis::cluster::Pool),
    Sentinel(deadpool_redis::sentinel::Pool),
}

/// The pool, whatever the topology.
#[derive(Clone)]
pub struct Cache {
    inner: Inner,
    topology: Topology,
}

/// A pooled connection of any topology.
pub enum CacheConn {
    Single(deadpool_redis::Connection),
    Cluster(deadpool_redis::cluster::Connection),
    Sentinel(deadpool_redis::sentinel::Connection),
}

impl ConnectionLike for CacheConn {
    fn req_packed_command<'a>(&'a mut self, cmd: &'a Cmd) -> RedisFuture<'a, Value> {
        match self {
            Self::Single(c) => c.req_packed_command(cmd),
            Self::Cluster(c) => c.req_packed_command(cmd),
            Self::Sentinel(c) => c.req_packed_command(cmd),
        }
    }

    fn req_packed_commands<'a>(
        &'a mut self,
        cmd: &'a Pipeline,
        offset: usize,
        count: usize,
    ) -> RedisFuture<'a, Vec<Value>> {
        match self {
            Self::Single(c) => c.req_packed_commands(cmd, offset, count),
            Self::Cluster(c) => c.req_packed_commands(cmd, offset, count),
            Self::Sentinel(c) => c.req_packed_commands(cmd, offset, count),
        }
    }

    fn get_db(&self) -> i64 {
        match self {
            Self::Single(c) => c.get_db(),
            Self::Cluster(c) => c.get_db(),
            Self::Sentinel(c) => c.get_db(),
        }
    }
}

fn pool_config() -> PoolConfig {
    PoolConfig {
        max_size: 32,
        timeouts: Timeouts {
            wait: Some(Duration::from_secs(5)),
            create: Some(Duration::from_secs(5)),
            recycle: Some(Duration::from_secs(5)),
        },
        ..Default::default()
    }
}

impl Cache {
    pub fn topology(&self) -> &Topology {
        &self.topology
    }

    pub async fn get(&self) -> Result<CacheConn, AppError> {
        Ok(match &self.inner {
            Inner::Single(p) => CacheConn::Single(p.get().await?),
            Inner::Cluster(p) => {
                CacheConn::Cluster(p.get().await.map_err(|e| AppError::Cache(e.to_string()))?)
            }
            Inner::Sentinel(p) => {
                CacheConn::Sentinel(p.get().await.map_err(|e| AppError::Cache(e.to_string()))?)
            }
        })
    }

    /// A client for pub/sub subscriptions: the server, any cluster node, or
    /// the master Sentinel currently names.
    pub async fn pubsub_client(&self) -> Result<redis::Client, redis::RedisError> {
        match &self.topology {
            Topology::Sentinel { urls, master } => {
                let mut sentinel = redis::sentinel::Sentinel::build(urls.clone())?;
                sentinel.async_master_for(master, None).await
            }
            other => redis::Client::open(other.first_url()),
        }
    }
}

pub fn connect(config: &Config) -> Result<Cache, AppError> {
    let topology = Topology::parse(&config.redis_url).map_err(AppError::Cache)?;
    let inner = match &topology {
        Topology::Single { url } => {
            let mut cfg = deadpool_redis::Config::from_url(url);
            cfg.pool = Some(pool_config());
            Inner::Single(
                cfg.create_pool(Some(Runtime::Tokio1))
                    .map_err(|e| AppError::Cache(e.to_string()))?,
            )
        }
        Topology::Cluster { urls } => {
            let mut cfg = deadpool_redis::cluster::Config::from_urls(urls.clone());
            cfg.pool = Some(pool_config());
            Inner::Cluster(
                cfg.create_pool(Some(Runtime::Tokio1))
                    .map_err(|e| AppError::Cache(e.to_string()))?,
            )
        }
        Topology::Sentinel { urls, master } => {
            let mut cfg = deadpool_redis::sentinel::Config::from_urls(
                urls.clone(),
                master.clone(),
                deadpool_redis::sentinel::SentinelServerType::Master,
            );
            cfg.pool = Some(pool_config());
            Inner::Sentinel(
                cfg.create_pool(Some(Runtime::Tokio1))
                    .map_err(|e| AppError::Cache(e.to_string()))?,
            )
        }
    };
    Ok(Cache { inner, topology })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topologies_parse() {
        assert_eq!(
            Topology::parse("redis://localhost:6390/0").unwrap(),
            Topology::Single {
                url: "redis://localhost:6390/0".into()
            }
        );
        assert_eq!(
            Topology::parse("redis+cluster://a:7000,b:7001").unwrap(),
            Topology::Cluster {
                urls: vec!["redis://a:7000".into(), "redis://b:7001".into()]
            }
        );
        assert_eq!(
            Topology::parse("redis+cluster://:secret@a:7000,b:7001/").unwrap(),
            Topology::Cluster {
                urls: vec![
                    "redis://:secret@a:7000".into(),
                    "redis://:secret@b:7001".into()
                ]
            }
        );
        assert_eq!(
            Topology::parse("redis+sentinel://s1:26379,s2:26379/mymaster").unwrap(),
            Topology::Sentinel {
                urls: vec!["redis://s1:26379".into(), "redis://s2:26379".into()],
                master: "mymaster".into()
            }
        );
        assert!(Topology::parse("redis+sentinel://s1:26379").is_err());
        assert!(Topology::parse("redis+cluster://").is_err());
        assert!(Topology::parse("http://x").is_err());
    }
}
