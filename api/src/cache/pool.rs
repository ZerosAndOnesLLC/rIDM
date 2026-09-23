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

use std::sync::Arc;

use uuid::Uuid;

use super::keys;
use crate::config::{Config, HOME_REGION};
use crate::db::Db;
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

/// One Valkey deployment, whatever its topology.
#[derive(Clone)]
struct Backend {
    inner: Inner,
    topology: Topology,
}

impl Backend {
    fn connect(url: &str, max_size: u32) -> Result<Self, AppError> {
        let topology = Topology::parse(url).map_err(AppError::Cache)?;
        let pool = pool_config(max_size);
        let inner = match &topology {
            Topology::Single { url } => {
                let mut cfg = deadpool_redis::Config::from_url(url);
                cfg.pool = Some(pool);
                Inner::Single(
                    cfg.create_pool(Some(Runtime::Tokio1))
                        .map_err(|e| AppError::Cache(e.to_string()))?,
                )
            }
            Topology::Cluster { urls } => {
                let mut cfg = deadpool_redis::cluster::Config::from_urls(urls.clone());
                cfg.pool = Some(pool);
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
                cfg.pool = Some(pool);
                Inner::Sentinel(
                    cfg.create_pool(Some(Runtime::Tokio1))
                        .map_err(|e| AppError::Cache(e.to_string()))?,
                )
            }
        };
        Ok(Self { inner, topology })
    }

    async fn get(&self) -> Result<RawConn, AppError> {
        Ok(match &self.inner {
            Inner::Single(p) => RawConn::Single(p.get().await?),
            Inner::Cluster(p) => {
                RawConn::Cluster(p.get().await.map_err(|e| AppError::Cache(e.to_string()))?)
            }
            Inner::Sentinel(p) => {
                RawConn::Sentinel(p.get().await.map_err(|e| AppError::Cache(e.to_string()))?)
            }
        })
    }
}

/// The pool, whatever the topology. With data regions, a region may have
/// its own Valkey: a command on a tenant's key (`ridm:t:{tenant}:…`) then
/// goes to the Valkey of the region the tenant lives in, found through the
/// same placement as its database ([`Db::locate`]); every other key (leader
/// locks, the tenant registry cache, invalidation pub/sub) stays here.
#[derive(Clone)]
pub struct Cache {
    home: Backend,
    /// Regions with their own Valkey, by region name.
    regions: Arc<[(Arc<str>, Backend)]>,
    locator: Option<Db>,
}

/// A raw pooled connection of any topology.
enum RawConn {
    Single(deadpool_redis::Connection),
    Cluster(deadpool_redis::cluster::Connection),
    Sentinel(deadpool_redis::sentinel::Connection),
}

impl ConnectionLike for RawConn {
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

/// A connection callers use like any redis connection. Without regional
/// Valkeys it is one pooled connection; with them, each command is sent to
/// the Valkey its key belongs to, taking a connection there on first use.
pub struct CacheConn(Conn);

enum Conn {
    Direct(RawConn),
    Routed(Box<Routed>),
}

struct Routed {
    cache: Cache,
    /// `[0]` home, `[i]` `cache.regions[i - 1]`.
    conns: Vec<Option<RawConn>>,
}

impl Routed {
    async fn conn_for(&mut self, cmd: &Cmd) -> Result<&mut RawConn, redis::RedisError> {
        let index = self.cache.backend_index(routing_key(cmd)).await?;
        if self.conns[index].is_none() {
            let backend = match index {
                0 => &self.cache.home,
                i => &self.cache.regions[i - 1].1,
            };
            let conn = backend.get().await.map_err(|e| {
                redis::RedisError::from((redis::ErrorKind::Io, "cache pool", e.to_string()))
            })?;
            self.conns[index] = Some(conn);
        }
        Ok(self.conns[index].as_mut().expect("connection taken above"))
    }
}

impl ConnectionLike for CacheConn {
    fn req_packed_command<'a>(&'a mut self, cmd: &'a Cmd) -> RedisFuture<'a, Value> {
        match &mut self.0 {
            Conn::Direct(c) => c.req_packed_command(cmd),
            Conn::Routed(r) => Box::pin(async move {
                let conn = r.conn_for(cmd).await?;
                conn.req_packed_command(cmd).await
            }),
        }
    }

    /// A pipeline goes where its first command's key belongs: pipelines
    /// here never mix tenants.
    fn req_packed_commands<'a>(
        &'a mut self,
        cmd: &'a Pipeline,
        offset: usize,
        count: usize,
    ) -> RedisFuture<'a, Vec<Value>> {
        match &mut self.0 {
            Conn::Direct(c) => c.req_packed_commands(cmd, offset, count),
            Conn::Routed(r) => Box::pin(async move {
                let first = cmd
                    .cmd_iter()
                    .next()
                    .cloned()
                    .unwrap_or_else(|| redis::cmd("PING"));
                let conn = r.conn_for(&first).await?;
                conn.req_packed_commands(cmd, offset, count).await
            }),
        }
    }

    fn get_db(&self) -> i64 {
        match &self.0 {
            Conn::Direct(c) => c.get_db(),
            Conn::Routed(r) => r.conns[0].as_ref().map_or(0, RawConn::get_db),
        }
    }
}

/// The key a command acts on: the first argument, or the first key of a
/// script call (`EVAL`/`EVALSHA script numkeys key…`).
fn routing_key(cmd: &Cmd) -> Option<&[u8]> {
    let arg = |i: usize| match cmd.args_iter().nth(i) {
        Some(redis::Arg::Simple(a)) => Some(a),
        _ => None,
    };
    let name = arg(0)?;
    let script = [
        &b"EVAL"[..],
        b"EVALSHA",
        b"EVAL_RO",
        b"EVALSHA_RO",
        b"FCALL",
        b"FCALL_RO",
    ]
    .iter()
    .any(|n| name.eq_ignore_ascii_case(n));
    if script {
        let keys = std::str::from_utf8(arg(2)?).ok()?.parse::<u32>().ok()?;
        return if keys > 0 { arg(3) } else { None };
    }
    arg(1)
}

/// The tenant a key belongs to: `ridm:t:{uuid}:…`.
pub fn key_tenant(key: &[u8]) -> Option<Uuid> {
    let prefix = format!("{}:t:", keys::PREFIX);
    let rest = key.strip_prefix(prefix.as_bytes())?;
    let id = rest.get(..36)?;
    if rest.get(36).is_some_and(|c| *c != b':') {
        return None;
    }
    Uuid::parse_str(std::str::from_utf8(id).ok()?).ok()
}

fn pool_config(max_size: u32) -> PoolConfig {
    PoolConfig {
        max_size: max_size as usize,
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
        &self.home.topology
    }

    /// Route tenant keys to regional Valkeys by `db`'s placements. Without
    /// regional Valkeys this changes nothing.
    pub fn route_with(mut self, db: Db) -> Self {
        if !self.regions.is_empty() {
            self.locator = Some(db);
        }
        self
    }

    pub async fn get(&self) -> Result<CacheConn, AppError> {
        if self.locator.is_none() {
            return Ok(CacheConn(Conn::Direct(self.home.get().await?)));
        }
        let mut conns = Vec::with_capacity(self.regions.len() + 1);
        conns.resize_with(self.regions.len() + 1, || None);
        Ok(CacheConn(Conn::Routed(Box::new(Routed {
            cache: self.clone(),
            conns,
        }))))
    }

    /// Which backend a key lives on: `0` home, `i` `regions[i - 1]`.
    async fn backend_index(&self, key: Option<&[u8]>) -> Result<usize, redis::RedisError> {
        let (Some(db), Some(tenant)) = (&self.locator, key.and_then(key_tenant)) else {
            return Ok(0);
        };
        let database = db.locate(tenant).await.map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::Client,
                "tenant unavailable",
                e.to_string(),
            ))
        })?;
        Ok(self
            .regions
            .iter()
            .position(|(name, _)| *name == database.name)
            .map_or(0, |i| i + 1))
    }

    /// The Valkey `region` keeps its tenants' keys in (`None`: home), as a
    /// cache of its own, unrouted: the relocation copies keys between them.
    pub fn for_region(&self, region: Option<&str>) -> Cache {
        let backend = region
            .and_then(|r| self.regions.iter().find(|(name, _)| &**name == r))
            .map_or_else(|| self.home.clone(), |(_, b)| b.clone());
        Cache {
            home: backend,
            regions: Arc::from(Vec::new()),
            locator: None,
        }
    }

    /// Whether `a` and `b` (region names, `None`: home) share one Valkey.
    pub fn same_backend(&self, a: Option<&str>, b: Option<&str>) -> bool {
        let index = |r: Option<&str>| {
            r.and_then(|r| self.regions.iter().position(|(name, _)| &**name == r))
        };
        index(a) == index(b)
    }

    /// Every Valkey, home first, each unrouted (for `/readyz`).
    pub fn all(&self) -> Vec<(Arc<str>, Cache)> {
        let unrouted = |b: &Backend| Cache {
            home: b.clone(),
            regions: Arc::from(Vec::new()),
            locator: None,
        };
        let mut out = vec![(Arc::from(HOME_REGION), unrouted(&self.home))];
        out.extend(self.regions.iter().map(|(n, b)| (n.clone(), unrouted(b))));
        out
    }

    /// A client for pub/sub subscriptions: the server, any cluster node, or
    /// the master Sentinel currently names.
    pub async fn pubsub_client(&self) -> Result<redis::Client, redis::RedisError> {
        match &self.home.topology {
            Topology::Sentinel { urls, master } => {
                let mut sentinel = redis::sentinel::Sentinel::build(urls.clone())?;
                sentinel.async_master_for(master, None).await
            }
            other => redis::Client::open(other.first_url()),
        }
    }
}

impl Cache {
    /// Every key matching `pattern` on this Valkey (its home backend; on a
    /// cluster, every primary). For the rare full walks, such as a tenant's
    /// move between regions, never for serving a request.
    pub async fn scan_match(&self, pattern: &str) -> Result<Vec<String>, AppError> {
        let mut keys = vec![];
        match &self.home.topology {
            Topology::Cluster { urls } => {
                for url in cluster_primaries(urls).await? {
                    let client = redis::Client::open(url)?;
                    let mut conn = client.get_multiplexed_async_connection().await?;
                    scan_into(&mut conn, pattern, &mut keys).await?;
                }
            }
            _ => {
                let mut conn = self.home.get().await?;
                scan_into(&mut conn, pattern, &mut keys).await?;
            }
        }
        keys.sort();
        keys.dedup();
        Ok(keys)
    }
}

async fn scan_into<C: ConnectionLike + Send>(
    conn: &mut C,
    pattern: &str,
    out: &mut Vec<String>,
) -> Result<(), AppError> {
    let mut cursor: u64 = 0;
    loop {
        let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(1000)
            .query_async(conn)
            .await?;
        out.extend(batch);
        if next == 0 {
            return Ok(());
        }
        cursor = next;
    }
}

/// The primaries of the cluster the first seed URL belongs to, as URLs with
/// the seed's credentials and scheme.
async fn cluster_primaries(seeds: &[String]) -> Result<Vec<String>, AppError> {
    let seed = seeds
        .first()
        .ok_or_else(|| AppError::Cache("no cluster node configured".into()))?;
    let client = redis::Client::open(seed.as_str())?;
    let mut conn = client.get_multiplexed_async_connection().await?;
    let nodes: String = redis::cmd("CLUSTER")
        .arg("NODES")
        .query_async(&mut conn)
        .await?;
    let base = url::Url::parse(seed).map_err(|e| AppError::Cache(e.to_string()))?;
    Ok(parse_cluster_primaries(&nodes)
        .into_iter()
        .filter_map(|(host, port)| {
            let mut url = base.clone();
            url.set_host(Some(&host)).ok()?;
            url.set_port(Some(port)).ok()?;
            Some(url.to_string())
        })
        .collect())
}

/// `host:port` of each healthy primary in `CLUSTER NODES` output
/// (`<id> <host:port@cport[,hostname]> <flags> …`).
fn parse_cluster_primaries(nodes: &str) -> Vec<(String, u16)> {
    nodes
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _id = fields.next()?;
            let addr = fields.next()?;
            let flags = fields.next()?;
            let flags: Vec<&str> = flags.split(',').collect();
            if !flags.contains(&"master") || flags.iter().any(|f| f.starts_with("fail")) {
                return None;
            }
            let host_port = addr.split(['@', ',']).next()?;
            let (host, port) = host_port.rsplit_once(':')?;
            Some((
                host.trim_matches(['[', ']']).to_string(),
                port.parse().ok()?,
            ))
        })
        .collect()
}

/// Copy `keys` from `from` to `to` with their remaining lifetimes
/// (`DUMP`/`RESTORE … REPLACE`); a key that expired meanwhile is skipped.
/// Returns how many were copied.
pub async fn copy_keys(from: &Cache, to: &Cache, keys: &[String]) -> Result<u64, AppError> {
    let mut src = from.get().await?;
    let mut dst = to.get().await?;
    let mut copied = 0;
    for key in keys {
        let payload: Option<Vec<u8>> = redis::cmd("DUMP").arg(key).query_async(&mut src).await?;
        let Some(payload) = payload else { continue };
        let ttl: i64 = redis::cmd("PTTL").arg(key).query_async(&mut src).await?;
        if ttl == -2 {
            continue;
        }
        let _: () = redis::cmd("RESTORE")
            .arg(key)
            .arg(ttl.max(0))
            .arg(payload)
            .arg("REPLACE")
            .query_async(&mut dst)
            .await?;
        copied += 1;
    }
    Ok(copied)
}

/// Delete `keys` one at a time (a cluster refuses multi-key commands across slots).
pub async fn delete_keys(cache: &Cache, keys: &[String]) -> Result<(), AppError> {
    let mut conn = cache.get().await?;
    for key in keys {
        let _: () = conn.del(key).await?;
    }
    Ok(())
}

/// `REDIS_URL`, plus `REDIS_URL_<REGION>` for each region that has one.
/// Tenant keys are routed once [`Cache::route_with`] attaches placements.
pub fn connect(config: &Config) -> Result<Cache, AppError> {
    let home = Backend::connect(&config.redis_url, config.redis_pool_max)?;
    let mut regions = vec![];
    for region in &config.data_regions {
        if let Some(url) = &region.redis_url {
            regions.push((
                Arc::<str>::from(region.name.as_str()),
                Backend::connect(url, config.redis_pool_max)?,
            ));
        }
    }
    Ok(Cache {
        home,
        regions: Arc::from(regions),
        locator: None,
    })
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

    #[test]
    fn cluster_nodes_output_yields_the_healthy_primaries() {
        let nodes = "\
07c3 10.0.0.1:7000@17000 myself,master - 0 0 1 connected 0-5460
67ed 10.0.0.2:7001@17001,node-b master - 0 0 2 connected 5461-10922
292f 10.0.0.3:7002@17002 master,fail - 0 0 3 disconnected
e7d1 10.0.0.4:7003@17003 slave 07c3 0 0 1 connected
";
        assert_eq!(
            parse_cluster_primaries(nodes),
            vec![("10.0.0.1".into(), 7000), ("10.0.0.2".into(), 7001)]
        );
    }

    #[test]
    fn tenant_keys_are_recognised_and_nothing_else() {
        let t = Uuid::now_v7();
        assert_eq!(
            key_tenant(keys::sso_session(t, Uuid::nil()).as_bytes()),
            Some(t)
        );
        assert_eq!(key_tenant(format!("ridm:t:{t}").as_bytes()), Some(t));
        assert_eq!(key_tenant(keys::tenant_by_id(t).as_bytes()), None);
        assert_eq!(key_tenant(b"ridm:lock:cleanup"), None);
        assert_eq!(key_tenant(format!("ridm:t:{t}x:y").as_bytes()), None);
        assert_eq!(key_tenant(b"ridm:t:not-a-uuid:x"), None);
    }

    #[test]
    fn commands_route_by_their_key_and_scripts_by_their_first_key() {
        let mut get = redis::cmd("GET");
        get.arg("ridm:t:k");
        assert_eq!(routing_key(&get), Some(&b"ridm:t:k"[..]));
        let mut eval = redis::cmd("EVALSHA");
        eval.arg("abc").arg(1).arg("ridm:t:k").arg(60);
        assert_eq!(routing_key(&eval), Some(&b"ridm:t:k"[..]));
        let mut none = redis::cmd("eval");
        none.arg("return 1").arg(0);
        assert_eq!(routing_key(&none), None);
        assert_eq!(routing_key(&redis::cmd("PING")), None);
    }
}
