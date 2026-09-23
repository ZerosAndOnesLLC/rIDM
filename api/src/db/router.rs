//! Per-tenant database routing (data residency).
//!
//! A deployment has a home database (`DATABASE_URL`) and optionally regional
//! ones (`DATA_REGIONS`). The home database holds the `tenants` registry;
//! a tenant whose `data_region` names a region keeps every tenant-scoped row
//! in that region's database. [`Db::locate`] answers which database a tenant
//! lives in, from the registry, and [`super::tenant_tx`] opens its
//! transactions there, so no query needs to know about regions.
//!
//! Placements are cached per node for [`PLACEMENT_TTL`]. A move marks the
//! tenant `relocating` first and waits longer than that before copying, so
//! by then every node refuses the tenant rather than writing to the source.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use sqlx::PgPool;
use uuid::Uuid;

use crate::config::HOME_REGION;
use crate::models::MASTER_TENANT_ID;

/// How long a node trusts a tenant's cached placement.
pub const PLACEMENT_TTL: Duration = Duration::from_secs(5);

/// One database a tenant can live in: its primary and the pool read-only
/// listings use (a replica, or the primary again).
pub struct Database {
    pub name: Arc<str>,
    pub primary: PgPool,
    pub read: PgPool,
}

impl Database {
    pub fn is_home(&self) -> bool {
        &*self.name == HOME_REGION
    }

    /// The name stored in `tenants.data_region`: `None` for the home database.
    pub fn region(&self) -> Option<&str> {
        (!self.is_home()).then_some(&*self.name)
    }
}

/// Why a tenant's transaction could not be routed.
#[derive(Debug, thiserror::Error)]
pub enum Unroutable {
    #[error("the tenant is being moved to another region; try again shortly")]
    Relocating,
    #[error("the tenant's region `{0}` is not configured on this node")]
    UnknownRegion(String),
}

impl From<Unroutable> for sqlx::Error {
    fn from(err: Unroutable) -> Self {
        sqlx::Error::Configuration(Box::new(err))
    }
}

/// The [`Unroutable`] inside a database error, if that is what it is.
pub fn unroutable(err: &sqlx::Error) -> Option<&Unroutable> {
    match err {
        sqlx::Error::Configuration(inner) => inner.downcast_ref::<Unroutable>(),
        _ => None,
    }
}

#[derive(Clone, Copy)]
struct Placement {
    index: usize,
    relocating: bool,
    fetched: Instant,
}

/// The home database and the regional ones. Cheap to clone.
#[derive(Clone)]
pub struct Db {
    inner: Arc<Inner>,
}

struct Inner {
    /// Home first, then the regions in `DATA_REGIONS` order.
    databases: Vec<Database>,
    placements: RwLock<HashMap<Uuid, Placement>>,
}

impl From<PgPool> for Db {
    fn from(pool: PgPool) -> Self {
        Self::single(pool)
    }
}

impl Db {
    /// A deployment without regions: everything in `pool`.
    pub fn single(pool: PgPool) -> Self {
        Self::new(vec![Database {
            name: HOME_REGION.into(),
            read: pool.clone(),
            primary: pool,
        }])
    }

    /// `databases[0]` must be the home database.
    pub fn new(databases: Vec<Database>) -> Self {
        assert!(
            databases.first().is_some_and(Database::is_home),
            "the home database comes first"
        );
        Self {
            inner: Arc::new(Inner {
                databases,
                placements: RwLock::new(HashMap::new()),
            }),
        }
    }

    /// The home database: the tenant registry, master-key generations,
    /// and every tenant without a region.
    pub fn home(&self) -> &PgPool {
        &self.inner.databases[0].primary
    }

    /// Every database, home first. Work that spans tenants (jobs, master-key
    /// rotation, migrations) runs over each.
    pub fn all(&self) -> &[Database] {
        &self.inner.databases
    }

    /// Whether any region is configured besides the home database.
    pub fn is_regional(&self) -> bool {
        self.inner.databases.len() > 1
    }

    /// The database for `tenants.data_region` (`None`: home), if configured.
    pub fn get(&self, region: Option<&str>) -> Option<&Database> {
        let name = region.unwrap_or(HOME_REGION);
        self.inner.databases.iter().find(|d| &*d.name == name)
    }

    /// The database `tenant_id` lives in. Fails while the tenant is being
    /// moved, or when its region is not configured here: its rows must
    /// never be written anywhere else.
    pub async fn locate(&self, tenant_id: Uuid) -> Result<&Database, sqlx::Error> {
        if !self.is_regional() || tenant_id == MASTER_TENANT_ID {
            return Ok(&self.inner.databases[0]);
        }
        let cached = self
            .inner
            .placements
            .read()
            .ok()
            .and_then(|m| m.get(&tenant_id).copied());
        let placement = match cached.filter(|p| p.fetched.elapsed() < PLACEMENT_TTL) {
            Some(p) => p,
            None => match self.fetch(tenant_id).await? {
                Some(p) => p,
                // Gone from the registry: a tenant this node knew was just
                // deleted, and what is still recorded for it (its audit
                // trail, which outlives it) goes where it lived.
                None => match cached {
                    Some(p) if !p.relocating => p,
                    // Never known: nothing of it exists anywhere, and the
                    // home database is where a lookup finds that out.
                    _ => return Ok(&self.inner.databases[0]),
                },
            },
        };
        if placement.relocating {
            return Err(Unroutable::Relocating.into());
        }
        Ok(&self.inner.databases[placement.index])
    }

    async fn fetch(&self, tenant_id: Uuid) -> Result<Option<Placement>, sqlx::Error> {
        let row: Option<(Option<String>, bool)> =
            sqlx::query_as("SELECT data_region, relocating FROM tenants WHERE id = $1")
                .bind(tenant_id)
                .fetch_optional(self.home())
                .await?;
        let Some((region, relocating)) = row else {
            return Ok(None);
        };
        let index = self
            .inner
            .databases
            .iter()
            .position(|d| d.region() == region.as_deref())
            .ok_or_else(|| Unroutable::UnknownRegion(region.unwrap_or_default()))?;
        let placement = Placement {
            index,
            relocating,
            fetched: Instant::now(),
        };
        if let Ok(mut map) = self.inner.placements.write() {
            map.insert(tenant_id, placement);
        }
        Ok(Some(placement))
    }

    /// Close every pool (a one-shot command or test done with them).
    pub async fn close(&self) {
        for d in self.all() {
            d.primary.close().await;
            d.read.close().await;
        }
    }

    /// Drop this node's cached placement of `tenant_id` (after a move; a
    /// deleted tenant keeps its last one, see [`Db::locate`]).
    pub fn forget(&self, tenant_id: Uuid) {
        if let Ok(mut map) = self.inner.placements.write() {
            map.remove(&tenant_id);
        }
    }

    /// Tenants being moved right now. Jobs that pick work across tenants
    /// leave theirs alone until the move is done.
    pub async fn relocating(&self) -> Result<Vec<Uuid>, sqlx::Error> {
        if !self.is_regional() {
            return Ok(vec![]);
        }
        sqlx::query_scalar("SELECT id FROM tenants WHERE relocating")
            .fetch_all(self.home())
            .await
    }
}
