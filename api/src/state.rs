//! Shared application state injected into every handler.

use std::sync::Arc;

use ridm_core::events::EventBus;

use crate::cache::{Cache, CacheLayer};
use crate::config::Config;
use crate::db::Db;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Db,
    /// Raw Redis pool for sessions, flows, rate limits and other keyed state.
    pub redis: Cache,
    /// Read-through cache (L1 + Redis) for hot objects such as tenants.
    pub cache: CacheLayer,
    pub events: EventBus,
}

impl AppState {
    pub fn new(config: Config, db: Db, redis: Cache) -> Self {
        let cache = CacheLayer::new(redis.clone(), &config.redis_url);
        Self {
            config: Arc::new(config),
            db,
            redis,
            cache,
            events: EventBus::default(),
        }
    }
}
