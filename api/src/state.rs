//! Shared application state injected into every handler.

use std::sync::Arc;

use ridm_core::events::EventBus;
use ridm_core::providers::{KeyEncryptor, PasswordHasher};

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
    pub hasher: Arc<dyn PasswordHasher>,
    pub key_encryptor: Arc<dyn KeyEncryptor>,
}

impl AppState {
    pub fn new(config: Config, db: Db, redis: Cache) -> Self {
        let cache = CacheLayer::new(redis.clone(), &config.redis_url);
        let hasher = Arc::new(crate::services::password::Argon2Hasher::new(config.argon2));
        let key_encryptor =
            Arc::new(crate::services::key_encryptor::MasterKeyEncryptor::from_config(&config));
        Self {
            config: Arc::new(config),
            db,
            redis,
            cache,
            events: EventBus::default(),
            hasher,
            key_encryptor,
        }
    }
}
