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
    /// Read-heavy admin queries (listings, statistics): a replica when
    /// configured, else the same pool as `db`.
    pub db_read: Db,
    /// Raw Redis pool for sessions, flows, rate limits and other keyed state.
    pub redis: Cache,
    /// Read-through cache (L1 + Redis) for hot objects such as tenants.
    pub cache: CacheLayer,
    pub events: EventBus,
    pub hasher: Arc<dyn PasswordHasher>,
    pub key_encryptor: Arc<dyn KeyEncryptor>,
    /// Builds per-tenant email/SMS senders; tests swap in mocks.
    pub senders: Arc<dyn crate::messaging::SenderFactory>,
    /// Breached-password lookups; `None` when the deployment switched them off.
    pub breach: Option<Arc<dyn ridm_core::providers::BreachChecker>>,
    /// External destination every audit row is also shipped to.
    pub audit_sink: Option<crate::services::audit_sink::AuditSink>,
}

impl AppState {
    pub fn new(config: Config, db: Db, redis: Cache) -> Self {
        crate::util::outbound::allow_networks(&config.outbound_allow_networks);
        let cache = CacheLayer::new(redis.clone());
        let hasher = Arc::new(crate::services::password::Argon2Hasher::new(config.argon2));
        let key_encryptor =
            Arc::new(crate::services::key_encryptor::MasterKeyEncryptor::from_config(&config));
        let breach = config.breach_check_url.clone().map(|url| {
            Arc::new(crate::services::breach::HibpChecker::new(url))
                as Arc<dyn ridm_core::providers::BreachChecker>
        });
        let audit_sink = config.audit_sink_url.as_ref().and_then(|url| {
            match crate::services::audit_sink::AuditSink::spawn(
                url,
                config
                    .audit_sink_token
                    .as_ref()
                    .map(|t| t.expose().to_string()),
            ) {
                Ok(sink) => Some(sink),
                Err(err) => {
                    tracing::error!(error = %err, "audit sink not started");
                    None
                }
            }
        });
        Self {
            config: Arc::new(config),
            db_read: db.clone(),
            db,
            redis,
            cache,
            events: EventBus::default(),
            hasher,
            key_encryptor,
            senders: Arc::new(crate::messaging::DefaultSenderFactory),
            breach,
            audit_sink,
        }
    }
}
