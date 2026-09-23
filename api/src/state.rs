//! Shared application state injected into every handler.

use std::sync::Arc;

use ridm_core::events::EventBus;
use ridm_core::providers::{KeyEncryptor, PasswordHasher};

use url::Url;

use crate::cache::{Cache, CacheLayer};
use crate::config::{Config, page_url};
use crate::db::Db;
use crate::models::Tenant;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    /// The home database and the regional ones; a tenant's transactions open
    /// on the one it lives in (see [`crate::db::tenant_tx`]).
    pub db: Db,
    /// Raw Redis pool for sessions, flows, rate limits and other keyed state;
    /// a tenant's keys go to its region's Valkey when that has one.
    pub redis: Cache,
    /// Read-through cache (L1 + Redis) for hot objects such as tenants.
    pub cache: CacheLayer,
    pub events: EventBus,
    pub hasher: Arc<dyn PasswordHasher>,
    pub key_encryptor: Arc<dyn KeyEncryptor>,
    /// The encryptor behind `key_encryptor`, for what the trait does not
    /// cover: attaching key custody, creating a generation, status.
    pub master_keys: Arc<crate::key_custody::EnvelopeEncryptor>,
    /// Builds per-tenant email/SMS senders; tests swap in mocks.
    pub senders: Arc<dyn crate::messaging::SenderFactory>,
    /// Breached-password lookups; `None` when the deployment switched them off.
    pub breach: Option<Arc<dyn ridm_core::providers::BreachChecker>>,
    /// External destination every audit row is also shipped to, by
    /// [`crate::jobs::audit_sink`].
    pub audit_sink: Option<crate::services::audit_sink::AuditSink>,
    /// The UI this node serves itself (embedded UI mode); `None` when the
    /// build has none or `UI_URL` points elsewhere.
    pub ui: Option<crate::routes::ui::EmbeddedUi>,
    /// MaxMind database backing the risk policy's location signals; empty
    /// unless `GEOIP_DB` names a readable file.
    pub geoip: crate::services::geoip::GeoDatabase,
}

impl AppState {
    pub fn new(config: Config, db: impl Into<Db>, redis: Cache) -> Self {
        let db = db.into();
        let redis = redis.route_with(db.clone());
        crate::util::outbound::allow_networks(&config.outbound_allow_networks);
        let cache = CacheLayer::new(redis.clone());
        let hasher = Arc::new(crate::services::password::Argon2Hasher::new(config.argon2));
        let master_keys = Arc::new(crate::key_custody::EnvelopeEncryptor::from_config(&config));
        let key_encryptor: Arc<dyn KeyEncryptor> = master_keys.clone();
        let breach = config.breach_check_url.clone().map(|url| {
            Arc::new(crate::services::breach::HibpChecker::new(url))
                as Arc<dyn ridm_core::providers::BreachChecker>
        });
        let audit_sink = config.audit_sink_url.as_ref().and_then(|url| {
            match crate::services::audit_sink::AuditSink::new(
                url,
                config
                    .audit_sink_token
                    .as_ref()
                    .map(|t| t.expose().to_string()),
                config
                    .audit_sink_secret
                    .as_ref()
                    .map(|t| t.expose().to_string()),
                config.audit_sink_ca_file.as_deref(),
            ) {
                Ok(sink) => Some(sink),
                Err(err) => {
                    tracing::error!(error = %err, "audit sink not started");
                    None
                }
            }
        });
        let ui = crate::routes::ui::EmbeddedUi::from_build(&config);
        let geoip = crate::services::geoip::GeoDatabase::from_config(&config.geoip);
        Self {
            config: Arc::new(config),
            db,
            redis,
            cache,
            events: EventBus::default(),
            hasher,
            key_encryptor,
            master_keys,
            senders: Arc::new(crate::messaging::DefaultSenderFactory),
            breach,
            audit_sink,
            ui,
            geoip,
        }
    }
}

impl AppState {
    /// Origin the UI's pages for `tenant` are served on when that is its
    /// custom domain: only a node serving the embedded UI answers the pages
    /// there too (see `middleware::host`). `None`: the pages are under
    /// `UI_URL`.
    pub fn tenant_ui_base(&self, tenant: &Tenant) -> Option<Url> {
        self.ui.as_ref()?;
        let domain = tenant.settings.custom_domain.as_deref()?;
        Url::parse(&format!("https://{domain}/")).ok()
    }

    /// URL of a UI page (`/login/`, `/consent/`, ...) for `tenant`'s users.
    /// A tenant on a custom domain gets its pages on that host when this
    /// node serves the embedded UI, so the session the sign-in pages set
    /// belongs to the host its `/authorize` answers on; otherwise the page
    /// is under `UI_URL`.
    pub fn ui_page(&self, tenant: &Tenant, page: &str, params: &[(&str, &str)]) -> String {
        match self.tenant_ui_base(tenant) {
            Some(base) => page_url(&base, page, params),
            None => self.config.ui_page(page, params),
        }
    }
}
