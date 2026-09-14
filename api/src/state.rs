//! Shared application state injected into every handler.

use std::sync::Arc;

use ridm_core::events::EventBus;

use crate::cache::Cache;
use crate::config::Config;
use crate::db::Db;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Db,
    pub cache: Cache,
    pub events: EventBus,
}
