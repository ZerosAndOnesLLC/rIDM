//! Postgres connection pool.

use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, PgPool};

use crate::config::Config;

pub type Db = PgPool;

pub async fn connect(config: &Config) -> Result<Db, sqlx::Error> {
    let options = config
        .database_url
        .parse::<PgConnectOptions>()?
        .application_name("ridm-api")
        .log_slow_statements(tracing::log::LevelFilter::Warn, Duration::from_millis(250));

    PgPoolOptions::new()
        .min_connections(config.db_pool_min)
        .max_connections(config.db_pool_max)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(600))
        .max_lifetime(Duration::from_secs(1800))
        .connect_with(options)
        .await
}

/// Cheap liveness probe used by `/readyz`.
pub async fn ping(db: &Db) -> Result<(), sqlx::Error> {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(db)
        .await
        .map(|_| ())
}
