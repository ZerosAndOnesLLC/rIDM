//! Postgres connection pool.

use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, PgPool};

use crate::config::Config;

pub type Db = PgPool;

pub async fn connect(config: &Config) -> Result<Db, sqlx::Error> {
    connect_url(config, &config.database_url, "ridm-api").await
}

/// The pool read-heavy admin queries use: a replica when
/// `DATABASE_READ_URL` is set, otherwise the primary itself.
pub async fn connect_read(config: &Config, primary: &Db) -> Result<Db, sqlx::Error> {
    match &config.database_read_url {
        Some(url) => connect_url(config, url, "ridm-api-read").await,
        None => Ok(primary.clone()),
    }
}

async fn connect_url(config: &Config, url: &str, name: &str) -> Result<Db, sqlx::Error> {
    let options = url
        .parse::<PgConnectOptions>()?
        .application_name(name)
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

/// Embedded migrations (`api/migrations`). Applied at startup when
/// `MIGRATE_ON_START=true`, or with `sqlx migrate run --source api/migrations`.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Apply pending migrations. Safe to call concurrently from several nodes:
/// sqlx takes an advisory lock.
pub async fn migrate(db: &Db) -> Result<(), sqlx::migrate::MigrateError> {
    MIGRATOR.run(db).await
}

/// Versions of the migrations the database has applied successfully. Only
/// reads `_sqlx_migrations` (a missing table means none is applied), so the
/// DML-only application role can ask.
async fn applied_migrations(db: &Db) -> Result<Vec<i64>, sqlx::Error> {
    match sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success")
        .fetch_all(db)
        .await
    {
        Ok(v) => Ok(v),
        Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("42P01") => Ok(vec![]),
        Err(e) => Err(e),
    }
}

/// How many embedded migrations the database has not applied yet.
pub async fn pending_migrations(db: &Db) -> Result<usize, sqlx::Error> {
    let applied = applied_migrations(db).await?;
    Ok(MIGRATOR
        .iter()
        .filter(|m| m.migration_type.is_up_migration() && !applied.contains(&m.version))
        .count())
}

/// Applied migrations this binary does not embed, oldest first: the schema
/// was migrated by a newer release, and this one is running on it after a
/// rollback or during a rolling upgrade.
pub async fn unknown_migrations(db: &Db) -> Result<Vec<i64>, sqlx::Error> {
    let applied = applied_migrations(db).await?;
    Ok(not_embedded(&applied, MIGRATOR.iter().map(|m| m.version)))
}

fn not_embedded(applied: &[i64], embedded: impl Iterator<Item = i64>) -> Vec<i64> {
    let embedded: Vec<i64> = embedded.collect();
    let mut unknown: Vec<i64> = applied
        .iter()
        .copied()
        .filter(|v| !embedded.contains(v))
        .collect();
    unknown.sort_unstable();
    unknown
}

/// [`migrate`], but only when something is pending. Applying migrations
/// needs the schema owner (`CREATE` on the schema, for `_sqlx_migrations`
/// itself); skipping an up-to-date database lets the DML-only application
/// role start with `MIGRATE_ON_START=true` once `ridm-api migrate` has run.
pub async fn migrate_pending(db: &Db) -> Result<usize, sqlx::migrate::MigrateError> {
    let pending = pending_migrations(db).await?;
    if pending > 0 {
        migrate(db).await?;
    }
    Ok(pending)
}

/// Cheap liveness probe used by `/readyz`.
pub async fn ping(db: &Db) -> Result<(), sqlx::Error> {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(db)
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_the_binary_lacks_are_reported_in_order() {
        assert_eq!(
            not_embedded(&[1, 2], [1, 2, 3].into_iter()),
            Vec::<i64>::new()
        );
        assert_eq!(
            not_embedded(&[5, 1, 4, 2], [1, 2, 3].into_iter()),
            vec![4, 5]
        );
    }
}
