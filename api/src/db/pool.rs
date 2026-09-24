//! Postgres connection pool.

use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, PgPool};

use super::{Database, Db};
use crate::config::{Config, HOME_REGION};

/// The home database and every region in `DATA_REGIONS`, each with the
/// pool read-heavy admin queries use: its replica when one is configured
/// (`DATABASE_READ_URL`, `DATABASE_READ_URL_<REGION>`), else the primary.
/// The home database must answer; a region's pools connect when first used,
/// so a node starts while a region is down (its tenants fail until it is back).
pub async fn connect(config: &Config) -> Result<Db, sqlx::Error> {
    let mut databases = vec![
        database(
            config,
            HOME_REGION,
            &config.database_url,
            config.database_read_url.as_deref(),
        )
        .await?,
    ];
    for region in &config.data_regions {
        databases.push(
            database(
                config,
                &region.name,
                &region.database_url,
                region.database_read_url.as_deref(),
            )
            .await?,
        );
    }
    Ok(Db::new(databases))
}

async fn database(
    config: &Config,
    name: &str,
    url: &str,
    read_url: Option<&str>,
) -> Result<Database, sqlx::Error> {
    let (app, app_read) = if name == HOME_REGION {
        ("ridm-api".to_string(), "ridm-api-read".to_string())
    } else {
        (format!("ridm-api-{name}"), format!("ridm-api-{name}-read"))
    };
    let lazy = name != HOME_REGION;
    let primary = connect_url(config, url, &app, lazy).await?;
    let read = match read_url {
        Some(url) => connect_url(config, url, &app_read, lazy).await?,
        None => primary.clone(),
    };
    Ok(Database {
        name: name.into(),
        primary,
        read,
    })
}

async fn connect_url(
    config: &Config,
    url: &str,
    name: &str,
    lazy: bool,
) -> Result<PgPool, sqlx::Error> {
    let options = url
        .parse::<PgConnectOptions>()?
        .application_name(name)
        .log_slow_statements(tracing::log::LevelFilter::Warn, Duration::from_millis(250));

    let pool = PgPoolOptions::new()
        .min_connections(config.db_pool_min)
        .max_connections(config.db_pool_max)
        .acquire_timeout(Duration::from_millis(config.db_acquire_timeout_ms))
        .idle_timeout(Duration::from_secs(600))
        .max_lifetime(Duration::from_secs(1800));
    if lazy {
        return Ok(pool.connect_lazy_with(options));
    }
    pool.connect_with(options).await
}

/// Embedded migrations (`api/migrations`). Applied at startup when
/// `MIGRATE_ON_START=true`, or with `sqlx migrate run --source api/migrations`.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Apply pending migrations. Safe to call concurrently from several nodes:
/// sqlx takes an advisory lock.
pub async fn migrate(db: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    MIGRATOR.run(db).await
}

/// Versions of the migrations the database has applied successfully. Only
/// reads `_sqlx_migrations` (a missing table means none is applied), so the
/// DML-only application role can ask.
async fn applied_migrations(db: &PgPool) -> Result<Vec<i64>, sqlx::Error> {
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
pub async fn pending_migrations(db: &PgPool) -> Result<usize, sqlx::Error> {
    let applied = applied_migrations(db).await?;
    Ok(MIGRATOR
        .iter()
        .filter(|m| m.migration_type.is_up_migration() && !applied.contains(&m.version))
        .count())
}

/// Applied migrations this binary does not embed, oldest first: the schema
/// was migrated by a newer release, and this one is running on it after a
/// rollback or during a rolling upgrade.
pub async fn unknown_migrations(db: &PgPool) -> Result<Vec<i64>, sqlx::Error> {
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
pub async fn migrate_pending(db: &PgPool) -> Result<usize, sqlx::migrate::MigrateError> {
    let pending = pending_migrations(db).await?;
    if pending > 0 {
        migrate(db).await?;
    }
    Ok(pending)
}

/// [`migrate`] on every database, home first: a region runs the same schema.
/// Stops at the first that fails (`ridm-api migrate` reports it).
pub async fn migrate_all(db: &Db) -> Result<(), sqlx::migrate::MigrateError> {
    for database in db.all() {
        migrate(&database.primary).await?;
    }
    Ok(())
}

/// [`migrate_pending`] on every database at start-up; the migrations
/// applied in all. The home database must succeed; a region that fails is
/// logged and left for `ridm-api migrate` once it is back.
pub async fn migrate_pending_all(db: &Db) -> Result<usize, sqlx::migrate::MigrateError> {
    let mut applied = 0;
    for database in db.all() {
        match migrate_pending(&database.primary).await {
            Ok(n) => applied += n,
            Err(err) if !database.is_home() => region_failed(database, &err),
            Err(err) => return Err(err),
        }
    }
    Ok(applied)
}

/// [`pending_migrations`] summed over every database that answers (a region
/// that does not is logged, as in [`migrate_pending_all`]).
pub async fn pending_migrations_all(db: &Db) -> Result<usize, sqlx::Error> {
    let mut pending = 0;
    for database in db.all() {
        match pending_migrations(&database.primary).await {
            Ok(n) => pending += n,
            Err(err) if !database.is_home() => region_failed(database, &err),
            Err(err) => return Err(err),
        }
    }
    Ok(pending)
}

/// [`unknown_migrations`] of every database that answers, oldest first,
/// each once.
pub async fn unknown_migrations_all(db: &Db) -> Result<Vec<i64>, sqlx::Error> {
    let mut unknown = vec![];
    for database in db.all() {
        match unknown_migrations(&database.primary).await {
            Ok(v) => unknown.extend(v),
            Err(err) if !database.is_home() => region_failed(database, &err),
            Err(err) => return Err(err),
        }
    }
    unknown.sort_unstable();
    unknown.dedup();
    Ok(unknown)
}

fn region_failed(database: &Database, err: &dyn std::fmt::Display) {
    tracing::error!(
        region = %database.name,
        error = %err,
        "data region unreachable at start-up; its tenants fail until it is back"
    );
}

/// Cheap liveness probe used by `/readyz`.
pub async fn ping(db: &PgPool) -> Result<(), sqlx::Error> {
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
