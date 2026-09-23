//! `master_key_generations`: the wrapped data keys. Deployment-wide, no RLS.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GenerationRow {
    pub version: i32,
    pub backend: String,
    pub key_ref: String,
    pub wrapped_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

/// A generation as the status report shows it.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct GenerationInfo {
    pub version: u32,
    /// `env` for `MASTER_KEY` / `MASTER_KEY_PREVIOUS`, else the custody
    /// backend that wrapped it.
    pub backend: String,
    /// The backend key that wrapped it; absent for `env`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    /// Whether this node holds the data key (it can decrypt rows under it).
    pub loaded: bool,
}

/// The advisory lock that serialises generation creation across nodes.
const CREATE_LOCK: &str = "ridm:master-key-generations";

pub async fn all(db: &PgPool) -> Result<Vec<GenerationRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT version, backend, key_ref, wrapped_key, created_at \
         FROM master_key_generations ORDER BY version",
    )
    .fetch_all(db)
    .await
}

pub async fn get(db: &PgPool, version: u32) -> Result<Option<GenerationRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT version, backend, key_ref, wrapped_key, created_at \
         FROM master_key_generations WHERE version = $1",
    )
    .bind(version as i32)
    .fetch_optional(db)
    .await
}

/// Versions above `after`, newest last: what a node has not seen yet.
pub async fn newer_than(db: &PgPool, after: u32) -> Result<Vec<u32>, sqlx::Error> {
    let rows: Vec<i32> = sqlx::query_scalar(
        "SELECT version FROM master_key_generations WHERE version > $1 ORDER BY version",
    )
    .bind(after as i32)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|v| v as u32).collect())
}

/// Hold the creation lock for the life of `tx`.
pub async fn lock(tx: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(CREATE_LOCK)
        .execute(tx)
        .await
        .map(|_| ())
}

/// The newest generation of `backend`, and the highest version of any.
pub async fn latest(
    tx: &mut sqlx::PgConnection,
    backend: &str,
) -> Result<(Option<u32>, u32), sqlx::Error> {
    let (of_backend, any): (Option<i32>, Option<i32>) = sqlx::query_as(
        "SELECT max(version) FILTER (WHERE backend = $1), max(version) FROM master_key_generations",
    )
    .bind(backend)
    .fetch_one(tx)
    .await?;
    Ok((of_backend.map(|v| v as u32), any.unwrap_or(0) as u32))
}

pub async fn insert(
    tx: &mut sqlx::PgConnection,
    version: u32,
    backend: &str,
    key_ref: &str,
    wrapped: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO master_key_generations (version, backend, key_ref, wrapped_key) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(version as i32)
    .bind(backend)
    .bind(key_ref)
    .bind(wrapped)
    .execute(tx)
    .await
    .map(|_| ())
}
