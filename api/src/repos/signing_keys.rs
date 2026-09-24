//! Tenant-scoped signing key queries (run inside a tenant-bound transaction).

use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{KeyStatus, SigningAlg, SigningKey};

const COLUMNS: &str = "id, tenant_id, kid, alg, public_jwk, private_key_enc, key_version, status, \
    not_before, expires_at, created_at, updated_at";

#[allow(clippy::too_many_arguments)]
pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    kid: &str,
    alg: SigningAlg,
    public_jwk: &serde_json::Value,
    private_key_enc: &[u8],
    key_version: i32,
    status: KeyStatus,
    not_before: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<SigningKey, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO signing_keys (id, tenant_id, kid, alg, public_jwk, private_key_enc, \
         key_version, status, not_before, expires_at) VALUES (",
    );
    let mut sep = qb.separated(", ");
    sep.push_bind(id)
        .push_bind(tenant_id)
        .push_bind(kid)
        .push_bind(alg)
        .push_bind(public_jwk.clone())
        .push_bind(private_key_enc.to_vec())
        .push_bind(key_version)
        .push_bind(status)
        .push_bind(not_before)
        .push_bind(expires_at);
    qb.push(") RETURNING ").push(COLUMNS);
    qb.build_query_as::<SigningKey>().fetch_one(exec).await
}

pub async fn find_by_id<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<SigningKey>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM signing_keys WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id);
    qb.build_query_as::<SigningKey>().fetch_optional(exec).await
}

pub async fn find_by_kid<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    kid: &str,
) -> Result<Option<SigningKey>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM signing_keys WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND kid = ")
        .push_bind(kid);
    qb.build_query_as::<SigningKey>().fetch_optional(exec).await
}

/// All keys of a tenant, newest first; optionally only one status.
pub async fn list<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    status: Option<KeyStatus>,
) -> Result<Vec<SigningKey>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM signing_keys WHERE tenant_id = ")
        .push_bind(tenant_id);
    if let Some(s) = status {
        qb.push(" AND status = ").push_bind(s);
    }
    qb.push(" ORDER BY created_at DESC, id DESC");
    qb.build_query_as::<SigningKey>().fetch_all(exec).await
}

/// Keys that belong in the JWKS document (pending, active, retiring).
pub async fn list_published<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
) -> Result<Vec<SigningKey>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM signing_keys WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND status IN ('pending', 'active', 'retiring') ORDER BY created_at DESC, id DESC");
    qb.build_query_as::<SigningKey>().fetch_all(exec).await
}

/// The newest active key for an algorithm whose validity window has started.
pub async fn find_active<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    alg: SigningAlg,
) -> Result<Option<SigningKey>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM signing_keys WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND alg = ")
        .push_bind(alg)
        .push(" AND status = 'active' AND not_before <= now() ORDER BY not_before DESC, id DESC LIMIT 1");
    qb.build_query_as::<SigningKey>().fetch_optional(exec).await
}

pub async fn set_status<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    status: KeyStatus,
    expires_at: Option<DateTime<Utc>>,
) -> Result<Option<SigningKey>, sqlx::Error> {
    let mut qb = QueryBuilder::new("UPDATE signing_keys SET status = ");
    qb.push_bind(status);
    if let Some(e) = expires_at {
        qb.push(", expires_at = ").push_bind(e);
    }
    qb.push(" WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id)
        .push(" RETURNING ")
        .push(COLUMNS);
    qb.build_query_as::<SigningKey>().fetch_optional(exec).await
}

/// Replace the encrypted private key (master-key rotation).
pub async fn update_private_key<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    private_key_enc: &[u8],
    key_version: i32,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE signing_keys SET private_key_enc = $3, key_version = $4 \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(private_key_enc)
    .bind(key_version)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn delete<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("DELETE FROM signing_keys WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// What the key housekeeping job needs to know of one tenant's keys.
#[derive(Debug, sqlx::FromRow)]
pub struct KeyHousekeeping {
    pub tenant_id: Uuid,
    /// A retiring key has reached its expiry (it is due to be revoked).
    pub retiring_expired: bool,
    /// When the oldest active key started signing.
    pub oldest_active: Option<DateTime<Utc>>,
}

/// [`KeyHousekeeping`] of every tenant with an active or retiring key in
/// this database, in one read.
pub async fn housekeeping<'e>(
    exec: impl PgExecutor<'e>,
) -> Result<Vec<KeyHousekeeping>, sqlx::Error> {
    sqlx::query_as(
        "SELECT tenant_id, \
                COALESCE(bool_or(status = 'retiring' AND expires_at <= now()), false) \
                    AS retiring_expired, \
                min(not_before) FILTER (WHERE status = 'active') AS oldest_active \
         FROM signing_keys WHERE status IN ('active', 'retiring') GROUP BY tenant_id",
    )
    .fetch_all(exec)
    .await
}
