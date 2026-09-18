//! Initial access tokens for dynamic client registration (tenant-bound
//! transactions).

use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::InitialAccessToken;

const COLUMNS: &str = "id, tenant_id, description, token_hash, max_uses, uses, expires_at, \
    last_used_at, revoked_at, created_at";

pub struct NewRow<'a> {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub description: Option<&'a str>,
    pub token_hash: &'a [u8],
    pub max_uses: Option<i32>,
    pub expires_at: Option<DateTime<Utc>>,
}

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    row: NewRow<'_>,
) -> Result<InitialAccessToken, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO dcr_initial_access_tokens \
         (id, tenant_id, description, token_hash, max_uses, expires_at) VALUES (",
    );
    let mut s = qb.separated(", ");
    s.push_bind(row.id)
        .push_bind(row.tenant_id)
        .push_bind(row.description)
        .push_bind(row.token_hash.to_vec())
        .push_bind(row.max_uses)
        .push_bind(row.expires_at);
    qb.push(") RETURNING ").push(COLUMNS);
    qb.build_query_as::<InitialAccessToken>()
        .fetch_one(exec)
        .await
}

/// Newest first, spent and revoked ones included.
pub async fn list<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
) -> Result<Vec<InitialAccessToken>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM dcr_initial_access_tokens WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" ORDER BY created_at DESC, id DESC");
    qb.build_query_as::<InitialAccessToken>()
        .fetch_all(exec)
        .await
}

/// Spend one use of the token behind `token_hash`, atomically: `Ok(false)`
/// when it is unknown, revoked, expired or used up.
pub async fn consume<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    token_hash: &[u8],
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE dcr_initial_access_tokens SET uses = uses + 1, last_used_at = now() \
         WHERE tenant_id = $1 AND token_hash = $2 AND revoked_at IS NULL \
           AND (expires_at IS NULL OR expires_at > now()) \
           AND (max_uses IS NULL OR uses < max_uses)",
    )
    .bind(tenant_id)
    .bind(token_hash)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// `Ok(false)` when unknown or already revoked.
pub async fn revoke<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE dcr_initial_access_tokens SET revoked_at = now() \
         WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}
