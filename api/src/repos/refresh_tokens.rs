//! Tenant-scoped refresh token queries (run inside a tenant-bound transaction).

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::models::RefreshToken;

const COLUMNS: &str = "id, tenant_id, family_id, client_id, user_id, session_id, token_hash, scopes, \
    audiences, expires_at, consumed_at, revoked_at, created_at";

#[allow(clippy::too_many_arguments)]
pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    family_id: Uuid,
    client_id: &str,
    user_id: Option<Uuid>,
    session_id: Option<Uuid>,
    token_hash: &[u8],
    scopes: &[String],
    audiences: &[String],
    expires_at: DateTime<Utc>,
) -> Result<RefreshToken, sqlx::Error> {
    sqlx::query_as::<_, RefreshToken>(
        "INSERT INTO refresh_tokens (id, tenant_id, family_id, client_id, user_id, session_id, \
         token_hash, scopes, audiences, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         RETURNING id, tenant_id, family_id, client_id, user_id, session_id, token_hash, scopes, \
         audiences, expires_at, consumed_at, revoked_at, created_at",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(family_id)
    .bind(client_id)
    .bind(user_id)
    .bind(session_id)
    .bind(token_hash)
    .bind(scopes)
    .bind(audiences)
    .bind(expires_at)
    .fetch_one(exec)
    .await
}

/// Lock the row for update so concurrent rotations of the same token serialize.
pub async fn find_by_hash_for_update<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    token_hash: &[u8],
) -> Result<Option<RefreshToken>, sqlx::Error> {
    let mut qb = sqlx::QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM refresh_tokens WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND token_hash = ")
        .push_bind(token_hash.to_vec())
        .push(" FOR UPDATE");
    qb.build_query_as::<RefreshToken>()
        .fetch_optional(exec)
        .await
}

pub async fn mark_consumed<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE refresh_tokens SET consumed_at = now() WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(())
}

pub async fn revoke_by_id<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now() WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(exec)
    .await?
    .rows_affected())
}

pub async fn revoke_family<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    family_id: Uuid,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now() WHERE tenant_id = $1 AND family_id = $2 AND revoked_at IS NULL",
    )
    .bind(tenant_id)
    .bind(family_id)
    .execute(exec)
    .await?
    .rows_affected())
}

pub async fn revoke_for_user<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: Option<&str>,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2 \
         AND ($3::text IS NULL OR client_id = $3) AND revoked_at IS NULL",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(client_id)
    .execute(exec)
    .await?
    .rows_affected())
}

pub async fn revoke_for_session<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    session_id: Uuid,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now() WHERE tenant_id = $1 AND session_id = $2 AND revoked_at IS NULL",
    )
    .bind(tenant_id)
    .bind(session_id)
    .execute(exec)
    .await?
    .rows_affected())
}

/// Live (unconsumed, unrevoked, unexpired) tokens of a user, for listing.
pub async fn list_live_for_user<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<RefreshToken>, sqlx::Error> {
    let mut qb = sqlx::QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM refresh_tokens WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND user_id = ")
        .push_bind(user_id)
        .push(" AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > now() ORDER BY created_at DESC");
    qb.build_query_as::<RefreshToken>().fetch_all(exec).await
}

/// Delete rows that can never be used again and are older than `older_than`.
pub async fn purge<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    older_than: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "DELETE FROM refresh_tokens WHERE tenant_id = $1 AND (expires_at < $2 \
         OR (revoked_at IS NOT NULL AND revoked_at < $2) OR (consumed_at IS NOT NULL AND consumed_at < $2))",
    )
    .bind(tenant_id)
    .bind(older_than)
    .execute(exec)
    .await?
    .rows_affected())
}
