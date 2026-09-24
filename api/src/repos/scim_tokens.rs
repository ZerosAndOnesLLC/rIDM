//! SCIM provisioning tokens (tenant-bound transactions, except the lookup by
//! hash a bearer token needs before its tenant is known).

use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::ScimToken;

const COLUMNS: &str =
    "id, tenant_id, name, token_hash, expires_at, last_used_at, revoked_at, created_at";

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    name: &str,
    token_hash: &[u8],
    expires_at: Option<DateTime<Utc>>,
) -> Result<ScimToken, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO scim_tokens (id, tenant_id, name, token_hash, expires_at) VALUES (",
    );
    let mut s = qb.separated(", ");
    s.push_bind(id)
        .push_bind(tenant_id)
        .push_bind(name)
        .push_bind(token_hash.to_vec())
        .push_bind(expires_at);
    qb.push(") RETURNING ").push(COLUMNS);
    qb.build_query_as::<ScimToken>().fetch_one(exec).await
}

/// Live tokens (at most `services::limits::SCIM_TOKENS`), then the most
/// recently created revoked ones, newest first within each: 200 rows at most,
/// so years of rotation do not grow the list.
pub async fn list<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
) -> Result<Vec<ScimToken>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM scim_tokens WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" ORDER BY revoked_at IS NOT NULL, created_at DESC, id DESC LIMIT 200");
    qb.build_query_as::<ScimToken>().fetch_all(exec).await
}

/// The token behind a hash, whatever its tenant (bypass transaction).
pub async fn find_by_hash<'e>(
    exec: impl PgExecutor<'e>,
    token_hash: &[u8],
) -> Result<Option<ScimToken>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM scim_tokens WHERE token_hash = ")
        .push_bind(token_hash.to_vec());
    qb.build_query_as::<ScimToken>().fetch_optional(exec).await
}

pub async fn touch<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE scim_tokens SET last_used_at = now() WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(())
}

/// `Ok(false)` when unknown or already revoked.
pub async fn revoke<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE scim_tokens SET revoked_at = now() WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}
