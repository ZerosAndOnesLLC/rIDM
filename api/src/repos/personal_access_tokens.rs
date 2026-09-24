//! Personal access tokens (tenant-bound transactions, except the lookup by
//! hash a bearer token needs before its tenant is known).

use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::PersonalAccessToken;

const COLUMNS: &str = "id, tenant_id, user_id, name, token_hash, scopes, expires_at, last_used_at, \
     revoked_at, created_at";

/// A token to store (its hash, never the token).
pub struct NewToken<'a> {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: &'a str,
    pub token_hash: &'a [u8],
    pub scopes: &'a [String],
    pub expires_at: Option<DateTime<Utc>>,
}

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    t: NewToken<'_>,
) -> Result<PersonalAccessToken, sqlx::Error> {
    let NewToken {
        id,
        user_id,
        name,
        token_hash,
        scopes,
        expires_at,
    } = t;
    let mut qb = QueryBuilder::new(
        "INSERT INTO personal_access_tokens (id, tenant_id, user_id, name, token_hash, scopes, expires_at) VALUES (",
    );
    let mut s = qb.separated(", ");
    s.push_bind(id)
        .push_bind(tenant_id)
        .push_bind(user_id)
        .push_bind(name)
        .push_bind(token_hash.to_vec())
        .push_bind(scopes)
        .push_bind(expires_at);
    qb.push(") RETURNING ").push(COLUMNS);
    qb.build_query_as::<PersonalAccessToken>()
        .fetch_one(exec)
        .await
}

/// A user's tokens, newest first, revoked ones included.
pub async fn list_for_user<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<PersonalAccessToken>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM personal_access_tokens WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND user_id = ")
        .push_bind(user_id)
        .push(" ORDER BY created_at DESC, id DESC");
    qb.build_query_as::<PersonalAccessToken>()
        .fetch_all(exec)
        .await
}

/// The token behind a hash, whatever its tenant (the caller runs this in a
/// bypass transaction and checks the tenant afterwards).
pub async fn find_by_hash<'e>(
    exec: impl PgExecutor<'e>,
    token_hash: &[u8],
) -> Result<Option<PersonalAccessToken>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM personal_access_tokens WHERE token_hash = ")
        .push_bind(token_hash.to_vec());
    qb.build_query_as::<PersonalAccessToken>()
        .fetch_optional(exec)
        .await
}

pub async fn touch<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE personal_access_tokens SET last_used_at = now() WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(exec)
    .await?;
    Ok(())
}

/// Revoke one of a user's tokens; returns its hash (to evict it from the
/// cache), or `None` when it is not theirs or already revoked.
pub async fn revoke<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    id: Uuid,
) -> Result<Option<Vec<u8>>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE personal_access_tokens SET revoked_at = now() \
         WHERE tenant_id = $1 AND user_id = $2 AND id = $3 AND revoked_at IS NULL \
         RETURNING token_hash",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(id)
    .fetch_optional(exec)
    .await
}

/// Every live token of a user (account deletion, admin sign-out everywhere);
/// returns their hashes.
pub async fn revoke_all_for_user<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<Vec<u8>>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE personal_access_tokens SET revoked_at = now() \
         WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL RETURNING token_hash",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_all(exec)
    .await
}
