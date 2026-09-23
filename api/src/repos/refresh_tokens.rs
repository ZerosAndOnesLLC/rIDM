//! Tenant-scoped refresh token queries (run inside a tenant-bound transaction).

use sqlx::PgExecutor;
use uuid::Uuid;

use crate::models::RefreshToken;

const COLUMNS: &str = "id, tenant_id, family_id, client_id, user_id, session_id, token_hash, scopes, \
    audiences, auth_time, amr, acr, org_id, act, expires_at, dpop_jkt, mtls_x5t, consumed_at, revoked_at, created_at";

/// Insert a token row as assembled by the service and return it as stored.
pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    t: &RefreshToken,
) -> Result<RefreshToken, sqlx::Error> {
    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "INSERT INTO refresh_tokens (id, tenant_id, family_id, client_id, user_id, session_id, \
         token_hash, scopes, audiences, auth_time, amr, acr, org_id, expires_at, dpop_jkt, act, \
         mtls_x5t) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) RETURNING ",
    );
    qb.push(COLUMNS);
    sqlx::query_as::<_, RefreshToken>(qb.sql())
        .bind(t.id)
        .bind(t.tenant_id)
        .bind(t.family_id)
        .bind(&t.client_id)
        .bind(t.user_id)
        .bind(t.session_id)
        .bind(&t.token_hash)
        .bind(&t.scopes)
        .bind(&t.audiences)
        .bind(t.auth_time)
        .bind(&t.amr)
        .bind(t.acr.as_deref())
        .bind(t.org_id)
        .bind(t.expires_at)
        .bind(t.dpop_jkt.as_deref())
        .bind(t.act.as_ref())
        .bind(t.mtls_x5t.as_deref())
        .fetch_one(exec)
        .await
}

/// Lock the row for update so concurrent rotations of the same token serialize.
pub async fn find_by_hash_for_update<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    token_hash: &[u8],
) -> Result<Option<RefreshToken>, sqlx::Error> {
    find_by_hash_query(tenant_id, token_hash, " FOR UPDATE")
        .build_query_as::<RefreshToken>()
        .fetch_optional(exec)
        .await
}

/// Read the row without locking it (introspection only looks).
pub async fn find_by_hash<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    token_hash: &[u8],
) -> Result<Option<RefreshToken>, sqlx::Error> {
    find_by_hash_query(tenant_id, token_hash, "")
        .build_query_as::<RefreshToken>()
        .fetch_optional(exec)
        .await
}

fn find_by_hash_query(
    tenant_id: Uuid,
    token_hash: &[u8],
    suffix: &'static str,
) -> sqlx::QueryBuilder<sqlx::Postgres> {
    let mut qb = sqlx::QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM refresh_tokens WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND token_hash = ")
        .push_bind(token_hash.to_vec())
        .push(suffix);
    qb
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
