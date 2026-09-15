//! Invitations (run inside a tenant transaction).

use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::Invitation;
use crate::util::cursor::Cursor;

const COLUMNS: &str = "id, tenant_id, email, roles, groups, org_id, token_hash, invited_by, expires_at, \
    accepted_at, revoked_at, created_at";

#[allow(clippy::too_many_arguments)]
pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    email: &str,
    roles: &[Uuid],
    groups: &[Uuid],
    org_id: Option<Uuid>,
    token_hash: &[u8],
    invited_by: Option<Uuid>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<Invitation, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO invitations (id, tenant_id, email, roles, groups, org_id, token_hash, invited_by, expires_at) VALUES (",
    );
    let mut s = qb.separated(", ");
    s.push_bind(id)
        .push_bind(tenant_id)
        .push_bind(email)
        .push_bind(roles.to_vec())
        .push_bind(groups.to_vec())
        .push_bind(org_id)
        .push_bind(token_hash.to_vec())
        .push_bind(invited_by)
        .push_bind(expires_at);
    qb.push(") RETURNING ").push(COLUMNS);
    qb.build_query_as::<Invitation>().fetch_one(exec).await
}

pub async fn find_by_id<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<Invitation>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM invitations WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id);
    qb.build_query_as::<Invitation>().fetch_optional(exec).await
}

pub async fn find_by_token_hash<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    token_hash: &[u8],
) -> Result<Option<Invitation>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM invitations WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND token_hash = ")
        .push_bind(token_hash.to_vec())
        .push(" FOR UPDATE");
    qb.build_query_as::<Invitation>().fetch_optional(exec).await
}

pub async fn mark_accepted<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE invitations SET accepted_at = now() WHERE tenant_id = $1 AND id = $2 AND accepted_at IS NULL AND revoked_at IS NULL",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn revoke<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE invitations SET revoked_at = now() WHERE tenant_id = $1 AND id = $2 AND accepted_at IS NULL AND revoked_at IS NULL",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn set_token_hash<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    token_hash: &[u8],
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE invitations SET token_hash = $3, expires_at = $4 WHERE tenant_id = $1 AND id = $2 AND accepted_at IS NULL AND revoked_at IS NULL",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(token_hash)
    .bind(expires_at)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn list<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    open_only: bool,
    after: Option<Cursor>,
    limit: i64,
) -> Result<Vec<Invitation>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM invitations WHERE tenant_id = ")
        .push_bind(tenant_id);
    if open_only {
        qb.push(" AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()");
    }
    if let Some(c) = after {
        qb.push(" AND (created_at, id) > (")
            .push_bind(c.created_at)
            .push(", ")
            .push_bind(c.id)
            .push(")");
    }
    qb.push(" ORDER BY created_at, id LIMIT ")
        .push_bind(limit + 1);
    qb.build_query_as::<Invitation>().fetch_all(exec).await
}
