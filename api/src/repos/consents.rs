//! Tenant-scoped consent queries (run inside a tenant-bound transaction).

use sqlx::PgExecutor;
use uuid::Uuid;

use crate::models::Consent;

const COLUMNS: &str = "tenant_id, user_id, client_id, scopes, granted_at, revoked_at";

pub async fn find<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: Uuid,
) -> Result<Option<Consent>, sqlx::Error> {
    let mut qb = sqlx::QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM consents WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND user_id = ")
        .push_bind(user_id)
        .push(" AND client_id = ")
        .push_bind(client_id);
    qb.build_query_as::<Consent>().fetch_optional(exec).await
}

/// Insert or merge scopes into an existing grant (un-revoking it).
pub async fn upsert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: Uuid,
    scopes: &[String],
) -> Result<Consent, sqlx::Error> {
    sqlx::query_as::<_, Consent>(
        "INSERT INTO consents (tenant_id, user_id, client_id, scopes) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (tenant_id, user_id, client_id) DO UPDATE SET \
            scopes = (SELECT array_agg(DISTINCT s) FROM unnest(consents.scopes || EXCLUDED.scopes) AS s), \
            granted_at = now(), revoked_at = NULL \
         RETURNING tenant_id, user_id, client_id, scopes, granted_at, revoked_at",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(client_id)
    .bind(scopes)
    .fetch_one(exec)
    .await
}

pub async fn revoke<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE consents SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2 \
         AND client_id = $3 AND revoked_at IS NULL",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(client_id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn list_for_user<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<Consent>, sqlx::Error> {
    let mut qb = sqlx::QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM consents WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND user_id = ")
        .push_bind(user_id)
        .push(" AND revoked_at IS NULL ORDER BY granted_at DESC");
    qb.build_query_as::<Consent>().fetch_all(exec).await
}
