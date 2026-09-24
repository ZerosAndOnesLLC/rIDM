//! Tenant-scoped consent queries (run inside a tenant-bound transaction).

use sqlx::PgExecutor;
use uuid::Uuid;

use crate::models::{Consent, ConsentWithClient};

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

/// A user's live consents with their clients, newest first.
pub async fn list_for_user<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<ConsentWithClient>, sqlx::Error> {
    sqlx::query_as::<_, ConsentWithClient>(
        "SELECT cs.tenant_id, cs.user_id, cs.client_id, cs.scopes, cs.granted_at, cs.revoked_at, \
                c.name AS client_name, c.client_id AS client, c.logo_uri, c.tos_uri, c.policy_uri \
         FROM consents cs JOIN clients c ON c.tenant_id = cs.tenant_id AND c.id = cs.client_id \
         WHERE cs.tenant_id = $1 AND cs.user_id = $2 AND cs.revoked_at IS NULL \
         ORDER BY cs.granted_at DESC",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_all(exec)
    .await
}
