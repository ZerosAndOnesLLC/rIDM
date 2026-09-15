//! Trusted devices (run inside a tenant transaction).

use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::TrustedDevice;

const COLUMNS: &str = "id, tenant_id, user_id, device_hash, name, user_agent, ip, created_at, last_seen_at, expires_at, revoked_at";

#[allow(clippy::too_many_arguments)]
pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    user_id: Uuid,
    device_hash: &[u8],
    name: Option<&str>,
    user_agent: Option<&str>,
    ip: Option<&str>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<TrustedDevice, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO trusted_devices (id, tenant_id, user_id, device_hash, name, user_agent, ip, expires_at) VALUES (",
    );
    let mut s = qb.separated(", ");
    s.push_bind(id)
        .push_bind(tenant_id)
        .push_bind(user_id)
        .push_bind(device_hash.to_vec())
        .push_bind(name)
        .push_bind(user_agent)
        .push_bind(ip)
        .push_bind(expires_at);
    qb.push(") RETURNING ").push(COLUMNS);
    qb.build_query_as::<TrustedDevice>().fetch_one(exec).await
}

pub async fn find_by_hash<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    device_hash: &[u8],
) -> Result<Option<TrustedDevice>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM trusted_devices WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND device_hash = ")
        .push_bind(device_hash.to_vec());
    qb.build_query_as::<TrustedDevice>()
        .fetch_optional(exec)
        .await
}

pub async fn touch<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    ip: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE trusted_devices SET last_seen_at = now(), ip = COALESCE($3, ip) WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .bind(ip)
        .execute(exec)
        .await?;
    Ok(())
}

pub async fn list_for_user<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<TrustedDevice>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM trusted_devices WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND user_id = ")
        .push_bind(user_id)
        .push(" AND revoked_at IS NULL AND expires_at > now() ORDER BY created_at DESC");
    qb.build_query_as::<TrustedDevice>().fetch_all(exec).await
}

pub async fn revoke<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE trusted_devices SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2 AND id = $3 AND revoked_at IS NULL",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn revoke_all<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("UPDATE trusted_devices SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL")
        .bind(tenant_id)
        .bind(user_id)
        .execute(exec)
        .await?
        .rows_affected())
}
