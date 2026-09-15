//! Login attempt log (tenant-scoped; run inside a tenant transaction).

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

pub async fn record<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    identifier: &str,
    ip: Option<&str>,
    success: bool,
    reason: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO login_attempts (tenant_id, identifier, ip, success, reason) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(tenant_id)
    .bind(identifier)
    .bind(ip)
    .bind(success)
    .bind(reason)
    .execute(exec)
    .await?;
    Ok(())
}

/// Failed attempts from `ip` since `since`.
pub async fn failures_from_ip<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    ip: &str,
    since: DateTime<Utc>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM login_attempts WHERE tenant_id = $1 AND ip = $2 AND success = false AND created_at >= $3",
    )
    .bind(tenant_id)
    .bind(ip)
    .bind(since)
    .fetch_one(exec)
    .await
}

pub async fn purge<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    older_than: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    Ok(
        sqlx::query("DELETE FROM login_attempts WHERE tenant_id = $1 AND created_at < $2")
            .bind(tenant_id)
            .bind(older_than)
            .execute(exec)
            .await?
            .rows_affected(),
    )
}
