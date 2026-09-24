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

/// Failed attempts from `ip` since each of two instants, counted in one read
/// (the lockout's IP throttle and the risk policy's velocity signal look at
/// the same rows over their own windows).
pub async fn failures_from_ip_since<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    ip: &str,
    since: [DateTime<Utc>; 2],
) -> Result<(i64, i64), sqlx::Error> {
    sqlx::query_as(
        "SELECT count(*) FILTER (WHERE created_at >= $3), count(*) FILTER (WHERE created_at >= $4) \
         FROM login_attempts WHERE tenant_id = $1 AND ip = $2 AND success = false \
         AND created_at >= LEAST($3, $4)",
    )
    .bind(tenant_id)
    .bind(ip)
    .bind(since[0])
    .bind(since[1])
    .fetch_one(exec)
    .await
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
