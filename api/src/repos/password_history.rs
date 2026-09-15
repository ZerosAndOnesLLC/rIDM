//! Previous password hashes, used to enforce the reuse policy.

use sqlx::PgExecutor;
use uuid::Uuid;

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO password_history (tenant_id, user_id, hash) VALUES ($1, $2, $3)")
        .bind(tenant_id)
        .bind(user_id)
        .bind(hash)
        .execute(exec)
        .await?;
    Ok(())
}

/// Most recent `limit` hashes, newest first.
pub async fn recent<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    limit: i64,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT hash FROM password_history WHERE tenant_id = $1 AND user_id = $2 \
         ORDER BY created_at DESC, id DESC LIMIT $3",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(limit)
    .fetch_all(exec)
    .await
}

/// Keep only the newest `keep` entries.
pub async fn trim<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    keep: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM password_history WHERE tenant_id = $1 AND user_id = $2 AND id NOT IN ( \
            SELECT id FROM password_history WHERE tenant_id = $1 AND user_id = $2 \
            ORDER BY created_at DESC, id DESC LIMIT $3)",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(keep)
    .execute(exec)
    .await?;
    Ok(())
}
