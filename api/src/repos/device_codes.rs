//! Audit rows of device authorization codes (tenant-bound transactions).

use sqlx::PgExecutor;
use uuid::Uuid;

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    client_id: Uuid,
    user_code: &str,
    scopes: &[String],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO device_codes (id, tenant_id, client_id, user_code, scopes) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(client_id)
    .bind(user_code)
    .bind(scopes)
    .execute(exec)
    .await?;
    Ok(())
}

/// Record the user's decision (`approved` or `denied`).
pub async fn decide<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    status: &str,
    user_id: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE device_codes SET status = $3, user_id = $4, decided_at = now() \
         WHERE tenant_id = $1 AND id = $2 AND status = 'pending'",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(status)
    .bind(user_id)
    .execute(exec)
    .await?;
    Ok(())
}

/// The device collected its tokens.
pub async fn consume<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE device_codes SET status = 'consumed', consumed_at = now() \
         WHERE tenant_id = $1 AND id = $2 AND status = 'approved'",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(exec)
    .await?;
    Ok(())
}
