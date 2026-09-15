//! Encrypted per-tenant provider configuration (run inside a tenant tx).

use sqlx::PgExecutor;
use uuid::Uuid;

pub async fn get<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    kind: &str,
) -> Result<Option<Vec<u8>>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT config_enc FROM tenant_provider_settings WHERE tenant_id = $1 AND kind = $2",
    )
    .bind(tenant_id)
    .bind(kind)
    .fetch_optional(exec)
    .await
}

pub async fn upsert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    kind: &str,
    config_enc: &[u8],
    key_version: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO tenant_provider_settings (tenant_id, kind, config_enc, key_version) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (tenant_id, kind) DO UPDATE SET config_enc = EXCLUDED.config_enc, \
            key_version = EXCLUDED.key_version, updated_at = now()",
    )
    .bind(tenant_id)
    .bind(kind)
    .bind(config_enc)
    .bind(key_version)
    .execute(exec)
    .await?;
    Ok(())
}

pub async fn delete<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    kind: &str,
) -> Result<bool, sqlx::Error> {
    let res =
        sqlx::query("DELETE FROM tenant_provider_settings WHERE tenant_id = $1 AND kind = $2")
            .bind(tenant_id)
            .bind(kind)
            .execute(exec)
            .await?;
    Ok(res.rows_affected() > 0)
}
