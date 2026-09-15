//! One `user_profile_schema` row per tenant (RLS-protected; run in a tenant tx).

use sqlx::PgExecutor;
use sqlx::types::Json;
use uuid::Uuid;

use crate::models::{AttributeDef, ProfileSchema};

pub async fn get<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
) -> Result<Option<ProfileSchema>, sqlx::Error> {
    let row: Option<(Json<Vec<AttributeDef>>, bool)> = sqlx::query_as(
        "SELECT attributes, allow_undeclared FROM user_profile_schema WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(exec)
    .await?;
    Ok(row.map(|(attrs, allow_undeclared)| ProfileSchema {
        attributes: attrs.0,
        allow_undeclared,
    }))
}

pub async fn upsert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    schema: &ProfileSchema,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO user_profile_schema (tenant_id, attributes, allow_undeclared) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (tenant_id) DO UPDATE SET attributes = EXCLUDED.attributes, \
            allow_undeclared = EXCLUDED.allow_undeclared, updated_at = now()",
    )
    .bind(tenant_id)
    .bind(Json(&schema.attributes))
    .bind(schema.allow_undeclared)
    .execute(exec)
    .await?;
    Ok(())
}
