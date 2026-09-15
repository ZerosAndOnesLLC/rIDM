//! Tenant-scoped claim mapper rows (run inside a tenant-bound transaction).

use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::ClaimMapperRow;

const COLUMNS: &str = "id, tenant_id, client_id, name, config, created_at, updated_at";

pub async fn find_by_id<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<ClaimMapperRow>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM claim_mappers WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id);
    qb.build_query_as::<ClaimMapperRow>()
        .fetch_optional(exec)
        .await
}

/// Mappers that apply to `client_id`: the tenant-wide ones plus the client's own.
pub async fn list_effective<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    client_id: Uuid,
) -> Result<Vec<ClaimMapperRow>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM claim_mappers WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND (client_id IS NULL OR client_id = ")
        .push_bind(client_id)
        .push(") ORDER BY client_id NULLS FIRST, name");
    qb.build_query_as::<ClaimMapperRow>().fetch_all(exec).await
}

/// `None`: every mapper of the tenant; `Some(None)`: tenant-wide only;
/// `Some(Some(c))`: one client's own.
pub async fn list<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    scope: Option<Option<Uuid>>,
) -> Result<Vec<ClaimMapperRow>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM claim_mappers WHERE tenant_id = ")
        .push_bind(tenant_id);
    if let Some(client_id) = scope {
        qb.push(" AND client_id IS NOT DISTINCT FROM ")
            .push_bind(client_id);
    }
    qb.push(" ORDER BY name, id");
    qb.build_query_as::<ClaimMapperRow>().fetch_all(exec).await
}

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    client_id: Option<Uuid>,
    name: &str,
    config: &serde_json::Value,
) -> Result<ClaimMapperRow, sqlx::Error> {
    sqlx::query_as::<_, ClaimMapperRow>(
        "INSERT INTO claim_mappers (id, tenant_id, client_id, name, config) VALUES ($1, $2, $3, $4, $5) \
         RETURNING id, tenant_id, client_id, name, config, created_at, updated_at",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(client_id)
    .bind(name)
    .bind(config)
    .fetch_one(exec)
    .await
}

pub async fn update<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    name: Option<&str>,
    config: Option<&serde_json::Value>,
) -> Result<Option<ClaimMapperRow>, sqlx::Error> {
    let mut qb = QueryBuilder::new("UPDATE claim_mappers SET updated_at = now()");
    if let Some(n) = name {
        qb.push(", name = ").push_bind(n);
    }
    if let Some(c) = config {
        qb.push(", config = ").push_bind(c.clone());
    }
    qb.push(" WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id)
        .push(" RETURNING ")
        .push(COLUMNS);
    qb.build_query_as::<ClaimMapperRow>()
        .fetch_optional(exec)
        .await
}

pub async fn delete<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("DELETE FROM claim_mappers WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}
