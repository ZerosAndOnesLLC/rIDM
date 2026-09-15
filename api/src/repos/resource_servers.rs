//! Resource servers (audiences) and their permissions (run inside a tenant tx).

use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{Permission, ResourceServer};

const RS_COLUMNS: &str = "id, tenant_id, identifier, name, token_ttl_secs, signing_alg, \
    allow_offline_access, created_at, updated_at";
const PERM_COLUMNS: &str = "id, tenant_id, resource_server_id, name, description, created_at";

pub async fn list<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
) -> Result<Vec<ResourceServer>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(RS_COLUMNS)
        .push(" FROM resource_servers WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" ORDER BY identifier");
    qb.build_query_as::<ResourceServer>().fetch_all(exec).await
}

pub async fn find_by_identifier<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    identifier: &str,
) -> Result<Option<ResourceServer>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(RS_COLUMNS)
        .push(" FROM resource_servers WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND identifier = ")
        .push_bind(identifier);
    qb.build_query_as::<ResourceServer>()
        .fetch_optional(exec)
        .await
}

pub async fn find_by_id<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<ResourceServer>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(RS_COLUMNS)
        .push(" FROM resource_servers WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id);
    qb.build_query_as::<ResourceServer>()
        .fetch_optional(exec)
        .await
}

#[allow(clippy::too_many_arguments)]
pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    identifier: &str,
    name: &str,
    token_ttl_secs: Option<i32>,
    signing_alg: Option<&str>,
    allow_offline_access: bool,
) -> Result<ResourceServer, sqlx::Error> {
    sqlx::query_as::<_, ResourceServer>(
        "INSERT INTO resource_servers (id, tenant_id, identifier, name, token_ttl_secs, signing_alg, \
         allow_offline_access) VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING id, tenant_id, identifier, name, token_ttl_secs, signing_alg, allow_offline_access, \
         created_at, updated_at",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(identifier)
    .bind(name)
    .bind(token_ttl_secs)
    .bind(signing_alg)
    .bind(allow_offline_access)
    .fetch_one(exec)
    .await
}

pub async fn delete<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("DELETE FROM resource_servers WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn list_permissions<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    resource_server_id: Uuid,
) -> Result<Vec<Permission>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(PERM_COLUMNS)
        .push(" FROM permissions WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND resource_server_id = ")
        .push_bind(resource_server_id)
        .push(" ORDER BY name");
    qb.build_query_as::<Permission>().fetch_all(exec).await
}

pub async fn insert_permission<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    resource_server_id: Uuid,
    name: &str,
    description: Option<&str>,
) -> Result<Permission, sqlx::Error> {
    sqlx::query_as::<_, Permission>(
        "INSERT INTO permissions (id, tenant_id, resource_server_id, name, description) \
         VALUES ($1, $2, $3, $4, $5) \
         RETURNING id, tenant_id, resource_server_id, name, description, created_at",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(resource_server_id)
    .bind(name)
    .bind(description)
    .fetch_one(exec)
    .await
}

pub async fn delete_permission<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("DELETE FROM permissions WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn assign_permission<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    role_id: Uuid,
    permission_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "INSERT INTO permission_assignments (tenant_id, role_id, permission_id) VALUES ($1, $2, $3) \
         ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(role_id)
    .bind(permission_id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn unassign_permission<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    role_id: Uuid,
    permission_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "DELETE FROM permission_assignments WHERE tenant_id = $1 AND role_id = $2 AND permission_id = $3",
    )
    .bind(tenant_id)
    .bind(role_id)
    .bind(permission_id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Permission names of a resource server granted through any of `role_ids`.
pub async fn permissions_for_roles<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    resource_server_id: Uuid,
    role_ids: &[Uuid],
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT DISTINCT p.name FROM permission_assignments pa \
         JOIN permissions p ON p.tenant_id = pa.tenant_id AND p.id = pa.permission_id \
         WHERE pa.tenant_id = $1 AND p.resource_server_id = $2 AND pa.role_id = ANY($3) ORDER BY p.name",
    )
    .bind(tenant_id)
    .bind(resource_server_id)
    .bind(role_ids)
    .fetch_all(exec)
    .await
}
