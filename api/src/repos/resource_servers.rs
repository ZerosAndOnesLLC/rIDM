//! Resource servers (audiences) and their permissions (run inside a tenant tx).

use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{Permission, ResourceServer, ResourceServerUpdate};

const RS_COLUMNS: &str = "id, tenant_id, identifier, name, token_ttl_secs, signing_alg, \
    allow_offline_access, built_in, created_at, updated_at";
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
         built_in, created_at, updated_at",
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

/// Admin permissions each of `role_ids` carries once composites are expanded,
/// as (the role asked about, permission name) pairs. One query for the whole
/// set, which is what a role picker needs.
pub async fn permissions_per_role<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    resource_server_id: Uuid,
    role_ids: &[Uuid],
) -> Result<Vec<(Uuid, String)>, sqlx::Error> {
    sqlx::query_as(
        "WITH RECURSIVE reach AS ( \
            SELECT id AS root_id, id AS role_id, 0 AS depth \
              FROM roles WHERE tenant_id = $1 AND id = ANY($3) \
            UNION \
            SELECT re.root_id, rc.child_role_id, re.depth + 1 FROM role_composites rc \
              JOIN reach re ON rc.parent_role_id = re.role_id \
             WHERE rc.tenant_id = $1 AND re.depth < 64) \
         SELECT DISTINCT re.root_id, p.name FROM reach re \
           JOIN permission_assignments pa ON pa.tenant_id = $1 AND pa.role_id = re.role_id \
           JOIN permissions p ON p.tenant_id = pa.tenant_id AND p.id = pa.permission_id \
          WHERE p.resource_server_id = $2 ORDER BY re.root_id, p.name",
    )
    .bind(tenant_id)
    .bind(resource_server_id)
    .bind(role_ids)
    .fetch_all(exec)
    .await
}

/// Change the mutable columns (identifier and `built_in` never change).
pub async fn update<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    patch: &ResourceServerUpdate,
) -> Result<Option<ResourceServer>, sqlx::Error> {
    let mut qb = QueryBuilder::new("UPDATE resource_servers SET updated_at = now()");
    if let Some(n) = &patch.name {
        qb.push(", name = ").push_bind(n);
    }
    if let Some(t) = patch.token_ttl_secs {
        qb.push(", token_ttl_secs = ").push_bind(t);
    }
    if let Some(a) = &patch.signing_alg {
        qb.push(", signing_alg = ").push_bind(a);
    }
    if let Some(o) = patch.allow_offline_access {
        qb.push(", allow_offline_access = ").push_bind(o);
    }
    qb.push(" WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id)
        .push(" RETURNING ")
        .push(RS_COLUMNS);
    qb.build_query_as::<ResourceServer>()
        .fetch_optional(exec)
        .await
}

pub async fn find_permission<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<Permission>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(PERM_COLUMNS)
        .push(" FROM permissions WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id);
    qb.build_query_as::<Permission>().fetch_optional(exec).await
}

/// Permissions granted directly to a role (composites not expanded).
pub async fn permissions_of_role<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    role_id: Uuid,
) -> Result<Vec<Permission>, sqlx::Error> {
    sqlx::query_as::<_, Permission>(
        "SELECT p.id, p.tenant_id, p.resource_server_id, p.name, p.description, p.created_at \
         FROM permission_assignments pa \
         JOIN permissions p ON p.tenant_id = pa.tenant_id AND p.id = pa.permission_id \
         WHERE pa.tenant_id = $1 AND pa.role_id = $2 ORDER BY p.name, p.id",
    )
    .bind(tenant_id)
    .bind(role_id)
    .fetch_all(exec)
    .await
}
