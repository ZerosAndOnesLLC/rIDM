//! Tenant-scoped role queries (run inside a tenant-bound transaction).

use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{NewRole, Principal, Role, RoleAssignment, RoleUpdate};

const COLUMNS: &str =
    "id, tenant_id, client_id, name, description, built_in, created_at, updated_at";
const ASSIGNMENT_COLUMNS: &str = "id, tenant_id, role_id, user_id, group_id, org_id, created_at";

pub async fn find_by_id<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<Role>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM roles WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id);
    qb.build_query_as::<Role>().fetch_optional(exec).await
}

pub async fn find_by_name<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    client_id: Option<Uuid>,
    name: &str,
) -> Result<Option<Role>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM roles WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND client_id IS NOT DISTINCT FROM ")
        .push_bind(client_id)
        .push(" AND name = ")
        .push_bind(name);
    qb.build_query_as::<Role>().fetch_optional(exec).await
}

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    input: &NewRole,
) -> Result<Role, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO roles (id, tenant_id, client_id, name, description) VALUES (",
    );
    let mut sep = qb.separated(", ");
    sep.push_bind(id)
        .push_bind(tenant_id)
        .push_bind(input.client_id)
        .push_bind(&input.name)
        .push_bind(&input.description);
    qb.push(") RETURNING ").push(COLUMNS);
    qb.build_query_as::<Role>().fetch_one(exec).await
}

pub async fn update<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    patch: &RoleUpdate,
) -> Result<Option<Role>, sqlx::Error> {
    let mut qb = QueryBuilder::new("UPDATE roles SET updated_at = now()");
    if let Some(v) = &patch.name {
        qb.push(", name = ").push_bind(v);
    }
    if let Some(v) = &patch.description {
        qb.push(", description = ").push_bind(v.clone());
    }
    qb.push(" WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id)
        .push(" RETURNING ")
        .push(COLUMNS);
    qb.build_query_as::<Role>().fetch_optional(exec).await
}

pub async fn delete<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("DELETE FROM roles WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// All roles of a tenant, optionally only those of one client (or only realm roles
/// when `client_id` is `Some(None)`).
pub async fn list_all<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    client_id: Option<Option<Uuid>>,
) -> Result<Vec<Role>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM roles WHERE tenant_id = ")
        .push_bind(tenant_id);
    if let Some(c) = client_id {
        qb.push(" AND client_id IS NOT DISTINCT FROM ").push_bind(c);
    }
    qb.push(" ORDER BY name, id");
    qb.build_query_as::<Role>().fetch_all(exec).await
}

pub async fn assign<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    role_id: Uuid,
    principal: Principal,
    org_id: Option<Uuid>,
) -> Result<bool, sqlx::Error> {
    let (user_id, group_id) = match principal {
        Principal::User { id } => (Some(id), None),
        Principal::Group { id } => (None, Some(id)),
    };
    let res = sqlx::query(
        "INSERT INTO role_assignments (id, tenant_id, role_id, user_id, group_id, org_id) \
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(tenant_id)
    .bind(role_id)
    .bind(user_id)
    .bind(group_id)
    .bind(org_id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn unassign<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    role_id: Uuid,
    principal: Principal,
    org_id: Option<Uuid>,
) -> Result<bool, sqlx::Error> {
    let (user_id, group_id) = match principal {
        Principal::User { id } => (Some(id), None),
        Principal::Group { id } => (None, Some(id)),
    };
    let res = sqlx::query(
        "DELETE FROM role_assignments WHERE tenant_id = $1 AND role_id = $2 \
         AND user_id IS NOT DISTINCT FROM $3 AND group_id IS NOT DISTINCT FROM $4 \
         AND org_id IS NOT DISTINCT FROM $5",
    )
    .bind(tenant_id)
    .bind(role_id)
    .bind(user_id)
    .bind(group_id)
    .bind(org_id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Direct assignments of a principal.
pub async fn assignments_of<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    principal: Principal,
) -> Result<Vec<RoleAssignment>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(ASSIGNMENT_COLUMNS)
        .push(" FROM role_assignments WHERE tenant_id = ")
        .push_bind(tenant_id);
    match principal {
        Principal::User { id } => qb.push(" AND user_id = ").push_bind(id),
        Principal::Group { id } => qb.push(" AND group_id = ").push_bind(id),
    };
    qb.push(" ORDER BY created_at, id");
    qb.build_query_as::<RoleAssignment>().fetch_all(exec).await
}

pub async fn add_composite<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    parent_role_id: Uuid,
    child_role_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "INSERT INTO role_composites (tenant_id, parent_role_id, child_role_id) \
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(parent_role_id)
    .bind(child_role_id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn remove_composite<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    parent_role_id: Uuid,
    child_role_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "DELETE FROM role_composites WHERE tenant_id = $1 AND parent_role_id = $2 AND child_role_id = $3",
    )
    .bind(tenant_id)
    .bind(parent_role_id)
    .bind(child_role_id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Direct children of a composite role.
pub async fn composites_of<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    parent_role_id: Uuid,
) -> Result<Vec<Role>, sqlx::Error> {
    sqlx::query_as::<_, Role>(
        "SELECT r.id, r.tenant_id, r.client_id, r.name, r.description, r.built_in, r.created_at, \
         r.updated_at \
         FROM role_composites rc JOIN roles r ON r.tenant_id = rc.tenant_id AND r.id = rc.child_role_id \
         WHERE rc.tenant_id = $1 AND rc.parent_role_id = $2 ORDER BY r.name",
    )
    .bind(tenant_id)
    .bind(parent_role_id)
    .fetch_all(exec)
    .await
}

/// Would adding `child` under `parent` create a cycle? True when `parent` is
/// already reachable from `child`.
pub async fn composite_would_cycle<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    parent_role_id: Uuid,
    child_role_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "WITH RECURSIVE down AS ( \
            SELECT child_role_id AS id, 0 AS depth FROM role_composites \
             WHERE tenant_id = $1 AND parent_role_id = $3 \
            UNION \
            SELECT rc.child_role_id, down.depth + 1 FROM role_composites rc \
              JOIN down ON rc.parent_role_id = down.id WHERE rc.tenant_id = $1 AND down.depth < 64) \
         SELECT EXISTS (SELECT 1 FROM down WHERE id = $2)",
    )
    .bind(tenant_id)
    .bind(parent_role_id)
    .bind(child_role_id)
    .fetch_one(exec)
    .await
}

/// Effective roles of a user: direct assignments, assignments of every group
/// the user is in (including ancestor groups), and the transitive closure of
/// composite roles. Ordered by name.
pub async fn effective_roles_of_user<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<Role>, sqlx::Error> {
    sqlx::query_as::<_, Role>(
        "WITH RECURSIVE user_groups AS ( \
            SELECT g.id, g.parent_id, 0 AS depth FROM group_members gm \
              JOIN groups g ON g.tenant_id = gm.tenant_id AND g.id = gm.group_id \
             WHERE gm.tenant_id = $1 AND gm.user_id = $2 \
            UNION \
            SELECT p.id, p.parent_id, ug.depth + 1 FROM groups p \
              JOIN user_groups ug ON p.id = ug.parent_id WHERE p.tenant_id = $1 AND ug.depth < 64), \
         direct AS ( \
            SELECT ra.role_id FROM role_assignments ra WHERE ra.tenant_id = $1 AND ra.user_id = $2 \
            UNION \
            SELECT ra.role_id FROM role_assignments ra \
              JOIN user_groups ug ON ra.group_id = ug.id WHERE ra.tenant_id = $1), \
         effective AS ( \
            SELECT role_id, 0 AS depth FROM direct \
            UNION \
            SELECT rc.child_role_id, e.depth + 1 FROM role_composites rc \
              JOIN effective e ON rc.parent_role_id = e.role_id WHERE rc.tenant_id = $1 AND e.depth < 64) \
         SELECT r.id, r.tenant_id, r.client_id, r.name, r.description, r.built_in, r.created_at, \
         r.updated_at \
         FROM roles r JOIN (SELECT DISTINCT role_id FROM effective) e ON e.role_id = r.id \
         WHERE r.tenant_id = $1 ORDER BY r.name, r.id",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_all(exec)
    .await
}

/// `roles` plus every role reachable through composites (what assigning them
/// actually grants).
pub async fn expand_composites<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    role_ids: &[Uuid],
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "WITH RECURSIVE effective AS ( \
            SELECT id AS role_id, 0 AS depth FROM roles WHERE tenant_id = $1 AND id = ANY($2) \
            UNION \
            SELECT rc.child_role_id, e.depth + 1 FROM role_composites rc \
              JOIN effective e ON rc.parent_role_id = e.role_id WHERE rc.tenant_id = $1 AND e.depth < 64) \
         SELECT DISTINCT role_id FROM effective",
    )
    .bind(tenant_id)
    .bind(role_ids)
    .fetch_all(exec)
    .await
}

/// Roles assigned to a group or any of its ancestors (what group membership
/// grants before composites are expanded).
pub async fn role_ids_of_group_lineage<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    group_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "WITH RECURSIVE lineage AS ( \
            SELECT id, parent_id, 0 AS depth FROM groups WHERE tenant_id = $1 AND id = $2 \
            UNION \
            SELECT p.id, p.parent_id, l.depth + 1 FROM groups p \
              JOIN lineage l ON p.id = l.parent_id WHERE p.tenant_id = $1 AND l.depth < 64) \
         SELECT DISTINCT ra.role_id FROM role_assignments ra \
           JOIN lineage l ON ra.group_id = l.id WHERE ra.tenant_id = $1",
    )
    .bind(tenant_id)
    .bind(group_id)
    .fetch_all(exec)
    .await
}
