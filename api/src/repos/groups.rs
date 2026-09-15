//! Tenant-scoped group queries (run inside a tenant-bound transaction).

use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{Group, GroupUpdate, NewGroup, User};

const COLUMNS: &str =
    "id, tenant_id, parent_id, name, description, attributes, created_at, updated_at";
const USER_COLUMNS: &str = "u.id, u.tenant_id, u.org_id, u.username, u.email, u.email_verified, u.phone, \
    u.phone_verified, u.password_hash, u.password_algo, u.must_change_password, u.password_expires_at, \
    u.password_changed_at, u.status, u.attributes, u.locale, u.last_login_at, u.failed_attempts, \
    u.locked_until, u.deleted_at, u.terms_accepted_at, u.created_at, u.updated_at";

pub async fn find_by_id<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<Group>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM groups WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id);
    qb.build_query_as::<Group>().fetch_optional(exec).await
}

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    input: &NewGroup,
) -> Result<Group, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO groups (id, tenant_id, parent_id, name, description, attributes) VALUES (",
    );
    let mut sep = qb.separated(", ");
    sep.push_bind(id)
        .push_bind(tenant_id)
        .push_bind(input.parent_id)
        .push_bind(&input.name)
        .push_bind(&input.description)
        .push_bind(
            input
                .attributes
                .clone()
                .unwrap_or_else(|| serde_json::Value::Object(Default::default())),
        );
    qb.push(") RETURNING ").push(COLUMNS);
    qb.build_query_as::<Group>().fetch_one(exec).await
}

pub async fn update<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    patch: &GroupUpdate,
) -> Result<Option<Group>, sqlx::Error> {
    let mut qb = QueryBuilder::new("UPDATE groups SET updated_at = now()");
    if let Some(v) = &patch.name {
        qb.push(", name = ").push_bind(v);
    }
    if let Some(v) = &patch.parent_id {
        qb.push(", parent_id = ").push_bind(*v);
    }
    if let Some(v) = &patch.description {
        qb.push(", description = ").push_bind(v.clone());
    }
    if let Some(v) = &patch.attributes {
        qb.push(", attributes = ").push_bind(v.clone());
    }
    qb.push(" WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id)
        .push(" RETURNING ")
        .push(COLUMNS);
    qb.build_query_as::<Group>().fetch_optional(exec).await
}

pub async fn delete<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("DELETE FROM groups WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// All groups of a tenant ordered by name (trees are small; the UI builds the hierarchy).
pub async fn list_all<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
) -> Result<Vec<Group>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM groups WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" ORDER BY name, id");
    qb.build_query_as::<Group>().fetch_all(exec).await
}

/// Ids of `id` and every ancestor, walking `parent_id` upwards.
pub async fn ancestor_ids<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "WITH RECURSIVE up AS ( \
            SELECT id, parent_id, 0 AS depth FROM groups WHERE tenant_id = $1 AND id = $2 \
            UNION ALL \
            SELECT g.id, g.parent_id, up.depth + 1 FROM groups g \
              JOIN up ON g.id = up.parent_id WHERE g.tenant_id = $1 AND up.depth < 64) \
         SELECT id FROM up",
    )
    .bind(tenant_id)
    .bind(id)
    .fetch_all(exec)
    .await
}

pub async fn add_member<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    group_id: Uuid,
    user_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "INSERT INTO group_members (tenant_id, group_id, user_id) VALUES ($1, $2, $3) \
         ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(group_id)
    .bind(user_id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn remove_member<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    group_id: Uuid,
    user_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "DELETE FROM group_members WHERE tenant_id = $1 AND group_id = $2 AND user_id = $3",
    )
    .bind(tenant_id)
    .bind(group_id)
    .bind(user_id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Direct members of a group (not soft-deleted), ordered by username.
pub async fn members<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    group_id: Uuid,
) -> Result<Vec<User>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(USER_COLUMNS)
        .push(" FROM group_members gm JOIN users u ON u.tenant_id = gm.tenant_id AND u.id = gm.user_id \
                WHERE gm.tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND gm.group_id = ")
        .push_bind(group_id)
        .push(" AND u.deleted_at IS NULL ORDER BY u.username");
    qb.build_query_as::<User>().fetch_all(exec).await
}

/// Groups a user belongs to directly.
pub async fn direct_groups_of_user<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<Group>, sqlx::Error> {
    sqlx::query_as::<_, Group>(
        "SELECT g.id, g.tenant_id, g.parent_id, g.name, g.description, g.attributes, \
                g.created_at, g.updated_at \
         FROM group_members gm JOIN groups g ON g.tenant_id = gm.tenant_id AND g.id = gm.group_id \
         WHERE gm.tenant_id = $1 AND gm.user_id = $2 ORDER BY g.name",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_all(exec)
    .await
}

/// Direct groups plus all their ancestors (membership is inherited upwards).
pub async fn effective_groups_of_user<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<Group>, sqlx::Error> {
    sqlx::query_as::<_, Group>(
        "WITH RECURSIVE up AS ( \
            SELECT g.id, g.parent_id, 0 AS depth FROM group_members gm \
              JOIN groups g ON g.tenant_id = gm.tenant_id AND g.id = gm.group_id \
             WHERE gm.tenant_id = $1 AND gm.user_id = $2 \
            UNION \
            SELECT p.id, p.parent_id, up.depth + 1 FROM groups p \
              JOIN up ON p.id = up.parent_id WHERE p.tenant_id = $1 AND up.depth < 64) \
         SELECT g.id, g.tenant_id, g.parent_id, g.name, g.description, g.attributes, \
                g.created_at, g.updated_at \
         FROM groups g JOIN (SELECT DISTINCT id FROM up) u ON u.id = g.id \
         WHERE g.tenant_id = $1 ORDER BY g.name",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_all(exec)
    .await
}
