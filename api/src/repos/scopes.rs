//! Tenant-scoped scope queries (run inside a tenant-bound transaction).

use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{NewScope, Scope};

const COLUMNS: &str = "id, tenant_id, name, description, claims, resource_server_id, is_default, created_at, updated_at";

pub async fn list_all<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
) -> Result<Vec<Scope>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM scopes WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" ORDER BY name, id");
    qb.build_query_as::<Scope>().fetch_all(exec).await
}

pub async fn find_by_name<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    name: &str,
) -> Result<Option<Scope>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM scopes WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND name = ")
        .push_bind(name);
    qb.build_query_as::<Scope>().fetch_optional(exec).await
}

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    input: &NewScope,
) -> Result<Scope, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO scopes (id, tenant_id, name, description, claims, resource_server_id, is_default) VALUES (",
    );
    let mut s = qb.separated(", ");
    s.push_bind(id)
        .push_bind(tenant_id)
        .push_bind(&input.name)
        .push_bind(&input.description)
        .push_bind(&input.claims)
        .push_bind(input.resource_server_id)
        .push_bind(input.is_default);
    qb.push(") RETURNING ").push(COLUMNS);
    qb.build_query_as::<Scope>().fetch_one(exec).await
}

pub async fn update<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    description: Option<Option<&str>>,
    claims: Option<&[String]>,
    is_default: Option<bool>,
    resource_server_id: Option<Option<Uuid>>,
) -> Result<Option<Scope>, sqlx::Error> {
    let mut qb = QueryBuilder::new("UPDATE scopes SET updated_at = now()");
    if let Some(rs) = resource_server_id {
        qb.push(", resource_server_id = ").push_bind(rs);
    }
    if let Some(d) = description {
        qb.push(", description = ").push_bind(d.map(str::to_string));
    }
    if let Some(c) = claims {
        qb.push(", claims = ").push_bind(c.to_vec());
    }
    if let Some(v) = is_default {
        qb.push(", is_default = ").push_bind(v);
    }
    qb.push(" WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id)
        .push(" RETURNING ")
        .push(COLUMNS);
    qb.build_query_as::<Scope>().fetch_optional(exec).await
}

pub async fn delete<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("DELETE FROM scopes WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}
