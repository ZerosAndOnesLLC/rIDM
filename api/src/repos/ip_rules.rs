//! Per-tenant IP allow/deny rules (tenant-bound transactions).

use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{IpRule, IpRuleAction, IpRuleUpdate};

const COLUMNS: &str = "id, tenant_id, client_id, action, cidr, description, created_at, updated_at";

pub async fn list<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    client_id: Option<Option<Uuid>>,
) -> Result<Vec<IpRule>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM ip_rules WHERE tenant_id = ")
        .push_bind(tenant_id);
    if let Some(c) = client_id {
        qb.push(" AND client_id IS NOT DISTINCT FROM ").push_bind(c);
    }
    qb.push(" ORDER BY client_id NULLS FIRST, action, cidr");
    qb.build_query_as::<IpRule>().fetch_all(exec).await
}

pub async fn find_by_id<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<IpRule>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM ip_rules WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id);
    qb.build_query_as::<IpRule>().fetch_optional(exec).await
}

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    client_id: Option<Uuid>,
    action: IpRuleAction,
    cidr: &str,
    description: Option<&str>,
) -> Result<IpRule, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO ip_rules (id, tenant_id, client_id, action, cidr, description) VALUES (",
    );
    let mut s = qb.separated(", ");
    s.push_bind(id)
        .push_bind(tenant_id)
        .push_bind(client_id)
        .push_bind(action)
        .push_bind(cidr)
        .push_bind(description);
    qb.push(") RETURNING ").push(COLUMNS);
    qb.build_query_as::<IpRule>().fetch_one(exec).await
}

pub async fn update<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    patch: &IpRuleUpdate,
) -> Result<Option<IpRule>, sqlx::Error> {
    let mut qb = QueryBuilder::new("UPDATE ip_rules SET updated_at = now()");
    if let Some(a) = patch.action {
        qb.push(", action = ").push_bind(a);
    }
    if let Some(c) = &patch.cidr {
        qb.push(", cidr = ").push_bind(c);
    }
    if let Some(d) = &patch.description {
        qb.push(", description = ").push_bind(d);
    }
    qb.push(" WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id)
        .push(" RETURNING ")
        .push(COLUMNS);
    qb.build_query_as::<IpRule>().fetch_optional(exec).await
}

pub async fn delete<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("DELETE FROM ip_rules WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}
