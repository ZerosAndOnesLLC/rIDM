//! Tenant-scoped organization queries (run inside a tenant-bound transaction).

use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{
    NewOrganization, NewOrganizationDomain, Organization, OrganizationDomain,
    OrganizationDomainUpdate, OrganizationFilter, OrganizationUpdate,
};
use crate::repos::users::escape_like;

const COLUMNS: &str = "id, tenant_id, slug, display_name, description, status, attributes, \
    created_at, updated_at";
const DOMAIN_COLUMNS: &str = "id, tenant_id, org_id, domain, verification, verified_at, \
    auto_join, created_at, updated_at";

pub async fn find_by_id<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<Organization>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM organizations WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id);
    qb.build_query_as::<Organization>()
        .fetch_optional(exec)
        .await
}

pub async fn find_by_slug<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    slug: &str,
) -> Result<Option<Organization>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM organizations WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND slug = ")
        .push_bind(slug);
    qb.build_query_as::<Organization>()
        .fetch_optional(exec)
        .await
}

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    input: &NewOrganization,
) -> Result<Organization, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO organizations (id, tenant_id, slug, display_name, description, attributes) VALUES (",
    );
    let mut sep = qb.separated(", ");
    sep.push_bind(id)
        .push_bind(tenant_id)
        .push_bind(&input.slug)
        .push_bind(&input.display_name)
        .push_bind(&input.description)
        .push_bind(
            input
                .attributes
                .clone()
                .unwrap_or_else(|| serde_json::Value::Object(Default::default())),
        );
    qb.push(") RETURNING ").push(COLUMNS);
    qb.build_query_as::<Organization>().fetch_one(exec).await
}

pub async fn update<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    patch: &OrganizationUpdate,
) -> Result<Option<Organization>, sqlx::Error> {
    let mut qb = QueryBuilder::new("UPDATE organizations SET updated_at = now()");
    if let Some(v) = &patch.slug {
        qb.push(", slug = ").push_bind(v);
    }
    if let Some(v) = &patch.display_name {
        qb.push(", display_name = ").push_bind(v);
    }
    if let Some(v) = &patch.description {
        qb.push(", description = ").push_bind(v.clone());
    }
    if let Some(v) = &patch.status {
        qb.push(", status = ").push_bind(*v);
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
    qb.build_query_as::<Organization>()
        .fetch_optional(exec)
        .await
}

pub async fn delete<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("DELETE FROM organizations WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// One page of organizations, newest last (keyset over `created_at, id`).
pub async fn list<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    filter: &OrganizationFilter,
    after: Option<(chrono::DateTime<chrono::Utc>, Uuid)>,
    limit: i64,
) -> Result<Vec<Organization>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM organizations WHERE tenant_id = ")
        .push_bind(tenant_id);
    if let Some(status) = &filter.status {
        qb.push(" AND status = ").push_bind(*status);
    }
    if let Some(search) = &filter.search {
        let pattern = format!("%{}%", escape_like(search));
        qb.push(" AND (slug ILIKE ")
            .push_bind(pattern.clone())
            .push(" OR display_name ILIKE ")
            .push_bind(pattern)
            .push(")");
    }
    if let Some((created_at, id)) = after {
        qb.push(" AND (created_at, id) > (")
            .push_bind(created_at)
            .push(", ")
            .push_bind(id)
            .push(")");
    }
    qb.push(" ORDER BY created_at, id LIMIT ").push_bind(limit);
    qb.build_query_as::<Organization>().fetch_all(exec).await
}

pub async fn add_member<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "INSERT INTO organization_members (tenant_id, org_id, user_id) VALUES ($1, $2, $3) \
         ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(org_id)
    .bind(user_id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Clear the primary organization of up to `limit` of the users whose
/// primary organization is `org_id`; the ones cleared.
pub async fn clear_primary_org_batch<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    org_id: Uuid,
    limit: i64,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE users SET org_id = NULL \
          WHERE tenant_id = $1 AND id IN ( \
                SELECT id FROM users WHERE tenant_id = $1 AND org_id = $2 LIMIT $3) \
          RETURNING id",
    )
    .bind(tenant_id)
    .bind(org_id)
    .bind(limit)
    .fetch_all(exec)
    .await
}

/// Users whose primary organization is `org_id`.
pub async fn users_with_primary_org<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    org_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar("SELECT id FROM users WHERE tenant_id = $1 AND org_id = $2")
        .bind(tenant_id)
        .bind(org_id)
        .fetch_all(exec)
        .await
}

pub async fn remove_member<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "DELETE FROM organization_members WHERE tenant_id = $1 AND org_id = $2 AND user_id = $3",
    )
    .bind(tenant_id)
    .bind(org_id)
    .bind(user_id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn is_member<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) > 0 FROM organization_members \
         WHERE tenant_id = $1 AND org_id = $2 AND user_id = $3",
    )
    .bind(tenant_id)
    .bind(org_id)
    .bind(user_id)
    .fetch_one(exec)
    .await
}

/// The organizations a user belongs to, ordered by name. The login flow asks
/// this to decide whether there is anything to pick.
pub async fn of_user<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<Organization>, sqlx::Error> {
    sqlx::query_as::<_, Organization>(
        "SELECT o.id, o.tenant_id, o.slug, o.display_name, o.description, o.status, \
                o.attributes, o.created_at, o.updated_at \
         FROM organization_members om \
           JOIN organizations o ON o.tenant_id = om.tenant_id AND o.id = om.org_id \
         WHERE om.tenant_id = $1 AND om.user_id = $2 ORDER BY o.display_name, o.id",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_all(exec)
    .await
}

// Domains ------------------------------------------------------------------

pub async fn domains<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    org_id: Uuid,
) -> Result<Vec<OrganizationDomain>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(DOMAIN_COLUMNS)
        .push(" FROM organization_domains WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND org_id = ")
        .push_bind(org_id)
        .push(" ORDER BY domain");
    qb.build_query_as::<OrganizationDomain>()
        .fetch_all(exec)
        .await
}

pub async fn find_domain<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    org_id: Uuid,
    id: Uuid,
) -> Result<Option<OrganizationDomain>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(DOMAIN_COLUMNS)
        .push(" FROM organization_domains WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND org_id = ")
        .push_bind(org_id)
        .push(" AND id = ")
        .push_bind(id);
    qb.build_query_as::<OrganizationDomain>()
        .fetch_optional(exec)
        .await
}

pub async fn insert_domain<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    org_id: Uuid,
    id: Uuid,
    input: &NewOrganizationDomain,
    verification: &str,
) -> Result<OrganizationDomain, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO organization_domains (id, tenant_id, org_id, domain, verification, auto_join) VALUES (",
    );
    let mut sep = qb.separated(", ");
    sep.push_bind(id)
        .push_bind(tenant_id)
        .push_bind(org_id)
        .push_bind(&input.domain)
        .push_bind(verification)
        .push_bind(input.auto_join);
    qb.push(") RETURNING ").push(DOMAIN_COLUMNS);
    qb.build_query_as::<OrganizationDomain>()
        .fetch_one(exec)
        .await
}

pub async fn update_domain<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    org_id: Uuid,
    id: Uuid,
    patch: &OrganizationDomainUpdate,
) -> Result<Option<OrganizationDomain>, sqlx::Error> {
    let mut qb = QueryBuilder::new("UPDATE organization_domains SET updated_at = now()");
    if let Some(v) = patch.auto_join {
        qb.push(", auto_join = ").push_bind(v);
    }
    qb.push(" WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND org_id = ")
        .push_bind(org_id)
        .push(" AND id = ")
        .push_bind(id)
        .push(" RETURNING ")
        .push(DOMAIN_COLUMNS);
    qb.build_query_as::<OrganizationDomain>()
        .fetch_optional(exec)
        .await
}

/// Records that the domain's TXT record was seen. Returns the stored row.
pub async fn mark_domain_verified<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    org_id: Uuid,
    id: Uuid,
) -> Result<Option<OrganizationDomain>, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "UPDATE organization_domains SET verified_at = now(), updated_at = now() WHERE tenant_id = ",
    );
    qb.push_bind(tenant_id)
        .push(" AND org_id = ")
        .push_bind(org_id)
        .push(" AND id = ")
        .push_bind(id)
        .push(" RETURNING ")
        .push(DOMAIN_COLUMNS);
    qb.build_query_as::<OrganizationDomain>()
        .fetch_optional(exec)
        .await
}

pub async fn delete_domain<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    org_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "DELETE FROM organization_domains WHERE tenant_id = $1 AND org_id = $2 AND id = $3",
    )
    .bind(tenant_id)
    .bind(org_id)
    .bind(id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Every domain at which a verified address joins an organization: verified,
/// set to auto-join, of an active organization (the conditions of
/// [`auto_join_org_for_domain`]).
pub async fn auto_join_domains<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT d.domain FROM organization_domains d \
           JOIN organizations o ON o.tenant_id = d.tenant_id AND o.id = d.org_id \
         WHERE d.tenant_id = $1 AND d.auto_join \
           AND d.verified_at IS NOT NULL AND o.status = 'active'",
    )
    .bind(tenant_id)
    .fetch_all(exec)
    .await
}

/// The organization a verified auto-join domain points at, if any. One row at
/// most: a domain belongs to one organization per tenant.
pub async fn auto_join_org_for_domain<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    domain: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT d.org_id FROM organization_domains d \
           JOIN organizations o ON o.tenant_id = d.tenant_id AND o.id = d.org_id \
         WHERE d.tenant_id = $1 AND d.domain = $2 AND d.auto_join \
           AND d.verified_at IS NOT NULL AND o.status = 'active'",
    )
    .bind(tenant_id)
    .bind(domain)
    .fetch_optional(exec)
    .await
}

/// Sets a user's primary organization, but only while they have none: a
/// member's first organization becomes their primary one, and later
/// auto-joins never move it.
pub async fn set_primary_org_if_unset<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
    org_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE users SET org_id = $3, updated_at = now() \
         WHERE tenant_id = $1 AND id = $2 AND org_id IS NULL",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(org_id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}
