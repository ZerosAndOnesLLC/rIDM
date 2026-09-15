//! `tenants` is a global table (no RLS); queries take any executor.

use sqlx::types::Json;
use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{Tenant, TenantSettings, TenantStatus};
use crate::util::cursor::Cursor;

const COLUMNS: &str =
    "id, slug, display_name, status, settings, pairwise_salt, created_at, updated_at";

pub async fn find_by_slug<'e>(
    exec: impl PgExecutor<'e>,
    slug: &str,
) -> Result<Option<Tenant>, sqlx::Error> {
    sqlx::query_as::<_, Tenant>(
        "SELECT id, slug, display_name, status, settings, pairwise_salt, created_at, updated_at \
         FROM tenants WHERE slug = $1",
    )
    .bind(slug)
    .fetch_optional(exec)
    .await
}

pub async fn find_by_id<'e>(
    exec: impl PgExecutor<'e>,
    id: Uuid,
) -> Result<Option<Tenant>, sqlx::Error> {
    sqlx::query_as::<_, Tenant>(
        "SELECT id, slug, display_name, status, settings, pairwise_salt, created_at, updated_at \
         FROM tenants WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(exec)
    .await
}

pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    id: Uuid,
    slug: &str,
    display_name: &str,
    settings: &TenantSettings,
) -> Result<Tenant, sqlx::Error> {
    sqlx::query_as::<_, Tenant>(
        "INSERT INTO tenants (id, slug, display_name, settings) VALUES ($1, $2, $3, $4) \
         RETURNING id, slug, display_name, status, settings, pairwise_salt, created_at, updated_at",
    )
    .bind(id)
    .bind(slug)
    .bind(display_name)
    .bind(Json(settings))
    .fetch_one(exec)
    .await
}

pub async fn update<'e>(
    exec: impl PgExecutor<'e>,
    id: Uuid,
    display_name: Option<&str>,
    status: Option<TenantStatus>,
    settings: Option<&TenantSettings>,
) -> Result<Option<Tenant>, sqlx::Error> {
    let mut qb = QueryBuilder::new("UPDATE tenants SET updated_at = now()");
    if let Some(v) = display_name {
        qb.push(", display_name = ").push_bind(v);
    }
    if let Some(v) = status {
        qb.push(", status = ").push_bind(v);
    }
    if let Some(v) = settings {
        qb.push(", settings = ").push_bind(Json(v));
    }
    qb.push(" WHERE id = ").push_bind(id);
    qb.push(" RETURNING ").push(COLUMNS);
    qb.build_query_as::<Tenant>().fetch_optional(exec).await
}

pub async fn delete<'e>(exec: impl PgExecutor<'e>, id: Uuid) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(id)
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Keyset-paginated list ordered by `(created_at, id)`; fetches `limit + 1` rows.
pub async fn list<'e>(
    exec: impl PgExecutor<'e>,
    after: Option<Cursor>,
    limit: i64,
) -> Result<Vec<Tenant>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS).push(" FROM tenants");
    if let Some(c) = after {
        qb.push(" WHERE (created_at, id) > (")
            .push_bind(c.created_at)
            .push(", ")
            .push_bind(c.id)
            .push(")");
    }
    qb.push(" ORDER BY created_at, id LIMIT ")
        .push_bind(limit + 1);
    qb.build_query_as::<Tenant>().fetch_all(exec).await
}

/// Tenant whose discovery settings list `domain` (lower-case). First match wins.
pub async fn find_by_email_domain<'e>(
    exec: impl PgExecutor<'e>,
    domain: &str,
) -> Result<Option<Tenant>, sqlx::Error> {
    sqlx::query_as::<_, Tenant>(
        "SELECT id, slug, display_name, status, settings, pairwise_salt, created_at, updated_at FROM tenants \
         WHERE settings->'discovery'->'email_domains' ? $1 AND status = 'active' \
         ORDER BY created_at LIMIT 1",
    )
    .bind(domain)
    .fetch_optional(exec)
    .await
}
