//! `tenants` is a global table (no RLS); queries take any executor. The
//! registry is the home database's (`Db::home`); a regional database holds
//! a copy of each of its tenants' rows, kept by [`insert_copy`] and
//! [`update_copy`], only for the foreign keys of the rows it holds.

use sqlx::types::Json;
use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{Tenant, TenantSettings, TenantStatus};
use crate::util::cursor::Cursor;

const COLUMNS: &str = "id, slug, display_name, status, settings, pairwise_salt, created_at, \
     updated_at, data_region, relocating";

pub async fn find_by_slug<'e>(
    exec: impl PgExecutor<'e>,
    slug: &str,
) -> Result<Option<Tenant>, sqlx::Error> {
    sqlx::query_as::<_, Tenant>(
        "SELECT id, slug, display_name, status, settings, pairwise_salt, created_at, updated_at, data_region, relocating \
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
        "SELECT id, slug, display_name, status, settings, pairwise_salt, created_at, updated_at, data_region, relocating \
         FROM tenants WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(exec)
    .await
}

/// Register a tenant. With `data_region` the row is registry-only: the
/// tenant's data (and its seeded roles, scopes and clients) go in the
/// region's database, through [`insert_copy`] there.
pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    id: Uuid,
    slug: &str,
    display_name: &str,
    settings: &TenantSettings,
    data_region: Option<&str>,
) -> Result<Tenant, sqlx::Error> {
    sqlx::query_as::<_, Tenant>(
        "INSERT INTO tenants (id, slug, display_name, settings, data_region, registry_only) \
         VALUES ($1, $2, $3, $4, $5, $5 IS NOT NULL) \
         RETURNING id, slug, display_name, status, settings, pairwise_salt, created_at, updated_at, data_region, relocating",
    )
    .bind(id)
    .bind(slug)
    .bind(display_name)
    .bind(Json(settings))
    .bind(data_region)
    .fetch_one(exec)
    .await
}

/// Copy the registry's row of `t` into the database its data lives in. The
/// insert triggers seed the tenant there, unless the caller set
/// `app.skip_tenant_seed` (a move, which copies the seeded rows too).
pub async fn insert_copy<'e>(exec: impl PgExecutor<'e>, t: &Tenant) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO tenants (id, slug, display_name, status, settings, pairwise_salt, \
         created_at, updated_at, data_region, registry_only, relocating) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false, false)",
    )
    .bind(t.id)
    .bind(&t.slug)
    .bind(&t.display_name)
    .bind(t.status)
    .bind(&t.settings)
    .bind(&t.pairwise_salt)
    .bind(t.created_at)
    .bind(t.updated_at)
    .bind(&t.data_region)
    .execute(exec)
    .await?;
    Ok(())
}

/// Bring a regional copy up to date with the registry's row.
pub async fn update_copy<'e>(exec: impl PgExecutor<'e>, t: &Tenant) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE tenants SET slug = $2, display_name = $3, status = $4, settings = $5, \
         data_region = $6 WHERE id = $1",
    )
    .bind(t.id)
    .bind(&t.slug)
    .bind(&t.display_name)
    .bind(t.status)
    .bind(&t.settings)
    .bind(&t.data_region)
    .execute(exec)
    .await?;
    Ok(())
}

/// Mark the tenant as being moved (`true`, only if it was not already), or
/// no longer (`false`). Returns whether the row changed.
pub async fn set_relocating<'e>(
    exec: impl PgExecutor<'e>,
    id: Uuid,
    relocating: bool,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE tenants SET relocating = $2, updated_at = now() \
         WHERE id = $1 AND relocating IS DISTINCT FROM $2",
    )
    .bind(id)
    .bind(relocating)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// The end of a move: the registry points at the tenant's new database and
/// no longer holds its data when that is a region.
pub async fn set_placement<'e>(
    exec: impl PgExecutor<'e>,
    id: Uuid,
    data_region: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE tenants SET data_region = $2, registry_only = $2 IS NOT NULL, \
         relocating = false, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(data_region)
    .execute(exec)
    .await?;
    Ok(())
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

/// Tenant whose custom domain is `host` (lower-case, as stored).
pub async fn find_by_custom_domain<'e>(
    exec: impl PgExecutor<'e>,
    host: &str,
) -> Result<Option<Tenant>, sqlx::Error> {
    sqlx::query_as::<_, Tenant>(
        "SELECT id, slug, display_name, status, settings, pairwise_salt, created_at, updated_at, data_region, relocating FROM tenants \
         WHERE lower(settings->>'custom_domain') = $1 LIMIT 1",
    )
    .bind(host)
    .fetch_optional(exec)
    .await
}

/// Tenant whose discovery settings list `domain` (lower-case). First match wins.
pub async fn find_by_email_domain<'e>(
    exec: impl PgExecutor<'e>,
    domain: &str,
) -> Result<Option<Tenant>, sqlx::Error> {
    sqlx::query_as::<_, Tenant>(
        "SELECT id, slug, display_name, status, settings, pairwise_salt, created_at, updated_at, data_region, relocating FROM tenants \
         WHERE settings->'discovery'->'email_domains' ? $1 AND status = 'active' \
         ORDER BY created_at LIMIT 1",
    )
    .bind(domain)
    .fetch_optional(exec)
    .await
}

/// How many tenants each data region holds (`None`: the home database).
pub async fn count_by_region<'e>(
    exec: impl PgExecutor<'e>,
) -> Result<Vec<(Option<String>, i64)>, sqlx::Error> {
    sqlx::query_as("SELECT data_region, count(*) FROM tenants GROUP BY data_region")
        .fetch_all(exec)
        .await
}
