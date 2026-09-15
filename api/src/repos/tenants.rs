//! `tenants` is a global table (no RLS); queries take any executor.

use sqlx::PgExecutor;
use uuid::Uuid;

use crate::models::Tenant;

pub async fn find_by_slug<'e>(
    exec: impl PgExecutor<'e>,
    slug: &str,
) -> Result<Option<Tenant>, sqlx::Error> {
    sqlx::query_as::<_, Tenant>(
        "SELECT id, slug, display_name, status, settings, created_at, updated_at \
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
        "SELECT id, slug, display_name, status, settings, created_at, updated_at \
         FROM tenants WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(exec)
    .await
}
