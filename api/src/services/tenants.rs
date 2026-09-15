//! Tenant lifecycle. `tenants` is global, so no RLS binding is needed, but
//! every write invalidates the tenant cache on all nodes.

use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::{is_valid_slug, tenant_cache_keys};
use crate::models::{MASTER_TENANT_ID, Tenant, TenantSettings, TenantStatus};
use crate::repos;
use crate::state::AppState;
use crate::util::cursor::{Cursor, Page, page_size};

#[derive(Debug, Clone, Deserialize)]
pub struct NewTenant {
    pub slug: String,
    pub display_name: String,
    #[serde(default)]
    pub settings: Option<TenantSettings>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TenantUpdate {
    pub display_name: Option<String>,
    pub status: Option<TenantStatus>,
    pub settings: Option<TenantSettings>,
}

pub async fn create(state: &AppState, actor: Actor, input: NewTenant) -> AppResult<Tenant> {
    let slug = input.slug.trim().to_lowercase();
    if !is_valid_slug(&slug) {
        return Err(AppError::BadRequest(
            "slug must be 1-63 lowercase letters, digits or hyphens".into(),
        ));
    }
    let display_name = input.display_name.trim();
    if display_name.is_empty() || display_name.len() > 255 {
        return Err(AppError::BadRequest(
            "display_name must be 1-255 characters".into(),
        ));
    }
    let settings = input.settings.unwrap_or_default();
    let tenant = repos::tenants::insert(&state.db, Uuid::now_v7(), &slug, display_name, &settings)
        .await
        .map_err(|e| match AppError::from_db(e) {
            AppError::Conflict(_) => AppError::Conflict(format!("tenant slug `{slug}` is taken")),
            other => other,
        })?;
    // A negative cache entry may exist for this slug from earlier lookups.
    state.cache.invalidate(&tenant_cache_keys(&tenant)).await?;
    state.events.publish(Event::new(
        Some(tenant.id),
        actor,
        EventKind::TenantCreated {
            tenant_id: tenant.id,
        },
    ));
    Ok(tenant)
}

pub async fn get(state: &AppState, id: Uuid) -> AppResult<Tenant> {
    repos::tenants::find_by_id(&state.db, id)
        .await?
        .ok_or(AppError::NotFound("tenant"))
}

pub async fn update(
    state: &AppState,
    actor: Actor,
    id: Uuid,
    patch: TenantUpdate,
) -> AppResult<Tenant> {
    if let Some(name) = &patch.display_name
        && (name.trim().is_empty() || name.len() > 255)
    {
        return Err(AppError::BadRequest(
            "display_name must be 1-255 characters".into(),
        ));
    }
    if id == MASTER_TENANT_ID && patch.status == Some(TenantStatus::Disabled) {
        return Err(AppError::BadRequest(
            "the master tenant cannot be disabled".into(),
        ));
    }
    // Cache keys derived from settings (e.g. discovery domains) can change
    // with this update: evict both the old and the new derivations.
    let before = get(state, id).await?;
    let tenant = repos::tenants::update(
        &state.db,
        id,
        patch.display_name.as_deref().map(str::trim),
        patch.status,
        patch.settings.as_ref(),
    )
    .await
    .map_err(AppError::from_db)?
    .ok_or(AppError::NotFound("tenant"))?;
    let mut keys = tenant_cache_keys(&before);
    keys.extend(tenant_cache_keys(&tenant));
    keys.sort();
    keys.dedup();
    state.cache.invalidate(&keys).await?;
    state.events.publish(Event::new(
        Some(tenant.id),
        actor,
        EventKind::TenantUpdated {
            tenant_id: tenant.id,
        },
    ));
    Ok(tenant)
}

/// Permanently delete a tenant and everything in it (cascade).
pub async fn delete(state: &AppState, actor: Actor, id: Uuid) -> AppResult<()> {
    if id == MASTER_TENANT_ID {
        return Err(AppError::BadRequest(
            "the master tenant cannot be deleted".into(),
        ));
    }
    let tenant = get(state, id).await?;
    // Cascading deletes touch RLS-protected tables; run with bypass.
    let mut tx = crate::db::bypass_tx(&state.db).await?;
    let deleted = repos::tenants::delete(&mut *tx, id)
        .await
        .map_err(AppError::from_db)?;
    tx.commit().await?;
    if !deleted {
        return Err(AppError::NotFound("tenant"));
    }
    state.cache.invalidate(&tenant_cache_keys(&tenant)).await?;
    state.events.publish(Event::new(
        Some(id),
        actor,
        EventKind::TenantDeleted { tenant_id: id },
    ));
    Ok(())
}

pub async fn list(
    state: &AppState,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> AppResult<Page<Tenant>> {
    let after = cursor.map(Cursor::decode).transpose()?;
    let limit = page_size(limit);
    let rows = repos::tenants::list(&state.db, after, limit).await?;
    Ok(Page::from_rows(rows, limit, |t| Cursor {
        created_at: t.created_at,
        id: t.id,
    }))
}
