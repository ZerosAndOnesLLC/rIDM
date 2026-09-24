//! Tenant lifecycle. `tenants` is global, so no RLS binding is needed, but
//! every write invalidates the tenant cache on all nodes. The registry is in
//! the home database; a tenant created in a data region also gets a copy of
//! its row in that region's database, where its data lives.

use std::sync::Arc;

use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::Deserialize;
use uuid::Uuid;

use crate::cache::keys;
use crate::config::HOME_REGION;
use crate::error::{AppError, AppResult};
use crate::middleware::{TENANT_CACHE_TTL, is_valid_slug, tenant_cache_keys};
use crate::models::{MASTER_TENANT_ID, Tenant, TenantSettings, TenantStatus};
use crate::repos;
use crate::services::{features, impersonation, locale, rate_limit};
use crate::state::AppState;
use crate::util::cursor::{Cursor, Page, page_size};

#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct NewTenant {
    pub slug: String,
    pub display_name: String,
    #[serde(default)]
    pub settings: Option<TenantSettings>,
    /// The data region to keep the tenant's data in, one of
    /// `GET /admin/regions`; absent or `home`: the home database. Fixed at
    /// creation; `ridm-api move-tenant` moves a tenant later.
    #[serde(default)]
    pub data_region: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
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
    let mut settings = input.settings.unwrap_or_default();
    locale::validate_settings(&mut settings.locale)?;
    rate_limit::validate_policy(&settings.rate_limits)?;
    impersonation::validate_policy(&settings.impersonation)?;
    features::validate(&settings.features)?;
    settings.custom_domain = normalize_custom_domain(state, settings.custom_domain.as_deref())?;
    let region = region_for_new_tenant(state, input.data_region.as_deref())?;
    let tenant = repos::tenants::insert(
        state.db.home(),
        Uuid::now_v7(),
        &slug,
        display_name,
        &settings,
        region.and_then(|d| d.region()),
    )
    .await
    .map_err(|e| match AppError::from_db(e) {
        AppError::Conflict(_) if settings.custom_domain.is_some() => AppError::Conflict(format!(
            "tenant slug `{slug}` is taken or custom_domain is already used"
        )),
        AppError::Conflict(_) => AppError::Conflict(format!("tenant slug `{slug}` is taken")),
        other => other,
    })?;
    if let Some(database) = region
        && let Err(err) = repos::tenants::insert_copy(&database.primary, &tenant).await
    {
        // The registry must not point at a region that has no copy.
        if let Err(undo) = repos::tenants::delete(state.db.home(), tenant.id).await {
            tracing::error!(tenant = %tenant.id, error = %undo, "could not undo a tenant's registration");
        }
        return Err(AppError::from_db(err));
    }
    // A negative cache entry may exist for this slug from earlier lookups.
    state.cache.invalidate(&tenant_cache_keys(&tenant)).await?;
    state.events.publish(Event::new(
        Some(tenant.id),
        actor,
        EventKind::TenantCreated {
            tenant_id: tenant.id,
        },
    ));
    // The admin console signs in through a built-in client in every tenant.
    super::admin_console::ensure(state, tenant.id).await?;
    super::account_console::ensure(state, &tenant).await?;
    Ok(tenant)
}

/// The database a new tenant's data goes in: `None` for the home database,
/// or a configured region.
fn region_for_new_tenant<'a>(
    state: &'a AppState,
    requested: Option<&str>,
) -> AppResult<Option<&'a crate::db::Database>> {
    let Some(name) = requested
        .map(str::trim)
        .filter(|r| !r.is_empty() && *r != HOME_REGION)
    else {
        return Ok(None);
    };
    match state.db.get(Some(name)) {
        Some(database) => Ok(Some(database)),
        None => {
            let known: Vec<&str> = state.db.all().iter().map(|d| &*d.name).collect();
            Err(AppError::BadRequest(format!(
                "unknown data region `{name}`; this deployment has: {}",
                known.join(", ")
            )))
        }
    }
}

/// Lower-case a custom domain and reject anything that is not a hostname
/// (with an optional port) or that is one of the deployment's own hosts.
pub fn normalize_custom_domain(state: &AppState, raw: Option<&str>) -> AppResult<Option<String>> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let host = raw.to_ascii_lowercase();
    let (name, port) = match host.rsplit_once(':') {
        Some((n, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (n, Some(p)),
        _ => (host.as_str(), None),
    };
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    let valid = !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(label_ok)
        && port.is_none_or(|p| p.parse::<u16>().is_ok_and(|n| n > 0));
    if !valid {
        return Err(AppError::BadRequest(
            "custom_domain must be a hostname such as login.example.com".into(),
        ));
    }
    if state.config.is_primary_host(&host) {
        return Err(AppError::BadRequest(
            "custom_domain may not be the deployment's own host".into(),
        ));
    }
    Ok(Some(host))
}

/// Cached lookup by id (same cache the slug resolver uses; evicted on every write).
pub async fn get_cached(state: &AppState, id: Uuid) -> AppResult<Option<Arc<Tenant>>> {
    let db = state.db.clone();
    state
        .cache
        .get_or_load(&keys::tenant_by_id(id), TENANT_CACHE_TTL, || async move {
            Ok(repos::tenants::find_by_id(db.home(), id).await?)
        })
        .await
}

pub async fn get(state: &AppState, id: Uuid) -> AppResult<Tenant> {
    repos::tenants::find_by_id(state.db.home(), id)
        .await?
        .ok_or(AppError::NotFound("tenant"))
}

pub async fn update(
    state: &AppState,
    actor: Actor,
    id: Uuid,
    mut patch: TenantUpdate,
) -> AppResult<Tenant> {
    if let Some(settings) = patch.settings.as_mut() {
        locale::validate_settings(&mut settings.locale)?;
        rate_limit::validate_policy(&settings.rate_limits)?;
        impersonation::validate_policy(&settings.impersonation)?;
        features::validate(&settings.features)?;
        settings.custom_domain = normalize_custom_domain(state, settings.custom_domain.as_deref())?;
    }
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
    if before.relocating {
        return Err(AppError::Conflict(
            "the tenant is being moved to another region".into(),
        ));
    }
    let tenant = repos::tenants::update(
        state.db.home(),
        id,
        patch.display_name.as_deref().map(str::trim),
        patch.status,
        patch.settings.as_ref(),
    )
    .await
    .map_err(|e| match AppError::from_db(e) {
        AppError::Conflict(_) => {
            AppError::Conflict("custom_domain is already used by another tenant".into())
        }
        other => other,
    })?
    .ok_or(AppError::NotFound("tenant"))?;
    // Only the foreign keys read the regional copy, so a copy left behind
    // is harmless and caught up by the next change.
    if let Some(database) = tenant
        .data_region
        .as_deref()
        .and_then(|r| state.db.get(Some(r)))
        && let Err(err) = repos::tenants::update_copy(&database.primary, &tenant).await
    {
        tracing::warn!(tenant = %tenant.id, region = %database.name, error = %err, "regional copy of the tenant not updated");
    }
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
    // The account console is served on the custom domain too; its client
    // follows the domain.
    if before.settings.custom_domain != tenant.settings.custom_domain {
        super::account_console::ensure(state, &tenant).await?;
    }
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
    if tenant.relocating {
        return Err(AppError::Conflict(
            "the tenant is being moved to another region".into(),
        ));
    }
    // Remember where it lived, for the events recorded after it is gone.
    state.db.locate(id).await?;
    // The tenant's data first, in its region: the registry row goes last so
    // a failure leaves the tenant findable, to be deleted again.
    if let Some(region) = tenant.data_region.as_deref() {
        let database = state.db.get(Some(region)).ok_or_else(|| {
            AppError::Unavailable(format!(
                "data region `{region}` is not configured on this node"
            ))
        })?;
        let mut tx = crate::db::bypass_tx(&database.primary).await?;
        repos::tenants::delete(&mut *tx, id)
            .await
            .map_err(AppError::from_db)?;
        tx.commit().await?;
    }
    // Cascading deletes touch RLS-protected tables; run with bypass.
    let mut tx = crate::db::bypass_tx(state.db.home()).await?;
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

/// Tenants per data region (`None`: the home database).
pub async fn count_by_region(
    state: &AppState,
) -> AppResult<std::collections::HashMap<Option<String>, i64>> {
    Ok(repos::tenants::count_by_region(state.db.home())
        .await?
        .into_iter()
        .collect())
}

pub async fn list(
    state: &AppState,
    search: Option<&str>,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> AppResult<Page<Tenant>> {
    let after = cursor.map(Cursor::decode).transpose()?;
    let limit = page_size(limit);
    let rows = repos::tenants::list(state.db.home(), search, after, limit).await?;
    Ok(Page::from_rows(rows, limit, |t| Cursor {
        created_at: t.created_at,
        id: t.id,
    }))
}
