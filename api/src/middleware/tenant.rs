//! Tenant resolution for `/t/{slug}/...` routes.
//!
//! `TenantCtx` is an axum extractor: it reads the `slug` path parameter,
//! resolves it through the cache, and rejects unknown or disabled tenants.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{FromRequestParts, Path};
use axum::http::request::Parts;
use serde::Deserialize;

use crate::cache::keys;
use crate::error::AppError;
use crate::models::Tenant;
use crate::repos;
use crate::state::AppState;

/// Redis TTL for tenant documents; invalidated eagerly on every write anyway.
pub const TENANT_CACHE_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
pub struct TenantCtx {
    pub tenant: Arc<Tenant>,
}

impl TenantCtx {
    pub fn id(&self) -> uuid::Uuid {
        self.tenant.id
    }

    pub fn slug(&self) -> &str {
        &self.tenant.slug
    }

    /// Issuer URL for this tenant.
    pub fn issuer(&self, state: &AppState) -> String {
        match &self.tenant.settings.custom_domain {
            Some(host) => format!("https://{host}"),
            None => state.config.issuer_for(&self.tenant.slug),
        }
    }
}

#[derive(Deserialize)]
struct SlugPath {
    slug: String,
}

/// Resolve a tenant by slug through the cache. `Ok(None)` when it does not exist.
pub async fn resolve_tenant(state: &AppState, slug: &str) -> Result<Option<Arc<Tenant>>, AppError> {
    if !is_valid_slug(slug) {
        return Ok(None);
    }
    let db = state.db.clone();
    let slug_owned = slug.to_string();
    state
        .cache
        .get_or_load(
            &keys::tenant_by_slug(slug),
            TENANT_CACHE_TTL,
            || async move { Ok(repos::tenants::find_by_slug(&db, &slug_owned).await?) },
        )
        .await
}

/// Cache keys that must be evicted whenever a tenant row changes.
pub fn tenant_cache_keys(tenant: &Tenant) -> Vec<String> {
    let mut v = vec![
        keys::tenant_by_slug(&tenant.slug),
        keys::tenant_by_id(tenant.id),
        keys::jwks(tenant.id),
        keys::discovery(tenant.id),
    ];
    for d in &tenant.settings.discovery.email_domains {
        v.push(keys::tenant_by_email_domain(&d.to_lowercase()));
    }
    v
}

/// Same rule as the `tenants_slug_format` check constraint.
pub fn is_valid_slug(slug: &str) -> bool {
    let bytes = slug.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    let ok_char = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-';
    bytes.iter().all(ok_char) && bytes[0] != b'-' && bytes[bytes.len() - 1] != b'-'
}

impl FromRequestParts<AppState> for TenantCtx {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let Path(SlugPath { slug }) = Path::<SlugPath>::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::NotFound("tenant"))?;
        let tenant = resolve_tenant(state, &slug)
            .await?
            .ok_or(AppError::NotFound("tenant"))?;
        if !tenant.is_active() {
            return Err(AppError::Forbidden("tenant is disabled".into()));
        }
        Ok(Self { tenant })
    }
}

#[cfg(test)]
mod tests {
    use super::is_valid_slug;

    #[test]
    fn slug_validation() {
        assert!(is_valid_slug("master"));
        assert!(is_valid_slug("acme-corp-2"));
        assert!(!is_valid_slug(""));
        assert!(!is_valid_slug("-acme"));
        assert!(!is_valid_slug("acme-"));
        assert!(!is_valid_slug("Acme"));
        assert!(!is_valid_slug("a b"));
        assert!(!is_valid_slug(&"a".repeat(64)));
    }
}
