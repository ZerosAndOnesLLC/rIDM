//! Admin API: tenants (`/admin/tenants`).
//!
//! Listing, reading and changing settings are available to any administrator
//! whose scope reaches the tenant; creating and deleting tenants are global
//! operations. Settings are changed with a JSON merge patch (RFC 7396) so an
//! auto-saving UI can send just the fields that changed.

use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{
    CaptchaConfig, CaptchaProvider, ProviderKind, Tenant, TenantSettings, TenantStatus,
};
use crate::services::tenants::{self, NewTenant, TenantUpdate};
use crate::services::{captcha, provider_settings};
use crate::state::AppState;
use crate::util::cursor::Page;
use crate::util::patch::{diff_paths, merge_patch};

pub fn tenants_router() -> Router<AppState> {
    Router::new()
        .route("/admin/tenants", get(list).post(create))
        .route(
            "/admin/tenants/{slug}",
            get(get_one).patch(update).delete(delete),
        )
        .route(
            "/admin/tenants/{slug}/captcha",
            get(captcha_get).put(captcha_put).delete(captcha_delete),
        )
}

const P_READ: &str = "ridm:tenants:read";
const P_WRITE: &str = "ridm:tenants:write";
const P_CREATE: &str = "ridm:tenants:create";
const P_DELETE: &str = "ridm:tenants:delete";

#[derive(Deserialize)]
struct ListQuery {
    cursor: Option<String>,
    limit: Option<u32>,
}

/// Global administrators see every tenant; tenant-scoped ones see their own.
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Page<Tenant>>> {
    if admin.is_global() {
        admin.require_global(P_READ)?;
        return Ok(Json(
            tenants::list(&state, q.cursor.as_deref(), q.limit).await?,
        ));
    }
    admin.require(admin.tenant.id, P_READ)?;
    let own = tenants::get(&state, admin.tenant.id).await?;
    Ok(Json(Page {
        items: vec![own],
        next_cursor: None,
    }))
}

async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    Json(body): Json<NewTenant>,
) -> AppResult<Response> {
    admin.require_global(P_CREATE)?;
    let tenant = tenants::create(&state, admin.actor(), body).await?;
    Ok((StatusCode::CREATED, axum::Json(tenant)).into_response())
}

async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<Tenant>> {
    admin.require(tenant.id, P_READ)?;
    // The cache may lag a concurrent write by another node; read through.
    Ok(Json(tenants::get(&state, tenant.id).await?))
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct TenantPatch {
    display_name: Option<String>,
    status: Option<TenantStatus>,
    /// Merge patch applied to the current settings document.
    settings: Option<serde_json::Value>,
}

async fn update(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<TenantPatch>,
) -> AppResult<Json<Tenant>> {
    admin.require(tenant.id, P_WRITE)?;
    let settings = match body.settings {
        Some(patch) => {
            if !patch.is_object() {
                return Err(AppError::BadRequest("settings must be an object".into()));
            }
            let current = tenants::get(&state, tenant.id).await?;
            let mut doc = serde_json::to_value(&current.settings.0)?;
            merge_patch(&mut doc, &patch);
            let settings: TenantSettings = serde_json::from_value(doc.clone())
                .map_err(|e| AppError::BadRequest(format!("invalid settings: {e}")))?;
            // Stored documents tolerate unknown members (forward compatibility),
            // but an administrator naming one is almost certainly a typo.
            let dropped = diff_paths(&doc, &serde_json::to_value(&settings)?);
            if !dropped.is_empty() {
                return Err(AppError::BadRequest(format!(
                    "unknown settings fields: {}",
                    dropped.join(", ")
                )));
            }
            Some(settings)
        }
        None => None,
    };
    let updated = tenants::update(
        &state,
        admin.actor(),
        tenant.id,
        TenantUpdate {
            display_name: body.display_name,
            status: body.status,
            settings,
        },
    )
    .await?;
    Ok(Json(updated))
}

async fn delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<StatusCode> {
    admin.require_global(P_DELETE)?;
    tenants::delete(&state, admin.actor(), tenant.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// CAPTCHA provider configuration with the secret redacted.
#[derive(Serialize)]
struct CaptchaView {
    provider: CaptchaProvider,
    site_key: String,
    /// Always true when configured; the secret itself is never returned.
    secret_set: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    verify_url: Option<String>,
}

async fn captcha_get(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Response> {
    admin.require(tenant.id, P_READ)?;
    match provider_settings::get::<CaptchaConfig>(&state, tenant.id, ProviderKind::Captcha).await? {
        Some(cfg) => Ok(axum::Json(CaptchaView {
            provider: cfg.provider,
            site_key: cfg.site_key.clone(),
            secret_set: !cfg.secret.is_empty(),
            verify_url: cfg.verify_url.clone(),
        })
        .into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

async fn captcha_put(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(cfg): Json<CaptchaConfig>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    if cfg.site_key.trim().is_empty() || cfg.secret.trim().is_empty() {
        return Err(AppError::BadRequest(
            "site_key and secret are required".into(),
        ));
    }
    captcha::configure(&state, tenant.id, &cfg).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn captcha_delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    captcha::disable(&state, tenant.id).await?;
    Ok(StatusCode::NO_CONTENT)
}
