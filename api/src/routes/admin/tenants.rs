//! Admin API: tenants (`/admin/tenants`).
//!
//! Listing, reading and changing settings are available to any administrator
//! whose scope reaches the tenant; creating and deleting tenants are global
//! operations. Settings are changed with a JSON merge patch (RFC 7396) so an
//! auto-saving UI can send just the fields that changed.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::error::{AppError, AppResult};
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{
    CaptchaConfig, CaptchaProvider, ProviderKind, Tenant, TenantSettings, TenantStatus,
};
use crate::services::tenants::{self, NewTenant, TenantUpdate};
use crate::services::{captcha, profile_schema, provider_settings};
use crate::state::AppState;
use crate::util::cursor::Page;
use crate::util::patch::{diff_paths, merge_patch};

pub fn tenants_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(get_one, update, delete))
        .routes(routes!(captcha_get, captcha_put, captcha_delete))
        .routes(routes!(profile_schema_get, profile_schema_put))
}

const P_READ: &str = "ridm:tenants:read";
const P_WRITE: &str = "ridm:tenants:write";
const P_CREATE: &str = "ridm:tenants:create";
const P_DELETE: &str = "ridm:tenants:delete";

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct ListQuery {
    cursor: Option<String>,
    limit: Option<u32>,
}

/// Global administrators see every tenant; tenant-scoped ones see their own.
#[utoipa::path(get, path = "/admin/tenants", tag = "tenants", params(ListQuery), responses((status = 200, body = Page<Tenant>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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

#[utoipa::path(post, path = "/admin/tenants", tag = "tenants", request_body = NewTenant, responses((status = 201, body = Tenant), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    Json(body): Json<NewTenant>,
) -> AppResult<Response> {
    admin.require_global(P_CREATE)?;
    let tenant = tenants::create(&state, admin.actor(), body).await?;
    Ok((StatusCode::CREATED, axum::Json(tenant)).into_response())
}

#[utoipa::path(get, path = "/admin/tenants/{slug}", tag = "tenants", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Tenant), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<Tenant>> {
    admin.require(tenant.id, P_READ)?;
    // The cache may lag a concurrent write by another node; read through.
    Ok(Json(tenants::get(&state, tenant.id).await?))
}

#[derive(Deserialize, Default, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
struct TenantPatch {
    display_name: Option<String>,
    status: Option<TenantStatus>,
    /// Merge patch applied to the current settings document.
    settings: Option<serde_json::Value>,
}

#[utoipa::path(patch, path = "/admin/tenants/{slug}", tag = "tenants", params(("slug" = String, Path, description = "Tenant slug")), request_body = TenantPatch, responses((status = 200, body = Tenant), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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

#[utoipa::path(delete, path = "/admin/tenants/{slug}", tag = "tenants", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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
#[derive(Serialize, utoipa::ToSchema)]
struct CaptchaView {
    provider: CaptchaProvider,
    site_key: String,
    /// Always true when configured; the secret itself is never returned.
    secret_set: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    verify_url: Option<String>,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/captcha", tag = "tenants", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = CaptchaView), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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

#[utoipa::path(put, path = "/admin/tenants/{slug}/captcha", tag = "tenants", params(("slug" = String, Path, description = "Tenant slug")), request_body = CaptchaConfig, responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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

#[utoipa::path(delete, path = "/admin/tenants/{slug}/captcha", tag = "tenants", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn captcha_delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    captcha::disable(&state, tenant.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The tenant's user profile schema: declared attributes, their types,
/// validation, who may edit them and where they surface.
#[utoipa::path(get, path = "/admin/tenants/{slug}/profile-schema", tag = "tenants", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = crate::models::ProfileSchema), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn profile_schema_get(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<crate::models::ProfileSchema>> {
    admin.require(tenant.id, P_READ)?;
    let schema = profile_schema::get(&state, tenant.id).await?;
    Ok(Json((*schema).clone()))
}

/// Replace the profile schema. Validated structurally (names, types,
/// enum values, patterns); existing attribute values are not rewritten.
#[utoipa::path(put, path = "/admin/tenants/{slug}/profile-schema", tag = "tenants", params(("slug" = String, Path, description = "Tenant slug")), request_body = crate::models::ProfileSchema, responses((status = 200, body = crate::models::ProfileSchema), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn profile_schema_put(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<crate::models::ProfileSchema>,
) -> AppResult<Json<crate::models::ProfileSchema>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        profile_schema::set(&state, tenant.id, admin.actor(), body).await?,
    ))
}
