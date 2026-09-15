//! Admin API: signing keys (`/admin/tenants/{slug}/keys`) and the
//! master-key rotation status (`/admin/master-key`, global only).
//!
//! Key lifecycle: pending (published, not signing) → active (signing) →
//! retiring (published for verification until the overlap ends) → revoked
//! (unpublished at once). Private material never leaves the API.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{KeyStatus, RsaBits, SigningAlg, SigningKey};
use crate::services::master_key::{RotationReport, StatusReport};
use crate::services::{keys, master_key};
use crate::state::AppState;

pub fn keys_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(rotate))
        .routes(routes!(get_one))
        .routes(routes!(activate))
        .routes(routes!(retire))
        .routes(routes!(revoke))
        .routes(routes!(master_status))
        .routes(routes!(master_rotate))
}

const P_READ: &str = "ridm:keys:read";
const P_WRITE: &str = "ridm:keys:write";

#[derive(Deserialize)]
struct KeyPath {
    key: Uuid,
}

#[derive(Deserialize, Default, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(default)]
struct ListQuery {
    #[param(inline)]
    status: Option<KeyStatus>,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/keys", tag = "keys", params(("slug" = String, Path, description = "Tenant slug"), ListQuery), responses((status = 200, body = Vec<SigningKey>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Vec<SigningKey>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(keys::list(&state, tenant.id, q.status).await?))
}

#[derive(Deserialize, Default, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
struct CreateKey {
    /// Defaults to the tenant's key policy.
    alg: Option<SigningAlg>,
    /// 2048, 3072 or 4096; defaults to the tenant's key policy.
    rsa_bits: Option<u32>,
    /// Publish only (`pending`) unless set, in which case the key starts
    /// signing at once and the previous active key retires with overlap.
    activate: bool,
    /// Earliest signing time (informational until activation).
    not_before: Option<DateTime<Utc>>,
}

#[utoipa::path(post, path = "/admin/tenants/{slug}/keys", tag = "keys", params(("slug" = String, Path, description = "Tenant slug")), request_body(content = CreateKey, description = "Optional"), responses((status = 201, body = SigningKey), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    body: Option<Json<CreateKey>>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let policy = &tenant.settings.keys;
    let rsa_bits = match body.rsa_bits {
        None => policy.rsa_bits,
        Some(2048) => RsaBits::B2048,
        Some(3072) => RsaBits::B3072,
        Some(4096) => RsaBits::B4096,
        Some(_) => {
            return Err(AppError::BadRequest(
                "rsa_bits must be 2048, 3072 or 4096".into(),
            ));
        }
    };
    let key = keys::create(
        &state,
        tenant.id,
        admin.actor(),
        body.alg.unwrap_or(policy.default_alg),
        rsa_bits,
        KeyStatus::Pending,
        body.not_before,
    )
    .await?;
    let key = if body.activate {
        keys::activate(&state, tenant.id, policy, admin.actor(), key.id).await?
    } else {
        key
    };
    Ok((StatusCode::CREATED, axum::Json(key)).into_response())
}

/// New key with the tenant's default algorithm, active at once; the previous
/// active key retires with the policy's overlap.
#[utoipa::path(post, path = "/admin/tenants/{slug}/keys/rotate", tag = "keys", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 201, body = SigningKey), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn rotate(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let key = keys::rotate(&state, tenant.id, &tenant.settings.keys, admin.actor()).await?;
    Ok((StatusCode::CREATED, axum::Json(key)).into_response())
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/keys/{key}", tag = "keys", params(("slug" = String, Path, description = "Tenant slug"), ("key" = Uuid, Path)), responses((status = 200, body = SigningKey), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(KeyPath { key }): Path<KeyPath>,
) -> AppResult<Json<SigningKey>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(keys::get(&state, tenant.id, key).await?))
}

#[utoipa::path(post, path = "/admin/tenants/{slug}/keys/{key}/activate", tag = "keys", params(("slug" = String, Path, description = "Tenant slug"), ("key" = Uuid, Path)), responses((status = 200, body = SigningKey), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn activate(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(KeyPath { key }): Path<KeyPath>,
) -> AppResult<Json<SigningKey>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        keys::activate(&state, tenant.id, &tenant.settings.keys, admin.actor(), key).await?,
    ))
}

#[utoipa::path(post, path = "/admin/tenants/{slug}/keys/{key}/retire", tag = "keys", params(("slug" = String, Path, description = "Tenant slug"), ("key" = Uuid, Path)), responses((status = 200, body = SigningKey), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn retire(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(KeyPath { key }): Path<KeyPath>,
) -> AppResult<Json<SigningKey>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        keys::retire(&state, tenant.id, &tenant.settings.keys, admin.actor(), key).await?,
    ))
}

/// Unpublish now: tokens signed with the key stop verifying.
#[utoipa::path(post, path = "/admin/tenants/{slug}/keys/{key}/revoke", tag = "keys", params(("slug" = String, Path, description = "Tenant slug"), ("key" = Uuid, Path)), responses((status = 200, body = SigningKey), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(KeyPath { key }): Path<KeyPath>,
) -> AppResult<Json<SigningKey>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        keys::revoke(&state, tenant.id, admin.actor(), key).await?,
    ))
}

#[derive(Serialize, utoipa::ToSchema)]
struct MasterStatus {
    #[serde(flatten)]
    report: StatusReport,
    /// Encrypted rows still under an older generation.
    pending_rows: i64,
}

/// Which master-key generation every encrypted row is under. Spans all
/// tenants, so global administrators only.
#[utoipa::path(get, path = "/admin/master-key", tag = "keys", responses((status = 200, body = MasterStatus), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn master_status(
    State(state): State<AppState>,
    admin: AdminCtx,
) -> AppResult<Json<MasterStatus>> {
    admin.require_global(P_READ)?;
    let report = master_key::status(&state).await?;
    Ok(Json(MasterStatus {
        pending_rows: report.pending(),
        report,
    }))
}

/// Re-encrypt every row still under an older generation with the current
/// master key (the new key itself comes from the environment).
#[utoipa::path(post, path = "/admin/master-key/rotate", tag = "keys", responses((status = 200, body = RotationReport), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn master_rotate(
    State(state): State<AppState>,
    admin: AdminCtx,
) -> AppResult<Json<RotationReport>> {
    admin.require_global(P_WRITE)?;
    Ok(Json(master_key::rotate_all(&state).await?))
}
