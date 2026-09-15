//! Admin API: signing keys (`/admin/tenants/{slug}/keys`) and the
//! master-key rotation status (`/admin/master-key`, global only).
//!
//! Key lifecycle: pending (published, not signing) → active (signing) →
//! retiring (published for verification until the overlap ends) → revoked
//! (unpublished at once). Private material never leaves the API.

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{KeyStatus, RsaBits, SigningAlg, SigningKey};
use crate::services::master_key::{RotationReport, StatusReport};
use crate::services::{keys, master_key};
use crate::state::AppState;

pub fn keys_router() -> Router<AppState> {
    let base = "/admin/tenants/{slug}/keys";
    Router::new()
        .route(base, get(list).post(create))
        .route(&format!("{base}/rotate"), post(rotate))
        .route(&format!("{base}/{{key}}"), get(get_one))
        .route(&format!("{base}/{{key}}/activate"), post(activate))
        .route(&format!("{base}/{{key}}/retire"), post(retire))
        .route(&format!("{base}/{{key}}/revoke"), post(revoke))
        .route("/admin/master-key", get(master_status))
        .route("/admin/master-key/rotate", post(master_rotate))
}

const P_READ: &str = "ridm:keys:read";
const P_WRITE: &str = "ridm:keys:write";

#[derive(Deserialize)]
struct KeyPath {
    key: Uuid,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ListQuery {
    status: Option<KeyStatus>,
}

async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Vec<SigningKey>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(keys::list(&state, tenant.id, q.status).await?))
}

#[derive(Deserialize, Default)]
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
async fn rotate(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let key = keys::rotate(&state, tenant.id, &tenant.settings.keys, admin.actor()).await?;
    Ok((StatusCode::CREATED, axum::Json(key)).into_response())
}

async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(KeyPath { key }): Path<KeyPath>,
) -> AppResult<Json<SigningKey>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(keys::get(&state, tenant.id, key).await?))
}

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

#[derive(Serialize)]
struct MasterStatus {
    #[serde(flatten)]
    report: StatusReport,
    /// Encrypted rows still under an older generation.
    pending_rows: i64,
}

/// Which master-key generation every encrypted row is under. Spans all
/// tenants, so global administrators only.
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
async fn master_rotate(
    State(state): State<AppState>,
    admin: AdminCtx,
) -> AppResult<Json<RotationReport>> {
    admin.require_global(P_WRITE)?;
    Ok(Json(master_key::rotate_all(&state).await?))
}
