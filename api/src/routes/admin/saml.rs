//! Admin API: rIDM as a SAML identity provider (`/admin/tenants/{slug}/saml`).
//!
//! Service providers are clients (`client_type` `saml`), so they need the
//! client permissions; the SAML signing keys need the key permissions.
//! A key rollover is: add a pending key (metadata lists it at once), let
//! the SPs pick up the metadata, activate it, delete the old one.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::services::saml_keys::{self, SamlKeyView};
use crate::services::saml_sps::{self, SamlSpInput, SamlSpView};
use crate::services::{clients, saml_idp};
use crate::state::AppState;

pub fn saml_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(idp))
        .routes(routes!(add_key))
        .routes(routes!(activate_key))
        .routes(routes!(delete_key))
        .routes(routes!(list, create))
        .routes(routes!(import_metadata))
        .routes(routes!(get_one, replace, delete))
}

const P_CLIENTS_READ: &str = "ridm:clients:read";
const P_CLIENTS_WRITE: &str = "ridm:clients:write";
const P_KEYS_WRITE: &str = "ridm:keys:write";

/// The IdP side: what to give an SP, and the signing keys.
#[derive(Serialize, utoipa::ToSchema)]
struct IdpView {
    entity_id: String,
    sso_url: String,
    slo_url: String,
    metadata_url: String,
    /// IdP-initiated sign-in: add `?sp=<entity ID or client id>`.
    init_url: String,
    keys: Vec<SamlKeyView>,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/saml", tag = "saml", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = IdpView), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn idp(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<IdpView>> {
    admin.require(tenant.id, P_CLIENTS_READ)?;
    saml_keys::ensure_active(&state, &tenant).await?;
    let ep = saml_idp::endpoints(&state, &tenant);
    Ok(Json(IdpView {
        init_url: format!("{}/saml/init", ep.entity_id),
        entity_id: ep.entity_id,
        sso_url: ep.sso_url,
        slo_url: ep.slo_url,
        metadata_url: ep.metadata_url,
        keys: saml_keys::list(&state, tenant.id).await?,
    }))
}

#[derive(Deserialize)]
struct KeyPath {
    key: Uuid,
}

/// Start a rollover: a new key, listed in metadata at once but not signing.
#[utoipa::path(post, path = "/admin/tenants/{slug}/saml/keys", tag = "saml", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 201, body = SamlKeyView), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 409, description = "A pending key exists", body = crate::error::Problem)), security(("bearer" = [])))]
async fn add_key(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Response> {
    admin.require(tenant.id, P_KEYS_WRITE)?;
    let key = saml_keys::add_pending(&state, &tenant, admin.actor()).await?;
    Ok((StatusCode::CREATED, axum::Json(key)).into_response())
}

/// Sign with this key from now on; the active one before it is kept in
/// metadata as `retiring` until deleted.
#[utoipa::path(post, path = "/admin/tenants/{slug}/saml/keys/{key}/activate", tag = "saml", params(("slug" = String, Path, description = "Tenant slug"), ("key" = Uuid, Path)), responses((status = 204), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn activate_key(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(KeyPath { key }): Path<KeyPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_KEYS_WRITE)?;
    saml_keys::activate(&state, tenant.id, admin.actor(), key).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Remove a pending or retiring key from metadata.
#[utoipa::path(delete, path = "/admin/tenants/{slug}/saml/keys/{key}", tag = "saml", params(("slug" = String, Path, description = "Tenant slug"), ("key" = Uuid, Path)), responses((status = 204), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 409, description = "The active key cannot be deleted", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete_key(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(KeyPath { key }): Path<KeyPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_KEYS_WRITE)?;
    saml_keys::delete(&state, tenant.id, admin.actor(), key).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/saml/service-providers", tag = "saml", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Vec<SamlSpView>), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<Vec<SamlSpView>>> {
    admin.require(tenant.id, P_CLIENTS_READ)?;
    Ok(Json(saml_sps::list(&state, tenant.id).await?))
}

#[utoipa::path(post, path = "/admin/tenants/{slug}/saml/service-providers", tag = "saml", params(("slug" = String, Path, description = "Tenant slug")), request_body = SamlSpInput, responses((status = 201, body = SamlSpView), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 409, description = "The entity ID or client id is taken", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<SamlSpInput>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_CLIENTS_WRITE)?;
    let sp = saml_sps::create(&state, tenant.id, admin.actor(), body).await?;
    Ok((StatusCode::CREATED, axum::Json(sp)).into_response())
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct MetadataBody {
    /// The SP's metadata document (XML).
    metadata: String,
}

/// Read an SP's metadata into a registration to review; nothing is saved.
#[utoipa::path(post, path = "/admin/tenants/{slug}/saml/service-providers/metadata", tag = "saml", params(("slug" = String, Path, description = "Tenant slug")), request_body = MetadataBody, responses((status = 200, body = SamlSpInput), (status = 400, description = "Not usable SP metadata", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem)), security(("bearer" = [])))]
async fn import_metadata(
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<MetadataBody>,
) -> AppResult<Json<SamlSpInput>> {
    admin.require(tenant.id, P_CLIENTS_WRITE)?;
    Ok(Json(saml_sps::from_metadata(&body.metadata)?))
}

#[derive(Deserialize)]
struct SpPath {
    sp: Uuid,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/saml/service-providers/{sp}", tag = "saml", params(("slug" = String, Path, description = "Tenant slug"), ("sp" = Uuid, Path, description = "The client's row id")), responses((status = 200, body = SamlSpView), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(SpPath { sp }): Path<SpPath>,
) -> AppResult<Json<SamlSpView>> {
    admin.require(tenant.id, P_CLIENTS_READ)?;
    Ok(Json(saml_sps::get(&state, tenant.id, sp).await?))
}

/// Replace the SP's settings (the public client id and status are kept).
#[utoipa::path(put, path = "/admin/tenants/{slug}/saml/service-providers/{sp}", tag = "saml", params(("slug" = String, Path, description = "Tenant slug"), ("sp" = Uuid, Path, description = "The client's row id")), request_body = SamlSpInput, responses((status = 200, body = SamlSpView), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem), (status = 409, description = "The entity ID is taken", body = crate::error::Problem)), security(("bearer" = [])))]
async fn replace(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(SpPath { sp }): Path<SpPath>,
    Json(body): Json<SamlSpInput>,
) -> AppResult<Json<SamlSpView>> {
    admin.require(tenant.id, P_CLIENTS_WRITE)?;
    Ok(Json(
        saml_sps::replace(&state, tenant.id, admin.actor(), sp, body).await?,
    ))
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/saml/service-providers/{sp}", tag = "saml", params(("slug" = String, Path, description = "Tenant slug"), ("sp" = Uuid, Path, description = "The client's row id")), responses((status = 204), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(SpPath { sp }): Path<SpPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_CLIENTS_WRITE)?;
    // Only a SAML client is deleted here.
    saml_sps::get(&state, tenant.id, sp).await?;
    clients::delete(&state, tenant.id, admin.actor(), sp).await?;
    Ok(StatusCode::NO_CONTENT)
}
