//! Admin API: claim mappers (`/admin/tenants/{slug}/claim-mappers`).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{ClaimMapperRow, ClaimMapperUpdate, NewClaimMapper};
use crate::services::claim_mappers;
use crate::state::AppState;

pub fn mappers_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(get_one, update, delete))
}

const P_READ: &str = "ridm:mappers:read";
const P_WRITE: &str = "ridm:mappers:write";

#[derive(Deserialize)]
struct MapperPath {
    mapper: Uuid,
}

#[derive(Deserialize, Default, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(default)]
struct ListQuery {
    /// Only mappers bound to this client.
    client_id: Option<Uuid>,
    /// Only tenant-wide mappers.
    tenant_wide: bool,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/claim-mappers", tag = "mappers", params(("slug" = String, Path, description = "Tenant slug"), ListQuery), responses((status = 200, body = Vec<ClaimMapperRow>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Vec<ClaimMapperRow>>> {
    admin.require(tenant.id, P_READ)?;
    let scope = match (q.client_id, q.tenant_wide) {
        (Some(c), _) => Some(Some(c)),
        (None, true) => Some(None),
        (None, false) => None,
    };
    Ok(Json(claim_mappers::list(&state, tenant.id, scope).await?))
}

/// Body: `{name, client_id?, config}` where `config` is `{type, ..., include_in}`.
#[utoipa::path(post, path = "/admin/tenants/{slug}/claim-mappers", tag = "mappers", params(("slug" = String, Path, description = "Tenant slug")), request_body = NewClaimMapper, responses((status = 201, body = ClaimMapperRow), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<NewClaimMapper>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let m = claim_mappers::create(&state, tenant.id, admin.actor(), body).await?;
    Ok((StatusCode::CREATED, axum::Json(m)).into_response())
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/claim-mappers/{mapper}", tag = "mappers", params(("slug" = String, Path, description = "Tenant slug"), ("mapper" = Uuid, Path)), responses((status = 200, body = ClaimMapperRow), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(MapperPath { mapper }): Path<MapperPath>,
) -> AppResult<Json<ClaimMapperRow>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(claim_mappers::get(&state, tenant.id, mapper).await?))
}

/// `config` replaces the whole document (mapper types differ too much to merge).
#[utoipa::path(patch, path = "/admin/tenants/{slug}/claim-mappers/{mapper}", tag = "mappers", params(("slug" = String, Path, description = "Tenant slug"), ("mapper" = Uuid, Path)), request_body = ClaimMapperUpdate, responses((status = 200, body = ClaimMapperRow), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn update(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(MapperPath { mapper }): Path<MapperPath>,
    Json(body): Json<ClaimMapperUpdate>,
) -> AppResult<Json<ClaimMapperRow>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        claim_mappers::update(&state, tenant.id, admin.actor(), mapper, body).await?,
    ))
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/claim-mappers/{mapper}", tag = "mappers", params(("slug" = String, Path, description = "Tenant slug"), ("mapper" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(MapperPath { mapper }): Path<MapperPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    claim_mappers::delete(&state, tenant.id, admin.actor(), mapper).await?;
    Ok(StatusCode::NO_CONTENT)
}
