//! Admin API: resource servers (`/admin/tenants/{slug}/resource-servers`)
//! and their permissions. The built-in `urn:ridm:admin` server is read-only.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{
    NewPermission, NewResourceServer, Permission, ResourceServer, ResourceServerUpdate,
};
use crate::services::resource_servers;
use crate::state::AppState;

pub fn resource_servers_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(get_one, update, delete))
        .routes(routes!(permissions, create_permission))
        .routes(routes!(delete_permission))
}

const P_READ: &str = "ridm:resource-servers:read";
const P_WRITE: &str = "ridm:resource-servers:write";

#[derive(Deserialize)]
struct RsPath {
    rs: Uuid,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/resource-servers", tag = "resource_servers", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Vec<ResourceServer>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<Vec<ResourceServer>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(resource_servers::list(&state, tenant.id).await?))
}

#[utoipa::path(post, path = "/admin/tenants/{slug}/resource-servers", tag = "resource_servers", params(("slug" = String, Path, description = "Tenant slug")), request_body = NewResourceServer, responses((status = 201, body = ResourceServer), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<NewResourceServer>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let rs = resource_servers::create(&state, tenant.id, admin.actor(), body).await?;
    Ok((StatusCode::CREATED, axum::Json(rs)).into_response())
}

#[derive(Serialize, utoipa::ToSchema)]
struct ResourceServerDetail {
    #[serde(flatten)]
    resource_server: ResourceServer,
    permissions: Vec<Permission>,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/resource-servers/{rs}", tag = "resource_servers", params(("slug" = String, Path, description = "Tenant slug"), ("rs" = Uuid, Path)), responses((status = 200, body = ResourceServerDetail), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RsPath { rs }): Path<RsPath>,
) -> AppResult<Json<ResourceServerDetail>> {
    admin.require(tenant.id, P_READ)?;
    let server = resource_servers::get(&state, tenant.id, rs).await?;
    Ok(Json(ResourceServerDetail {
        permissions: resource_servers::list_permissions(&state, tenant.id, rs).await?,
        resource_server: server,
    }))
}

#[utoipa::path(patch, path = "/admin/tenants/{slug}/resource-servers/{rs}", tag = "resource_servers", params(("slug" = String, Path, description = "Tenant slug"), ("rs" = Uuid, Path)), request_body = ResourceServerUpdate, responses((status = 200, body = ResourceServer), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn update(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RsPath { rs }): Path<RsPath>,
    Json(body): Json<ResourceServerUpdate>,
) -> AppResult<Json<ResourceServer>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        resource_servers::update(&state, tenant.id, admin.actor(), rs, body).await?,
    ))
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/resource-servers/{rs}", tag = "resource_servers", params(("slug" = String, Path, description = "Tenant slug"), ("rs" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RsPath { rs }): Path<RsPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    resource_servers::delete(&state, tenant.id, admin.actor(), rs).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/resource-servers/{rs}/permissions", tag = "resource_servers", params(("slug" = String, Path, description = "Tenant slug"), ("rs" = Uuid, Path)), responses((status = 200, body = Vec<Permission>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn permissions(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RsPath { rs }): Path<RsPath>,
) -> AppResult<Json<Vec<Permission>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(
        resource_servers::list_permissions(&state, tenant.id, rs).await?,
    ))
}

#[utoipa::path(post, path = "/admin/tenants/{slug}/resource-servers/{rs}/permissions", tag = "resource_servers", params(("slug" = String, Path, description = "Tenant slug"), ("rs" = Uuid, Path)), request_body = NewPermission, responses((status = 201, body = Permission), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create_permission(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RsPath { rs }): Path<RsPath>,
    Json(body): Json<NewPermission>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let p = resource_servers::create_permission(&state, tenant.id, admin.actor(), rs, body).await?;
    Ok((StatusCode::CREATED, axum::Json(p)).into_response())
}

#[derive(Deserialize)]
struct PermissionPath {
    rs: Uuid,
    permission_id: Uuid,
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/resource-servers/{rs}/permissions/{permission_id}", tag = "resource_servers", params(("slug" = String, Path, description = "Tenant slug"), ("rs" = Uuid, Path), ("permission_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete_permission(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(PermissionPath { rs, permission_id }): Path<PermissionPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    resource_servers::delete_permission(&state, tenant.id, admin.actor(), rs, permission_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
