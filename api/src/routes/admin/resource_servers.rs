//! Admin API: resource servers (`/admin/tenants/{slug}/resource-servers`)
//! and their permissions. The built-in `urn:ridm:admin` server is read-only.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{
    NewPermission, NewResourceServer, Permission, ResourceServer, ResourceServerUpdate,
};
use crate::services::resource_servers;
use crate::state::AppState;

pub fn resource_servers_router() -> Router<AppState> {
    let base = "/admin/tenants/{slug}/resource-servers";
    Router::new()
        .route(base, get(list).post(create))
        .route(
            &format!("{base}/{{rs}}"),
            get(get_one).patch(update).delete(delete),
        )
        .route(
            &format!("{base}/{{rs}}/permissions"),
            get(permissions).post(create_permission),
        )
        .route(
            &format!("{base}/{{rs}}/permissions/{{permission_id}}"),
            axum::routing::delete(delete_permission),
        )
}

const P_READ: &str = "ridm:resource-servers:read";
const P_WRITE: &str = "ridm:resource-servers:write";

#[derive(Deserialize)]
struct RsPath {
    rs: Uuid,
}

async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<Vec<ResourceServer>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(resource_servers::list(&state, tenant.id).await?))
}

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

#[derive(Serialize)]
struct ResourceServerDetail {
    #[serde(flatten)]
    resource_server: ResourceServer,
    permissions: Vec<Permission>,
}

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
