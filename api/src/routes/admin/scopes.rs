//! Admin API: scopes (`/admin/tenants/{slug}/scopes`). The standard OIDC
//! scopes exist in every tenant and cannot be deleted; their description,
//! claims and default flag can still be tuned.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{NewScope, Scope, ScopeUpdate};
use crate::services::scopes;
use crate::state::AppState;

pub fn scopes_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(get_one, update, delete))
}

const P_READ: &str = "ridm:scopes:read";
const P_WRITE: &str = "ridm:scopes:write";

#[derive(Deserialize)]
struct ScopePath {
    scope: Uuid,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/scopes", tag = "scopes", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Vec<Scope>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<Vec<Scope>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(scopes::list(&state, tenant.id).await?.to_vec()))
}

#[utoipa::path(post, path = "/admin/tenants/{slug}/scopes", tag = "scopes", params(("slug" = String, Path, description = "Tenant slug")), request_body = NewScope, responses((status = 201, body = Scope), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<NewScope>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let s = scopes::create(&state, tenant.id, admin.actor(), body).await?;
    Ok((StatusCode::CREATED, axum::Json(s)).into_response())
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/scopes/{scope}", tag = "scopes", params(("slug" = String, Path, description = "Tenant slug"), ("scope" = Uuid, Path)), responses((status = 200, body = Scope), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(ScopePath { scope }): Path<ScopePath>,
) -> AppResult<Json<Scope>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(scopes::get(&state, tenant.id, scope).await?))
}

#[utoipa::path(patch, path = "/admin/tenants/{slug}/scopes/{scope}", tag = "scopes", params(("slug" = String, Path, description = "Tenant slug"), ("scope" = Uuid, Path)), request_body = ScopeUpdate, responses((status = 200, body = Scope), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn update(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(ScopePath { scope }): Path<ScopePath>,
    Json(body): Json<ScopeUpdate>,
) -> AppResult<Json<Scope>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        scopes::update(&state, tenant.id, admin.actor(), scope, body).await?,
    ))
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/scopes/{scope}", tag = "scopes", params(("slug" = String, Path, description = "Tenant slug"), ("scope" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(ScopePath { scope }): Path<ScopePath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    scopes::delete(&state, tenant.id, admin.actor(), scope).await?;
    Ok(StatusCode::NO_CONTENT)
}
