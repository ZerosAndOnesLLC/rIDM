//! Admin API: roles (`/admin/tenants/{slug}/roles`), composites, permission
//! grants and holders. Built-in `ridm:*` roles are readable and assignable
//! but immutable. Composites and permission grants are checked against the
//! caller's own admin permissions.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{NewRole, Permission, Role, RoleAssignment, RoleUpdate};
use crate::services::admin_access::{self, Grant};
use crate::services::{resource_servers, roles};
use crate::state::AppState;

pub fn roles_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(get_one, update, delete))
        .routes(routes!(composites))
        .routes(routes!(add_composite, remove_composite))
        .routes(routes!(permissions))
        .routes(routes!(grant_permission, revoke_permission))
        .routes(routes!(holders))
}

const P_READ: &str = "ridm:roles:read";
const P_WRITE: &str = "ridm:roles:write";
/// Granting permissions to roles belongs to the resource-server side of the
/// catalogue.
const P_GRANT: &str = "ridm:resource-servers:write";

#[derive(Deserialize)]
struct RolePath {
    role: Uuid,
}

#[derive(Deserialize, Default, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(default)]
struct ListQuery {
    /// Only this client's roles.
    client_id: Option<Uuid>,
    /// Only realm-wide roles (no client).
    realm_only: bool,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/roles", tag = "roles", params(("slug" = String, Path, description = "Tenant slug"), ListQuery), responses((status = 200, body = Vec<Role>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Vec<Role>>> {
    admin.require(tenant.id, P_READ)?;
    let filter = match (q.client_id, q.realm_only) {
        (Some(c), _) => Some(Some(c)),
        (None, true) => Some(None),
        (None, false) => None,
    };
    Ok(Json(roles::list(&state, tenant.id, filter).await?))
}

#[utoipa::path(post, path = "/admin/tenants/{slug}/roles", tag = "roles", params(("slug" = String, Path, description = "Tenant slug")), request_body = NewRole, responses((status = 201, body = Role), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<NewRole>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let r = roles::create(&state, tenant.id, admin.actor(), body).await?;
    Ok((StatusCode::CREATED, axum::Json(r)).into_response())
}

#[derive(Serialize, utoipa::ToSchema)]
struct RoleDetail {
    #[serde(flatten)]
    role: Role,
    composites: Vec<Role>,
    permissions: Vec<Permission>,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/roles/{role}", tag = "roles", params(("slug" = String, Path, description = "Tenant slug"), ("role" = Uuid, Path)), responses((status = 200, body = RoleDetail), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RolePath { role }): Path<RolePath>,
) -> AppResult<Json<RoleDetail>> {
    admin.require(tenant.id, P_READ)?;
    let r = roles::get(&state, tenant.id, role).await?;
    Ok(Json(RoleDetail {
        composites: roles::composites_of(&state, tenant.id, role).await?,
        permissions: resource_servers::permissions_of_role(&state, tenant.id, role).await?,
        role: r,
    }))
}

#[utoipa::path(patch, path = "/admin/tenants/{slug}/roles/{role}", tag = "roles", params(("slug" = String, Path, description = "Tenant slug"), ("role" = Uuid, Path)), request_body = RoleUpdate, responses((status = 200, body = Role), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn update(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RolePath { role }): Path<RolePath>,
    Json(body): Json<RoleUpdate>,
) -> AppResult<Json<Role>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        roles::update(&state, tenant.id, admin.actor(), role, body).await?,
    ))
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/roles/{role}", tag = "roles", params(("slug" = String, Path, description = "Tenant slug"), ("role" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RolePath { role }): Path<RolePath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    roles::delete(&state, tenant.id, admin.actor(), role).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/roles/{role}/composites", tag = "roles", params(("slug" = String, Path, description = "Tenant slug"), ("role" = Uuid, Path)), responses((status = 200, body = Vec<Role>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn composites(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RolePath { role }): Path<RolePath>,
) -> AppResult<Json<Vec<Role>>> {
    admin.require(tenant.id, P_READ)?;
    roles::get(&state, tenant.id, role).await?;
    Ok(Json(roles::composites_of(&state, tenant.id, role).await?))
}

#[derive(Deserialize)]
struct CompositePath {
    role: Uuid,
    child_id: Uuid,
}

/// Everyone holding `role` gains `child_id`, so the child's permissions
/// must be within the caller's reach.
#[utoipa::path(put, path = "/admin/tenants/{slug}/roles/{role}/composites/{child_id}", tag = "roles", params(("slug" = String, Path, description = "Tenant slug"), ("role" = Uuid, Path), ("child_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn add_composite(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(CompositePath { role, child_id }): Path<CompositePath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    let parent = roles::get(&state, tenant.id, role).await?;
    if parent.built_in {
        return Err(AppError::Forbidden(
            "built-in roles cannot be changed".into(),
        ));
    }
    roles::get(&state, tenant.id, child_id).await?;
    let granted =
        admin_access::permissions_of_grant(&state, tenant.id, Grant::Role(child_id)).await?;
    admin.require_can_grant(granted.iter().map(String::as_str))?;
    roles::add_composite(&state, tenant.id, admin.actor(), role, child_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/roles/{role}/composites/{child_id}", tag = "roles", params(("slug" = String, Path, description = "Tenant slug"), ("role" = Uuid, Path), ("child_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn remove_composite(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(CompositePath { role, child_id }): Path<CompositePath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    let parent = roles::get(&state, tenant.id, role).await?;
    if parent.built_in {
        return Err(AppError::Forbidden(
            "built-in roles cannot be changed".into(),
        ));
    }
    roles::remove_composite(&state, tenant.id, admin.actor(), role, child_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/roles/{role}/permissions", tag = "roles", params(("slug" = String, Path, description = "Tenant slug"), ("role" = Uuid, Path)), responses((status = 200, body = Vec<Permission>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn permissions(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RolePath { role }): Path<RolePath>,
) -> AppResult<Json<Vec<Permission>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(
        resource_servers::permissions_of_role(&state, tenant.id, role).await?,
    ))
}

#[derive(Deserialize)]
struct GrantPath {
    role: Uuid,
    permission_id: Uuid,
}

/// Admin-catalogue permissions can only be granted by someone who holds them.
#[utoipa::path(put, path = "/admin/tenants/{slug}/roles/{role}/permissions/{permission_id}", tag = "roles", params(("slug" = String, Path, description = "Tenant slug"), ("role" = Uuid, Path), ("permission_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn grant_permission(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(GrantPath {
        role,
        permission_id,
    }): Path<GrantPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_GRANT)?;
    let p = resource_servers::get_permission(&state, tenant.id, permission_id).await?;
    let rs = resource_servers::get(&state, tenant.id, p.resource_server_id).await?;
    if rs.built_in {
        admin.require_can_grant([p.name.as_str()])?;
    }
    resource_servers::grant(&state, tenant.id, admin.actor(), role, permission_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/roles/{role}/permissions/{permission_id}", tag = "roles", params(("slug" = String, Path, description = "Tenant slug"), ("role" = Uuid, Path), ("permission_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke_permission(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(GrantPath {
        role,
        permission_id,
    }): Path<GrantPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_GRANT)?;
    resource_servers::revoke(&state, tenant.id, admin.actor(), role, permission_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Users and groups the role is assigned to directly.
#[utoipa::path(get, path = "/admin/tenants/{slug}/roles/{role}/holders", tag = "roles", params(("slug" = String, Path, description = "Tenant slug"), ("role" = Uuid, Path)), responses((status = 200, body = Vec<RoleAssignment>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn holders(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RolePath { role }): Path<RolePath>,
) -> AppResult<Json<Vec<RoleAssignment>>> {
    admin.require(tenant.id, P_READ)?;
    roles::get(&state, tenant.id, role).await?;
    Ok(Json(roles::holders_of(&state, tenant.id, role).await?))
}
