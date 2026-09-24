//! Admin API: groups (`/admin/tenants/{slug}/groups`), membership and the
//! roles a group carries. Adding a member or a role is checked against the
//! caller's own admin permissions (no escalation through groups).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{Group, GroupUpdate, Member, NewGroup, Principal, Role};
use crate::services::admin_access::{self, Grant};
use crate::services::{groups, roles, users};
use crate::state::AppState;
use crate::util::cursor::Page;

pub fn groups_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(get_one, update, delete))
        .routes(routes!(members))
        .routes(routes!(add_member, remove_member))
        .routes(routes!(group_roles))
        .routes(routes!(assign_role, unassign_role))
}

const P_READ: &str = "ridm:groups:read";
const P_WRITE: &str = "ridm:groups:write";

#[derive(serde::Deserialize)]
struct GroupPath {
    group: Uuid,
}

/// Flat list with `parent_id`; the UI builds the tree.
#[utoipa::path(get, path = "/admin/tenants/{slug}/groups", tag = "groups", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Vec<Group>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<Vec<Group>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(groups::list(&state, tenant.id).await?))
}

#[utoipa::path(post, path = "/admin/tenants/{slug}/groups", tag = "groups", params(("slug" = String, Path, description = "Tenant slug")), request_body = NewGroup, responses((status = 201, body = Group), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<NewGroup>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let g = groups::create(&state, tenant.id, admin.actor(), body).await?;
    Ok((StatusCode::CREATED, axum::Json(g)).into_response())
}

#[derive(Serialize, utoipa::ToSchema)]
struct GroupDetail {
    #[serde(flatten)]
    group: Group,
    /// Roles assigned to this group itself (ancestors' roles are inherited at runtime).
    roles: Vec<Role>,
    member_count: i64,
}

/// A page of a group's or organization's members.
#[derive(Deserialize, Default, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(default)]
pub(crate) struct MembersQuery {
    /// Only members whose username or email starts with this.
    pub(crate) search: Option<String>,
    pub(crate) cursor: Option<String>,
    pub(crate) limit: Option<u32>,
}

async fn roles_of_group(state: &AppState, tenant_id: Uuid, group_id: Uuid) -> AppResult<Vec<Role>> {
    let assignments =
        roles::assignments_of(state, tenant_id, Principal::Group { id: group_id }).await?;
    let mut out = Vec::with_capacity(assignments.len());
    for a in assignments {
        if let Ok(r) = roles::get(state, tenant_id, a.role_id).await {
            out.push(r);
        }
    }
    Ok(out)
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/groups/{group}", tag = "groups", params(("slug" = String, Path, description = "Tenant slug"), ("group" = Uuid, Path)), responses((status = 200, body = GroupDetail), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(GroupPath { group }): Path<GroupPath>,
) -> AppResult<Json<GroupDetail>> {
    admin.require(tenant.id, P_READ)?;
    let g = groups::get(&state, tenant.id, group).await?;
    let member_count = groups::member_count(&state, tenant.id, group).await?;
    Ok(Json(GroupDetail {
        roles: roles_of_group(&state, tenant.id, group).await?,
        group: g,
        member_count,
    }))
}

/// `parent_id: null` moves the group to the top level.
#[utoipa::path(patch, path = "/admin/tenants/{slug}/groups/{group}", tag = "groups", params(("slug" = String, Path, description = "Tenant slug"), ("group" = Uuid, Path)), request_body = GroupUpdate, responses((status = 200, body = Group), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn update(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(GroupPath { group }): Path<GroupPath>,
    Json(body): Json<GroupUpdate>,
) -> AppResult<Json<Group>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        groups::update(&state, tenant.id, admin.actor(), group, body).await?,
    ))
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/groups/{group}", tag = "groups", params(("slug" = String, Path, description = "Tenant slug"), ("group" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(GroupPath { group }): Path<GroupPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    groups::delete(&state, tenant.id, admin.actor(), group).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/groups/{group}/members", tag = "groups", params(("slug" = String, Path, description = "Tenant slug"), ("group" = Uuid, Path), MembersQuery), responses((status = 200, body = Page<Member>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn members(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(GroupPath { group }): Path<GroupPath>,
    Query(q): Query<MembersQuery>,
) -> AppResult<Json<Page<Member>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(
        groups::members(
            &state,
            tenant.id,
            group,
            q.search.as_deref(),
            q.cursor.as_deref(),
            q.limit,
        )
        .await?,
    ))
}

#[derive(serde::Deserialize)]
struct MemberPath {
    group: Uuid,
    user_id: Uuid,
}

#[utoipa::path(put, path = "/admin/tenants/{slug}/groups/{group}/members/{user_id}", tag = "groups", params(("slug" = String, Path, description = "Tenant slug"), ("group" = Uuid, Path), ("user_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn add_member(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(MemberPath { group, user_id }): Path<MemberPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    let user = users::get(&state, tenant.id, user_id).await?;
    if user.deleted_at.is_some() {
        return Err(crate::error::AppError::NotFound("user"));
    }
    groups::get(&state, tenant.id, group).await?;
    let granted =
        admin_access::permissions_of_grant(&state, tenant.id, Grant::Group(group)).await?;
    admin.require_can_grant(granted.iter().map(String::as_str))?;
    groups::add_member(&state, tenant.id, admin.actor(), group, user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/groups/{group}/members/{user_id}", tag = "groups", params(("slug" = String, Path, description = "Tenant slug"), ("group" = Uuid, Path), ("user_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn remove_member(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(MemberPath { group, user_id }): Path<MemberPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    groups::remove_member(&state, tenant.id, admin.actor(), group, user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/groups/{group}/roles", tag = "groups", params(("slug" = String, Path, description = "Tenant slug"), ("group" = Uuid, Path)), responses((status = 200, body = Vec<Role>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn group_roles(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(GroupPath { group }): Path<GroupPath>,
) -> AppResult<Json<Vec<Role>>> {
    admin.require(tenant.id, P_READ)?;
    groups::get(&state, tenant.id, group).await?;
    Ok(Json(roles_of_group(&state, tenant.id, group).await?))
}

#[derive(serde::Deserialize)]
struct GroupRolePath {
    group: Uuid,
    role_id: Uuid,
}

/// Every member (and members of descendant groups) gains the role.
#[utoipa::path(put, path = "/admin/tenants/{slug}/groups/{group}/roles/{role_id}", tag = "groups", params(("slug" = String, Path, description = "Tenant slug"), ("group" = Uuid, Path), ("role_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn assign_role(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(GroupRolePath { group, role_id }): Path<GroupRolePath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    groups::get(&state, tenant.id, group).await?;
    roles::get(&state, tenant.id, role_id).await?;
    let granted =
        admin_access::permissions_of_grant(&state, tenant.id, Grant::Role(role_id)).await?;
    admin.require_can_grant(granted.iter().map(String::as_str))?;
    roles::assign(
        &state,
        tenant.id,
        admin.actor(),
        role_id,
        Principal::Group { id: group },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/groups/{group}/roles/{role_id}", tag = "groups", params(("slug" = String, Path, description = "Tenant slug"), ("group" = Uuid, Path), ("role_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn unassign_role(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(GroupRolePath { group, role_id }): Path<GroupRolePath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    roles::unassign(
        &state,
        tenant.id,
        admin.actor(),
        role_id,
        Principal::Group { id: group },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
