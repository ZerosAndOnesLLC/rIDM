//! Admin API: groups (`/admin/tenants/{slug}/groups`), membership and the
//! roles a group carries. Adding a member or a role is checked against the
//! caller's own admin permissions (no escalation through groups).

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use serde::Serialize;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{Group, GroupUpdate, NewGroup, Principal, Role, User};
use crate::services::admin_access::{self, Grant};
use crate::services::{groups, roles, users};
use crate::state::AppState;

pub fn groups_router() -> Router<AppState> {
    let base = "/admin/tenants/{slug}/groups";
    Router::new()
        .route(base, get(list).post(create))
        .route(
            &format!("{base}/{{group}}"),
            get(get_one).patch(update).delete(delete),
        )
        .route(&format!("{base}/{{group}}/members"), get(members))
        .route(
            &format!("{base}/{{group}}/members/{{user_id}}"),
            put(add_member).delete(remove_member),
        )
        .route(&format!("{base}/{{group}}/roles"), get(group_roles))
        .route(
            &format!("{base}/{{group}}/roles/{{role_id}}"),
            put(assign_role).delete(unassign_role),
        )
}

const P_READ: &str = "ridm:groups:read";
const P_WRITE: &str = "ridm:groups:write";

#[derive(serde::Deserialize)]
struct GroupPath {
    group: Uuid,
}

/// Flat list with `parent_id`; the UI builds the tree.
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<Vec<Group>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(groups::list(&state, tenant.id).await?))
}

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

#[derive(Serialize)]
struct GroupDetail {
    #[serde(flatten)]
    group: Group,
    /// Roles assigned to this group itself (ancestors' roles are inherited at runtime).
    roles: Vec<Role>,
    member_count: usize,
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

async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(GroupPath { group }): Path<GroupPath>,
) -> AppResult<Json<GroupDetail>> {
    admin.require(tenant.id, P_READ)?;
    let g = groups::get(&state, tenant.id, group).await?;
    let member_count = groups::members(&state, tenant.id, group).await?.len();
    Ok(Json(GroupDetail {
        roles: roles_of_group(&state, tenant.id, group).await?,
        group: g,
        member_count,
    }))
}

/// `parent_id: null` moves the group to the top level.
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

async fn members(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(GroupPath { group }): Path<GroupPath>,
) -> AppResult<Json<Vec<User>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(groups::members(&state, tenant.id, group).await?))
}

#[derive(serde::Deserialize)]
struct MemberPath {
    group: Uuid,
    user_id: Uuid,
}

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
