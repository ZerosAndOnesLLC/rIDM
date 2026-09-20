//! Admin API: organizations (`/admin/tenants/{slug}/organizations`), their
//! members, their email domains and the roles they grant. A role granted
//! within an organization is checked against the caller's own admin
//! permissions, exactly as a group's roles are (no escalation through an
//! organization).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{
    NewOrganization, NewOrganizationDomain, Organization, OrganizationDomain,
    OrganizationDomainUpdate, OrganizationFilter, OrganizationStatus, OrganizationUpdate,
    Principal, RoleAssignment, User,
};
use crate::services::admin_access::{self, Grant};
use crate::services::{organizations, roles, users};
use crate::state::AppState;
use crate::util::cursor::{Cursor, Page, page_size};

pub fn organizations_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(get_one, update, delete))
        .routes(routes!(members))
        .routes(routes!(add_member, remove_member))
        .routes(routes!(role_grants))
        .routes(routes!(assign_user_role, unassign_user_role))
        .routes(routes!(assign_group_role, unassign_group_role))
        .routes(routes!(domains, add_domain))
        .routes(routes!(update_domain, delete_domain))
        .routes(routes!(verify_domain))
}

const P_READ: &str = "ridm:orgs:read";
const P_WRITE: &str = "ridm:orgs:write";

#[derive(Deserialize)]
struct OrgPath {
    org: Uuid,
}

#[derive(Deserialize, Default, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(default)]
struct ListQuery {
    /// Matches the slug or the display name.
    search: Option<String>,
    #[param(inline)]
    status: Option<OrganizationStatus>,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/organizations", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ListQuery), responses((status = 200, body = Page<Organization>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Page<Organization>>> {
    admin.require(tenant.id, P_READ)?;
    let cursor = q.cursor.as_deref().map(Cursor::decode).transpose()?;
    let filter = OrganizationFilter {
        search: q.search,
        status: q.status,
    };
    Ok(Json(
        organizations::list(&state, tenant.id, &filter, cursor, page_size(q.limit)).await?,
    ))
}

#[utoipa::path(post, path = "/admin/tenants/{slug}/organizations", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug")), request_body = NewOrganization, responses((status = 201, body = Organization), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<NewOrganization>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let org = organizations::create(&state, tenant.id, admin.actor(), body).await?;
    Ok((StatusCode::CREATED, axum::Json(org)).into_response())
}

#[derive(Serialize, utoipa::ToSchema)]
struct OrganizationDetail {
    #[serde(flatten)]
    organization: Organization,
    member_count: usize,
    domains: Vec<OrganizationDomain>,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/organizations/{org}", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path)), responses((status = 200, body = OrganizationDetail), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(OrgPath { org }): Path<OrgPath>,
) -> AppResult<Json<OrganizationDetail>> {
    admin.require(tenant.id, P_READ)?;
    let organization = organizations::get(&state, tenant.id, org).await?;
    let member_count = organizations::members(&state, tenant.id, org).await?.len();
    Ok(Json(OrganizationDetail {
        organization,
        member_count,
        domains: organizations::domains(&state, tenant.id, org).await?,
    }))
}

#[utoipa::path(patch, path = "/admin/tenants/{slug}/organizations/{org}", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path)), request_body = OrganizationUpdate, responses((status = 200, body = Organization), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn update(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(OrgPath { org }): Path<OrgPath>,
    Json(body): Json<OrganizationUpdate>,
) -> AppResult<Json<Organization>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        organizations::update(&state, tenant.id, admin.actor(), org, body).await?,
    ))
}

/// Memberships, domains and org-scoped role grants go with it. Members keep
/// their accounts; one whose primary organization this was is left without one.
#[utoipa::path(delete, path = "/admin/tenants/{slug}/organizations/{org}", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(OrgPath { org }): Path<OrgPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    organizations::delete(&state, tenant.id, admin.actor(), org).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/organizations/{org}/members", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path)), responses((status = 200, body = Vec<User>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn members(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(OrgPath { org }): Path<OrgPath>,
) -> AppResult<Json<Vec<User>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(organizations::members(&state, tenant.id, org).await?))
}

#[derive(Deserialize)]
struct MemberPath {
    org: Uuid,
    user_id: Uuid,
}

/// The user's first organization also becomes their primary one.
#[utoipa::path(put, path = "/admin/tenants/{slug}/organizations/{org}/members/{user_id}", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path), ("user_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn add_member(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(MemberPath { org, user_id }): Path<MemberPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    let user = users::get(&state, tenant.id, user_id).await?;
    if user.deleted_at.is_some() {
        return Err(AppError::NotFound("user"));
    }
    organizations::add_member(&state, tenant.id, admin.actor(), org, user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Any role the user held only within this organization goes with the
/// membership.
#[utoipa::path(delete, path = "/admin/tenants/{slug}/organizations/{org}/members/{user_id}", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path), ("user_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn remove_member(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(MemberPath { org, user_id }): Path<MemberPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    organizations::remove_member(&state, tenant.id, admin.actor(), org, user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Grants scoped to this organization: they apply to sessions acting in it and
/// nowhere else. `user_id` or `group_id` names the principal.
#[utoipa::path(get, path = "/admin/tenants/{slug}/organizations/{org}/roles", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path)), responses((status = 200, body = Vec<RoleAssignment>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn role_grants(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(OrgPath { org }): Path<OrgPath>,
) -> AppResult<Json<Vec<RoleAssignment>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(
        organizations::role_grants(&state, tenant.id, org).await?,
    ))
}

#[derive(Deserialize)]
struct MemberRolePath {
    org: Uuid,
    user_id: Uuid,
    role_id: Uuid,
}

/// The user gains the role while acting in this organization. The caller must
/// already hold every permission the role carries.
#[utoipa::path(put, path = "/admin/tenants/{slug}/organizations/{org}/members/{user_id}/roles/{role_id}", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path), ("user_id" = Uuid, Path), ("role_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn assign_user_role(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(MemberRolePath {
        org,
        user_id,
        role_id,
    }): Path<MemberRolePath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    roles::get(&state, tenant.id, role_id).await?;
    let granted =
        admin_access::permissions_of_grant(&state, tenant.id, Grant::Role(role_id)).await?;
    admin.require_can_grant(granted.iter().map(String::as_str))?;
    organizations::assign_role(
        &state,
        tenant.id,
        admin.actor(),
        org,
        role_id,
        Principal::User { id: user_id },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/organizations/{org}/members/{user_id}/roles/{role_id}", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path), ("user_id" = Uuid, Path), ("role_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn unassign_user_role(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(MemberRolePath {
        org,
        user_id,
        role_id,
    }): Path<MemberRolePath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    organizations::unassign_role(
        &state,
        tenant.id,
        admin.actor(),
        org,
        role_id,
        Principal::User { id: user_id },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct GroupRolePath {
    org: Uuid,
    group_id: Uuid,
    role_id: Uuid,
}

/// Every member of the group (and of its descendants) gains the role while
/// acting in this organization.
#[utoipa::path(put, path = "/admin/tenants/{slug}/organizations/{org}/groups/{group_id}/roles/{role_id}", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path), ("group_id" = Uuid, Path), ("role_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn assign_group_role(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(GroupRolePath {
        org,
        group_id,
        role_id,
    }): Path<GroupRolePath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    roles::get(&state, tenant.id, role_id).await?;
    let granted =
        admin_access::permissions_of_grant(&state, tenant.id, Grant::Role(role_id)).await?;
    admin.require_can_grant(granted.iter().map(String::as_str))?;
    organizations::assign_role(
        &state,
        tenant.id,
        admin.actor(),
        org,
        role_id,
        Principal::Group { id: group_id },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/organizations/{org}/groups/{group_id}/roles/{role_id}", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path), ("group_id" = Uuid, Path), ("role_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn unassign_group_role(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(GroupRolePath {
        org,
        group_id,
        role_id,
    }): Path<GroupRolePath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    organizations::unassign_role(
        &state,
        tenant.id,
        admin.actor(),
        org,
        role_id,
        Principal::Group { id: group_id },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/organizations/{org}/domains", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path)), responses((status = 200, body = Vec<OrganizationDomain>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn domains(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(OrgPath { org }): Path<OrgPath>,
) -> AppResult<Json<Vec<OrganizationDomain>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(organizations::domains(&state, tenant.id, org).await?))
}

/// The response's `verification` is the value to publish as a TXT record at
/// `_ridm-challenge.<domain>`; auto-join waits for the verification.
#[utoipa::path(post, path = "/admin/tenants/{slug}/organizations/{org}/domains", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path)), request_body = NewOrganizationDomain, responses((status = 201, body = OrganizationDomain), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn add_domain(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(OrgPath { org }): Path<OrgPath>,
    Json(body): Json<NewOrganizationDomain>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let domain = organizations::add_domain(&state, tenant.id, admin.actor(), org, body).await?;
    Ok((StatusCode::CREATED, axum::Json(domain)).into_response())
}

#[derive(Deserialize)]
struct DomainPath {
    org: Uuid,
    domain_id: Uuid,
}

#[utoipa::path(patch, path = "/admin/tenants/{slug}/organizations/{org}/domains/{domain_id}", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path), ("domain_id" = Uuid, Path)), request_body = OrganizationDomainUpdate, responses((status = 200, body = OrganizationDomain), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn update_domain(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(DomainPath { org, domain_id }): Path<DomainPath>,
    Json(body): Json<OrganizationDomainUpdate>,
) -> AppResult<Json<OrganizationDomain>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        organizations::update_domain(&state, tenant.id, org, domain_id, body).await?,
    ))
}

/// Looks for the TXT record now. 400 while it is not there, 503 when the
/// server has no resolver to ask.
#[utoipa::path(post, path = "/admin/tenants/{slug}/organizations/{org}/domains/{domain_id}/verify", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path), ("domain_id" = Uuid, Path)), responses((status = 200, body = OrganizationDomain), (status = 400, description = "The record was not found", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem), (status = 503, description = "No DNS resolver", body = crate::error::Problem)), security(("bearer" = [])))]
async fn verify_domain(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(DomainPath { org, domain_id }): Path<DomainPath>,
) -> AppResult<Json<OrganizationDomain>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        organizations::verify_domain(&state, tenant.id, admin.actor(), org, domain_id).await?,
    ))
}

/// Members who joined through this domain keep their membership.
#[utoipa::path(delete, path = "/admin/tenants/{slug}/organizations/{org}/domains/{domain_id}", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path), ("domain_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete_domain(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(DomainPath { org, domain_id }): Path<DomainPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    organizations::delete_domain(&state, tenant.id, admin.actor(), org, domain_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
