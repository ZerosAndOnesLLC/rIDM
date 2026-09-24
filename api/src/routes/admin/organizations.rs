//! Admin API: organizations (`/admin/tenants/{slug}/organizations`), their
//! members, their email domains, their invitations and the roles they grant. A
//! role granted within an organization is checked against the caller's own
//! admin permissions, exactly as a group's roles are (no escalation through an
//! organization).
//!
//! Everything under `/organizations/{org}` accepts an organization's own
//! administrator: a caller holding `ridm:orgs:*` through a role granted within
//! that organization (`AdminCtx::require_org`). Three things stay tenant-wide,
//! because they are the tenant's business and not the organization's:
//! creating an organization, deleting one, and listing them all. Three more
//! are refused to a caller who is confined to the organization
//! (`AdminCtx::confined_to_org`): changing its slug, changing its status, and
//! adding an existing user as a member — they add people by invitation, or
//! through a verified auto-join domain.

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
    Invitation, Member, NewInvitation, NewOrganization, NewOrganizationDomain, Organization,
    OrganizationDomain, OrganizationDomainUpdate, OrganizationFilter, OrganizationStatus,
    OrganizationUpdate, Principal, RoleHolder,
};
use crate::routes::admin::groups::MembersQuery;
use crate::services::admin_access::{self, Grant};
use crate::services::{invitations, organizations, roles, users};
use crate::state::AppState;
use crate::util::cursor::{Cursor, Page, PageParams, page_size};

pub fn organizations_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(get_one, update, delete))
        .routes(routes!(members))
        .routes(routes!(add_member, remove_member))
        .routes(routes!(role_grants))
        .routes(routes!(grantable_roles))
        .routes(routes!(assign_user_role, unassign_user_role))
        .routes(routes!(assign_group_role, unassign_group_role))
        .routes(routes!(domains, add_domain))
        .routes(routes!(update_domain, delete_domain))
        .routes(routes!(verify_domain))
        .routes(routes!(invitations, invite))
        .routes(routes!(revoke_invitation))
}

const P_READ: &str = "ridm:orgs:read";
const P_WRITE: &str = "ridm:orgs:write";
const P_ROLES_READ: &str = "ridm:roles:read";
const P_INVITE_READ: &str = "ridm:invitations:read";
const P_INVITE_WRITE: &str = "ridm:invitations:write";

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
    member_count: i64,
    domains: Vec<OrganizationDomain>,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/organizations/{org}", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path)), responses((status = 200, body = OrganizationDetail), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(OrgPath { org }): Path<OrgPath>,
) -> AppResult<Json<OrganizationDetail>> {
    admin.require_org(tenant.id, org, P_READ)?;
    let organization = organizations::get(&state, tenant.id, org).await?;
    let member_count = organizations::member_count(&state, tenant.id, org).await?;
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
    admin.require_org(tenant.id, org, P_WRITE)?;
    if admin.confined_to_org(P_WRITE).is_some() && (body.slug.is_some() || body.status.is_some()) {
        return Err(AppError::Forbidden(
            "an organization's own administrator cannot change its slug or status".into(),
        ));
    }
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

#[utoipa::path(get, path = "/admin/tenants/{slug}/organizations/{org}/members", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path), MembersQuery), responses((status = 200, body = Page<Member>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn members(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(OrgPath { org }): Path<OrgPath>,
    Query(q): Query<MembersQuery>,
) -> AppResult<Json<Page<Member>>> {
    admin.require_org(tenant.id, org, P_READ)?;
    Ok(Json(
        organizations::members(
            &state,
            tenant.id,
            org,
            q.search.as_deref(),
            q.cursor.as_deref(),
            q.limit,
        )
        .await?,
    ))
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
    admin.require_org(tenant.id, org, P_WRITE)?;
    if admin.confined_to_org(P_WRITE).is_some() {
        return Err(AppError::Forbidden(
            "an organization's own administrator adds members by invitation".into(),
        ));
    }
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
    admin.require_org(tenant.id, org, P_WRITE)?;
    organizations::remove_member(&state, tenant.id, admin.actor(), org, user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Grants scoped to this organization: they apply to sessions acting in it and
/// nowhere else. `user_id` or `group_id` names the principal.
#[utoipa::path(get, path = "/admin/tenants/{slug}/organizations/{org}/roles", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path), PageParams), responses((status = 200, body = Page<RoleHolder>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn role_grants(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(OrgPath { org }): Path<OrgPath>,
    Query(page): Query<PageParams>,
) -> AppResult<Json<Page<RoleHolder>>> {
    admin.require_org(tenant.id, org, P_READ)?;
    Ok(Json(
        organizations::role_grants(&state, tenant.id, org, page.cursor.as_deref(), page.limit)
            .await?,
    ))
}

/// A tenant role, and whether this caller may grant it inside the
/// organization. Roles carrying admin permissions the caller does not hold
/// there are listed but not grantable.
#[derive(Serialize, utoipa::ToSchema)]
struct GrantableRole {
    #[serde(flatten)]
    role: crate::models::Role,
    grantable: bool,
}

/// The tenant's roles as a picker for this organization's grants. An
/// organization's own administrator may read them here without holding
/// `ridm:roles:read` tenant-wide.
#[utoipa::path(get, path = "/admin/tenants/{slug}/organizations/{org}/grantable-roles", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path)), responses((status = 200, body = Vec<GrantableRole>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn grantable_roles(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(OrgPath { org }): Path<OrgPath>,
) -> AppResult<Json<Vec<GrantableRole>>> {
    admin.require_org(tenant.id, org, P_ROLES_READ)?;
    organizations::get(&state, tenant.id, org).await?;
    let all = roles::list(&state, tenant.id, None).await?;
    let ids: Vec<Uuid> = all.iter().map(|r| r.id).collect();
    let carried = admin_access::permissions_per_role(&state, tenant.id, &ids).await?;
    Ok(Json(
        all.into_iter()
            .map(|role| {
                let grantable = match carried.get(&role.id) {
                    Some(perms) => admin
                        .require_can_grant_in_org(org, perms.iter().map(String::as_str))
                        .is_ok(),
                    None => true,
                };
                GrantableRole { role, grantable }
            })
            .collect(),
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
    admin.require_org(tenant.id, org, P_WRITE)?;
    roles::get(&state, tenant.id, role_id).await?;
    let granted =
        admin_access::permissions_of_grant(&state, tenant.id, Grant::Role(role_id)).await?;
    admin.require_can_grant_in_org(org, granted.iter().map(String::as_str))?;
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
    admin.require_org(tenant.id, org, P_WRITE)?;
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
    admin.require_org(tenant.id, org, P_WRITE)?;
    roles::get(&state, tenant.id, role_id).await?;
    let granted =
        admin_access::permissions_of_grant(&state, tenant.id, Grant::Role(role_id)).await?;
    admin.require_can_grant_in_org(org, granted.iter().map(String::as_str))?;
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
    admin.require_org(tenant.id, org, P_WRITE)?;
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
    admin.require_org(tenant.id, org, P_READ)?;
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
    admin.require_org(tenant.id, org, P_WRITE)?;
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
    admin.require_org(tenant.id, org, P_WRITE)?;
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
    admin.require_org(tenant.id, org, P_WRITE)?;
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
    admin.require_org(tenant.id, org, P_WRITE)?;
    organizations::delete_domain(&state, tenant.id, admin.actor(), org, domain_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(default)]
struct InvitationListQuery {
    /// Only invitations that can still be accepted.
    open_only: bool,
    cursor: Option<String>,
    limit: Option<u32>,
}

/// Only this organization's invitations; the tenant's others are not shown,
/// so an organization's own administrator never sees them.
#[utoipa::path(get, path = "/admin/tenants/{slug}/organizations/{org}/invitations", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path), InvitationListQuery), responses((status = 200, body = Page<Invitation>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn invitations(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(OrgPath { org }): Path<OrgPath>,
    Query(q): Query<InvitationListQuery>,
) -> AppResult<Json<Page<Invitation>>> {
    admin.require_org(tenant.id, org, P_INVITE_READ)?;
    organizations::get(&state, tenant.id, org).await?;
    Ok(Json(
        invitations::list(
            &state,
            tenant.id,
            Some(org),
            q.open_only,
            q.cursor.as_deref(),
            q.limit,
        )
        .await?,
    ))
}

/// The invitation carries this organization: accepting it creates the account
/// and the membership at once. Roles and groups are granted tenant-wide on
/// acceptance, so a caller confined to the organization may not attach any —
/// they grant roles within the organization afterwards.
#[utoipa::path(post, path = "/admin/tenants/{slug}/organizations/{org}/invitations", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path)), request_body = NewInvitation, responses((status = 201, body = Invitation), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn invite(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(OrgPath { org }): Path<OrgPath>,
    Json(mut body): Json<NewInvitation>,
) -> AppResult<Response> {
    admin.require_org(tenant.id, org, P_INVITE_WRITE)?;
    let confined = admin.confined_to_org(P_INVITE_WRITE).is_some();
    if confined && !(body.roles.is_empty() && body.groups.is_empty()) {
        return Err(AppError::Forbidden(
            "an organization's own administrator cannot attach tenant roles or groups to an \
             invitation"
                .into(),
        ));
    }
    if body.org_id.is_some_and(|o| o != org) {
        return Err(AppError::BadRequest(
            "org_id does not match the organization in the path".into(),
        ));
    }
    body.org_id = Some(org);
    organizations::get(&state, tenant.id, org).await?;
    for r in &body.roles {
        let granted =
            admin_access::permissions_of_grant(&state, tenant.id, Grant::Role(*r)).await?;
        admin.require_can_grant(granted.iter().map(String::as_str))?;
    }
    for g in &body.groups {
        let granted =
            admin_access::permissions_of_grant(&state, tenant.id, Grant::Group(*g)).await?;
        admin.require_can_grant(granted.iter().map(String::as_str))?;
    }
    let inv = invitations::create(&state, &tenant, admin.actor(), body).await?;
    Ok((StatusCode::CREATED, axum::Json(inv)).into_response())
}

#[derive(Deserialize)]
struct InvitationPath {
    org: Uuid,
    invitation: Uuid,
}

/// The link stops working. An invitation of another organization is not found
/// here, whatever the caller may do elsewhere.
#[utoipa::path(delete, path = "/admin/tenants/{slug}/organizations/{org}/invitations/{invitation}", tag = "organizations", params(("slug" = String, Path, description = "Tenant slug"), ("org" = Uuid, Path), ("invitation" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke_invitation(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(InvitationPath { org, invitation }): Path<InvitationPath>,
) -> AppResult<StatusCode> {
    admin.require_org(tenant.id, org, P_INVITE_WRITE)?;
    let inv = invitations::get(&state, tenant.id, invitation).await?;
    if inv.org_id != Some(org) {
        return Err(AppError::NotFound("invitation"));
    }
    invitations::revoke(&state, tenant.id, admin.actor(), invitation).await?;
    Ok(StatusCode::NO_CONTENT)
}
