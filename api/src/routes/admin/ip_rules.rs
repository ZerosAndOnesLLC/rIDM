//! Admin API: IP rules (`/admin/tenants/{slug}/ip-rules`).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{IpRule, IpRuleUpdate, NewIpRule};
use crate::services::ip_rules;
use crate::state::AppState;

pub fn ip_rules_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(get_one, update, delete))
}

/// IP rules are part of the tenant configuration.
const P_READ: &str = "ridm:tenants:read";
const P_WRITE: &str = "ridm:tenants:write";

#[derive(Deserialize)]
struct RulePath {
    rule: Uuid,
}

#[derive(Deserialize, Default, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(default)]
struct ListQuery {
    /// Only rules bound to this client.
    client_id: Option<Uuid>,
    /// Only tenant-wide rules.
    tenant_wide: bool,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/ip-rules", tag = "ip_rules", params(("slug" = String, Path, description = "Tenant slug"), ListQuery), responses((status = 200, body = Vec<IpRule>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Vec<IpRule>>> {
    admin.require(tenant.id, P_READ)?;
    let scope = match (q.client_id, q.tenant_wide) {
        (Some(c), _) => Some(Some(c)),
        (None, true) => Some(None),
        (None, false) => None,
    };
    Ok(Json(ip_rules::list(&state, tenant.id, scope).await?))
}

/// `{cidr, action?: allow|deny (default deny), client_id?, description?}`.
#[utoipa::path(post, path = "/admin/tenants/{slug}/ip-rules", tag = "ip_rules", params(("slug" = String, Path, description = "Tenant slug")), request_body = NewIpRule, responses((status = 201, body = IpRule), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<NewIpRule>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let r = ip_rules::create(&state, tenant.id, admin.actor(), body).await?;
    Ok((StatusCode::CREATED, axum::Json(r)).into_response())
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/ip-rules/{rule}", tag = "ip_rules", params(("slug" = String, Path, description = "Tenant slug"), ("rule" = Uuid, Path)), responses((status = 200, body = IpRule), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RulePath { rule }): Path<RulePath>,
) -> AppResult<Json<IpRule>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(ip_rules::get(&state, tenant.id, rule).await?))
}

#[utoipa::path(patch, path = "/admin/tenants/{slug}/ip-rules/{rule}", tag = "ip_rules", params(("slug" = String, Path, description = "Tenant slug"), ("rule" = Uuid, Path)), request_body = IpRuleUpdate, responses((status = 200, body = IpRule), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn update(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RulePath { rule }): Path<RulePath>,
    Json(body): Json<IpRuleUpdate>,
) -> AppResult<Json<IpRule>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        ip_rules::update(&state, tenant.id, admin.actor(), rule, body).await?,
    ))
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/ip-rules/{rule}", tag = "ip_rules", params(("slug" = String, Path, description = "Tenant slug"), ("rule" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RulePath { rule }): Path<RulePath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    ip_rules::delete(&state, tenant.id, admin.actor(), rule).await?;
    Ok(StatusCode::NO_CONTENT)
}
