//! Admin API: SCIM provisioning tokens (`/admin/tenants/{slug}/scim/tokens`).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{CreatedScimToken, NewScimToken, ScimTokens};
use crate::services::scim_tokens;
use crate::state::AppState;

pub fn scim_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(revoke))
}

const P_READ: &str = "ridm:scim:read";
const P_WRITE: &str = "ridm:scim:write";

#[derive(Deserialize)]
struct TokenPath {
    token: Uuid,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/scim/tokens", tag = "scim", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = ScimTokens), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<ScimTokens>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(scim_tokens::list(&state, &tenant).await?))
}

/// The token is returned once, in this response.
#[utoipa::path(post, path = "/admin/tenants/{slug}/scim/tokens", tag = "scim", params(("slug" = String, Path, description = "Tenant slug")), request_body = NewScimToken, responses((status = 201, body = CreatedScimToken), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<NewScimToken>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let created = scim_tokens::create(&state, tenant.id, admin.actor(), body).await?;
    Ok((StatusCode::CREATED, Json(created)).into_response())
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/scim/tokens/{token}", tag = "scim", params(("slug" = String, Path, description = "Tenant slug"), ("token" = Uuid, Path)), responses((status = 204, description = "Revoked"), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(TokenPath { token }): Path<TokenPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    scim_tokens::revoke(&state, tenant.id, admin.actor(), token).await?;
    Ok(StatusCode::NO_CONTENT)
}
