//! Admin API: initial access tokens for dynamic client registration
//! (`/admin/tenants/{slug}/dcr/initial-access-tokens`), which
//! `POST /t/{slug}/register` requires when the tenant's `dcr.mode` is
//! `initial_access_token`. They let their holder create clients, so they
//! take the client permissions.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{CreatedInitialAccessToken, InitialAccessToken, NewInitialAccessToken};
use crate::services::dcr;
use crate::state::AppState;

pub fn dcr_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_tokens, issue_token))
        .routes(routes!(revoke_token))
}

const P_READ: &str = "ridm:clients:read";
const P_WRITE: &str = "ridm:clients:write";

#[derive(Deserialize)]
struct TokenPath {
    token: Uuid,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/dcr/initial-access-tokens", tag = "clients", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Vec<InitialAccessToken>), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list_tokens(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<Vec<InitialAccessToken>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(dcr::list(&state, tenant.id).await?))
}

/// The token is returned once, in this response. `expires_in_secs` and
/// `max_uses` are optional; without them the token neither expires nor runs
/// out.
#[utoipa::path(post, path = "/admin/tenants/{slug}/dcr/initial-access-tokens", tag = "clients", params(("slug" = String, Path, description = "Tenant slug")), request_body = NewInitialAccessToken, responses((status = 201, body = CreatedInitialAccessToken), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn issue_token(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<NewInitialAccessToken>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let created = dcr::issue(&state, tenant.id, admin.actor(), body).await?;
    let mut res = (StatusCode::CREATED, Json(created)).into_response();
    if let Ok(v) = "no-store".parse() {
        res.headers_mut()
            .insert(axum::http::header::CACHE_CONTROL, v);
    }
    Ok(res)
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/dcr/initial-access-tokens/{token}", tag = "clients", params(("slug" = String, Path, description = "Tenant slug"), ("token" = Uuid, Path, description = "Token id")), responses((status = 204, description = "Revoked"), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke_token(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(TokenPath { token }): Path<TokenPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    dcr::revoke(&state, tenant.id, admin.actor(), token).await?;
    Ok(StatusCode::NO_CONTENT)
}
