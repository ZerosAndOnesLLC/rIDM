//! Admin API: scopes (`/admin/tenants/{slug}/scopes`). The standard OIDC
//! scopes exist in every tenant and cannot be deleted; their description,
//! claims and default flag can still be tuned.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{NewScope, Scope, ScopeUpdate};
use crate::services::scopes;
use crate::state::AppState;

pub fn scopes_router() -> Router<AppState> {
    let base = "/admin/tenants/{slug}/scopes";
    Router::new().route(base, get(list).post(create)).route(
        &format!("{base}/{{scope}}"),
        get(get_one).patch(update).delete(delete),
    )
}

const P_READ: &str = "ridm:scopes:read";
const P_WRITE: &str = "ridm:scopes:write";

#[derive(Deserialize)]
struct ScopePath {
    scope: Uuid,
}

async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<Vec<Scope>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(scopes::list(&state, tenant.id).await?.to_vec()))
}

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

async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(ScopePath { scope }): Path<ScopePath>,
) -> AppResult<Json<Scope>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(scopes::get(&state, tenant.id, scope).await?))
}

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
