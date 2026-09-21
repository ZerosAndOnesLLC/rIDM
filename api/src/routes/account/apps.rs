//! `/t/{slug}/account/apps`: the applications the user granted access to,
//! and taking that access back.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::{AccountCtx, Json};
use crate::services::account::{self, ConsentedApp};
use crate::state::AppState;

pub fn apps_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_apps))
        .routes(routes!(revoke_app))
}

#[utoipa::path(get, path = "/t/{slug}/account/apps", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Vec<ConsentedApp>), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list_apps(
    State(state): State<AppState>,
    ctx: AccountCtx,
) -> AppResult<Json<Vec<ConsentedApp>>> {
    Ok(Json(
        account::consented_apps(&state, ctx.tenant.id, ctx.user.id).await?,
    ))
}

#[derive(Deserialize)]
struct AppPath {
    client_id: Uuid,
}

/// Withdraw the consent and the refresh tokens the application holds; its
/// next sign-in asks again.
#[utoipa::path(delete, path = "/t/{slug}/account/apps/{client_id}", tag = "account", params(("slug" = String, Path, description = "Tenant slug"), ("client_id" = Uuid, Path, description = "The client's row id")), responses((status = 204, description = "No content"), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke_app(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Path(AppPath { client_id }): Path<AppPath>,
) -> AppResult<StatusCode> {
    // Consent is the user's to give and to take back.
    ctx.forbid_impersonation()?;
    if !account::revoke_app(&state, ctx.tenant.id, ctx.user.id, client_id).await? {
        return Err(AppError::NotFound("consent"));
    }
    Ok(StatusCode::NO_CONTENT)
}
