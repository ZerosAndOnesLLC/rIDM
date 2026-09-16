//! `/t/{slug}/account/devices`: the browsers the user asked not to be asked
//! for a second step on again.

use axum::extract::Path;
use axum::http::StatusCode;
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::{AccountCtx, Json};
use crate::models::TrustedDevice;
use crate::services::trusted_devices;
use crate::state::AppState;

pub fn devices_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, revoke_all))
        .routes(routes!(revoke))
}

#[utoipa::path(get, path = "/t/{slug}/account/devices", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Vec<TrustedDevice>), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list(
    axum::extract::State(state): axum::extract::State<AppState>,
    ctx: AccountCtx,
) -> AppResult<Json<Vec<TrustedDevice>>> {
    Ok(Json(
        trusted_devices::list(&state, ctx.tenant.id, ctx.user.id).await?,
    ))
}

#[derive(Deserialize)]
struct DevicePath {
    device_id: Uuid,
}

#[utoipa::path(delete, path = "/t/{slug}/account/devices/{device_id}", tag = "account", params(("slug" = String, Path, description = "Tenant slug"), ("device_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke(
    axum::extract::State(state): axum::extract::State<AppState>,
    ctx: AccountCtx,
    Path(DevicePath { device_id }): Path<DevicePath>,
) -> AppResult<StatusCode> {
    ctx.require_recent(&state).await?;
    let ok =
        trusted_devices::revoke(&state, ctx.tenant.id, ctx.actor(), ctx.user.id, device_id).await?;
    if !ok {
        return Err(AppError::NotFound("device"));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/t/{slug}/account/devices", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 204, description = "No content"), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke_all(
    axum::extract::State(state): axum::extract::State<AppState>,
    ctx: AccountCtx,
) -> AppResult<StatusCode> {
    ctx.require_recent(&state).await?;
    trusted_devices::revoke_all(&state, ctx.tenant.id, ctx.user.id).await?;
    Ok(StatusCode::NO_CONTENT)
}
