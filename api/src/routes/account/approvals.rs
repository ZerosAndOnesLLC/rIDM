//! `/t/{slug}/account/backchannel-requests`: the sign-in requests clients
//! sent over the back channel (CIBA) that wait on the user, and the user's
//! answer to each.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::{AccountCtx, Json};
use crate::repos::ciba_requests::PendingRequest;
use crate::services::ciba::{self, Approval};
use crate::services::{consents, sessions};
use crate::state::AppState;

pub fn approvals_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_requests))
        .routes(routes!(approve_request))
        .routes(routes!(deny_request))
}

#[utoipa::path(get, path = "/t/{slug}/account/backchannel-requests", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Vec<PendingRequest>), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list_requests(
    State(state): State<AppState>,
    ctx: AccountCtx,
) -> AppResult<Json<Vec<PendingRequest>>> {
    Ok(Json(
        ciba::list_pending(&state, ctx.tenant.id, ctx.user.id).await?,
    ))
}

#[derive(Deserialize)]
struct RequestPath {
    id: Uuid,
}

/// Approve the request: the client receives tokens for the scopes it asked
/// for, as if the user had signed in to it, and the grant is remembered as
/// consent (so it shows, and can be withdrawn, under connected apps).
#[utoipa::path(post, path = "/t/{slug}/account/backchannel-requests/{id}/approve", tag = "account", params(("slug" = String, Path, description = "Tenant slug"), ("id" = Uuid, Path, description = "The request's id")), responses((status = 204, description = "No content"), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "An impersonated session, or a token without a live sign-in session (a personal access token), cannot approve", body = crate::error::Problem), (status = 404, description = "No such pending request", body = crate::error::Problem)), security(("bearer" = [])))]
async fn approve_request(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Path(RequestPath { id }): Path<RequestPath>,
) -> AppResult<StatusCode> {
    // Letting a client in is the user's decision alone, made in a live
    // sign-in: a personal access token (no session) would otherwise turn
    // itself into the user's tokens at any CIBA client.
    ctx.forbid_impersonation()?;
    let session = match ctx.session_id {
        Some(sid) => {
            sessions::get(&state, ctx.tenant.id, sid, &ctx.tenant.settings.session).await?
        }
        None => None,
    }
    .ok_or_else(|| {
        AppError::Forbidden("approving a sign-in request needs a signed-in session".into())
    })?;
    let approval = Approval {
        user_id: ctx.user.id,
        session_id: session.id,
        auth_time: ctx.auth_time.unwrap_or(session.auth_time),
        amr: ctx.amr.clone(),
        acr: ctx.acr.clone(),
        org_id: session.org_id,
    };
    let granted = ciba::decide(&state, ctx.tenant.id, ctx.user.id, id, Some(approval)).await?;
    if let Some((client_id, scopes)) = granted {
        consents::grant(&state, ctx.tenant.id, ctx.user.id, client_id, &scopes).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Deny the request: the client's next token request is refused with
/// `access_denied`.
#[utoipa::path(post, path = "/t/{slug}/account/backchannel-requests/{id}/deny", tag = "account", params(("slug" = String, Path, description = "Tenant slug"), ("id" = Uuid, Path, description = "The request's id")), responses((status = 204, description = "No content"), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "An impersonated session cannot answer", body = crate::error::Problem), (status = 404, description = "No such pending request", body = crate::error::Problem)), security(("bearer" = [])))]
async fn deny_request(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Path(RequestPath { id }): Path<RequestPath>,
) -> AppResult<StatusCode> {
    ctx.forbid_impersonation()?;
    ciba::decide(&state, ctx.tenant.id, ctx.user.id, id, None).await?;
    Ok(StatusCode::NO_CONTENT)
}
