//! `/t/{slug}/account/tokens`: the user's personal access tokens. Minting
//! and revoking need a recent sign-in; a token itself can never mint another.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Serialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::{AccountCtx, Json};
use crate::models::{CreatedPersonalAccessToken, NewPersonalAccessToken, PersonalAccessToken};
use crate::services::personal_access_tokens as pats;
use crate::state::AppState;

pub fn tokens_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_tokens, create_token))
        .routes(routes!(revoke_token))
}

/// The user's tokens and the scopes a new one may carry.
#[derive(Serialize, utoipa::ToSchema)]
pub struct Tokens {
    pub tokens: Vec<PersonalAccessToken>,
    /// `account` and the admin permissions the user holds.
    pub available_scopes: Vec<String>,
    /// The tenant allows personal access tokens.
    pub enabled: bool,
    /// The longest a token may live in days; `0` means it may never expire.
    pub max_days: u32,
}

#[utoipa::path(get, path = "/t/{slug}/account/tokens", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Tokens), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list_tokens(State(state): State<AppState>, ctx: AccountCtx) -> AppResult<Json<Tokens>> {
    Ok(Json(Tokens {
        tokens: pats::list(&state, ctx.tenant.id, ctx.user.id).await?,
        available_scopes: pats::available_scopes(&state, ctx.tenant.id, ctx.user.id).await?,
        enabled: ctx.tenant.settings.account.personal_tokens,
        max_days: ctx.tenant.settings.account.personal_token_max_days,
    }))
}

/// The token is in the answer once and never again.
#[utoipa::path(post, path = "/t/{slug}/account/tokens", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), request_body = NewPersonalAccessToken, responses((status = 201, body = CreatedPersonalAccessToken), (status = 400, description = "Validation failed", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required, or tokens are not allowed", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create_token(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Json(body): Json<NewPersonalAccessToken>,
) -> AppResult<(StatusCode, Json<CreatedPersonalAccessToken>)> {
    ctx.require_recent(&state).await?;
    let (token, record) = pats::create(&state, &ctx.tenant, ctx.actor(), ctx.user.id, body).await?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedPersonalAccessToken {
            token: token.to_string(),
            record,
        }),
    ))
}

#[derive(serde::Deserialize)]
struct TokenPath {
    token_id: Uuid,
}

#[utoipa::path(delete, path = "/t/{slug}/account/tokens/{token_id}", tag = "account", params(("slug" = String, Path, description = "Tenant slug"), ("token_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem), (status = 404, description = "Not found or already revoked", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke_token(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Path(TokenPath { token_id }): Path<TokenPath>,
) -> AppResult<StatusCode> {
    ctx.require_recent(&state).await?;
    if !pats::revoke(&state, ctx.tenant.id, ctx.actor(), ctx.user.id, token_id).await? {
        return Err(AppError::NotFound("token"));
    }
    Ok(StatusCode::NO_CONTENT)
}
