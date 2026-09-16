//! `/t/{slug}/account/export` and `DELETE /t/{slug}/account/me`: taking
//! one's data along, and leaving.

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::error::{AppError, AppResult, FieldError};
use crate::middleware::{AccountCtx, Json};
use crate::services::account::{self, AccountExport};
use crate::state::AppState;

pub fn data_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(export))
        .routes(routes!(delete_me))
}

/// Everything held about the user as one JSON document, offered as a
/// download. Secrets are never part of it.
#[utoipa::path(get, path = "/t/{slug}/account/export", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = AccountExport), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem)), security(("bearer" = [])))]
async fn export(State(state): State<AppState>, ctx: AccountCtx) -> AppResult<Response> {
    ctx.require_recent(&state).await?;
    let doc = account::export(&state, &ctx.tenant, &ctx.user).await?;
    let filename = format!(
        "{}-{}-{}.json",
        ctx.tenant.slug,
        ctx.user
            .username
            .replace(|c: char| !c.is_ascii_alphanumeric(), "_"),
        doc.exported_at.format("%Y%m%d")
    );
    Ok((
        [(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )],
        Json(doc),
    )
        .into_response())
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteAccount {
    /// The username, typed again.
    pub confirm: String,
}

/// Delete the account: every session, token and trusted device ends now,
/// the username and email free up, and the record is purged after the
/// organisation's retention period. Needs a recent sign-in (with the
/// second step once there is one). Administrators cannot delete
/// themselves.
#[utoipa::path(delete, path = "/t/{slug}/account/me", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), request_body = DeleteAccount, responses((status = 204, description = "No content"), (status = 400, description = "Confirmation mismatch", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required, not allowed, or an administrator", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete_me(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Json(body): Json<DeleteAccount>,
) -> AppResult<StatusCode> {
    if !ctx.tenant.settings.account.self_deletion {
        return Err(AppError::Forbidden(
            "this organisation does not allow deleting your own account".into(),
        ));
    }
    ctx.require_recent(&state).await?;
    if body.confirm.trim().to_lowercase() != ctx.user.username {
        return Err(AppError::Validation(vec![FieldError {
            field: "confirm".into(),
            message: "must be your username".into(),
        }]));
    }
    account::delete_own(&state, &ctx.tenant, &ctx.user).await?;
    Ok(StatusCode::NO_CONTENT)
}
