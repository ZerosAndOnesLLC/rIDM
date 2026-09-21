//! `/t/{slug}/account/{email|phone}`: changing the address or number on
//! the account. A code goes to the new destination and confirming it moves
//! the account over; starting a change needs a recent sign-in.

use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::profile::{self, Profile};
use crate::error::{AppError, AppResult, FieldError};
use crate::middleware::{AccountCtx, Json};
use crate::services::contact_changes::{self, Contact};
use crate::services::otp_factors::Sent;
use crate::state::AppState;

pub fn contact_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(change_email, cancel_email_change))
        .routes(routes!(confirm_email_change))
        .routes(routes!(change_phone, cancel_phone_change))
        .routes(routes!(confirm_phone_change))
        .routes(routes!(remove_phone))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewEmail {
    pub email: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewPhone {
    /// E.164.
    pub phone: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Code {
    pub code: String,
}

async fn begin(
    state: &AppState,
    ctx: &AccountCtx,
    contact: Contact,
    destination: &str,
) -> AppResult<Json<Sent>> {
    ctx.require_recent(state).await?;
    Ok(Json(
        contact_changes::begin(state, &ctx.tenant, &ctx.user, contact, destination).await?,
    ))
}

async fn confirm(
    state: &AppState,
    ctx: &AccountCtx,
    contact: Contact,
    code: &str,
) -> AppResult<Json<Profile>> {
    ctx.forbid_impersonation()?;
    match contact_changes::confirm(state, &ctx.tenant, &ctx.user, contact, code).await? {
        Some(user) => Ok(Json(profile::view(state, ctx, &user).await?)),
        None => Err(AppError::Validation(vec![FieldError {
            field: "code".into(),
            message: "is incorrect or expired".into(),
        }])),
    }
}

async fn cancel(state: &AppState, ctx: &AccountCtx, contact: Contact) -> AppResult<StatusCode> {
    contact_changes::cancel(state, ctx.tenant.id, ctx.user.id, contact).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/t/{slug}/account/email/change", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), request_body = NewEmail, responses((status = 200, body = Sent), (status = 400, description = "Invalid address or the current one (field errors)", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem), (status = 409, description = "Address in use", body = crate::error::Problem), (status = 429, description = "Too many codes", body = crate::error::Problem)), security(("bearer" = [])))]
async fn change_email(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Json(body): Json<NewEmail>,
) -> AppResult<Json<Sent>> {
    begin(&state, &ctx, Contact::Email, &body.email).await
}

#[utoipa::path(post, path = "/t/{slug}/account/email/confirm", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), request_body = Code, responses((status = 200, body = Profile), (status = 400, description = "Wrong code or nothing pending", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 409, description = "Address in use", body = crate::error::Problem)), security(("bearer" = [])))]
async fn confirm_email_change(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Json(body): Json<Code>,
) -> AppResult<Json<Profile>> {
    confirm(&state, &ctx, Contact::Email, &body.code).await
}

#[utoipa::path(delete, path = "/t/{slug}/account/email/change", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 204, description = "No content"), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem)), security(("bearer" = [])))]
async fn cancel_email_change(
    State(state): State<AppState>,
    ctx: AccountCtx,
) -> AppResult<StatusCode> {
    cancel(&state, &ctx, Contact::Email).await
}

#[utoipa::path(post, path = "/t/{slug}/account/phone/change", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), request_body = NewPhone, responses((status = 200, body = Sent), (status = 400, description = "Invalid number or the current one (field errors)", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem), (status = 429, description = "Too many codes", body = crate::error::Problem)), security(("bearer" = [])))]
async fn change_phone(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Json(body): Json<NewPhone>,
) -> AppResult<Json<Sent>> {
    begin(&state, &ctx, Contact::Phone, &body.phone).await
}

#[utoipa::path(post, path = "/t/{slug}/account/phone/confirm", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), request_body = Code, responses((status = 200, body = Profile), (status = 400, description = "Wrong code or nothing pending", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem)), security(("bearer" = [])))]
async fn confirm_phone_change(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Json(body): Json<Code>,
) -> AppResult<Json<Profile>> {
    confirm(&state, &ctx, Contact::Phone, &body.code).await
}

#[utoipa::path(delete, path = "/t/{slug}/account/phone/change", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 204, description = "No content"), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem)), security(("bearer" = [])))]
async fn cancel_phone_change(
    State(state): State<AppState>,
    ctx: AccountCtx,
) -> AppResult<StatusCode> {
    cancel(&state, &ctx, Contact::Phone).await
}

#[utoipa::path(delete, path = "/t/{slug}/account/phone", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Profile), (status = 400, description = "The number backs an SMS second step", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem), (status = 404, description = "No number on the account", body = crate::error::Problem)), security(("bearer" = [])))]
async fn remove_phone(State(state): State<AppState>, ctx: AccountCtx) -> AppResult<Json<Profile>> {
    ctx.require_recent(&state).await?;
    let user = contact_changes::remove_phone(&state, &ctx.tenant, &ctx.user).await?;
    Ok(Json(profile::view(&state, &ctx, &user).await?))
}
