//! `/t/{slug}/account/password`: the user's own password. Changing it
//! needs a recent sign-in (with the second step once there is one) and,
//! when the account has a password, the current one.

use axum::extract::State;
use chrono::{DateTime, Utc};
use ridm_core::events::Actor;
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult, FieldError};
use crate::middleware::{AccountCtx, Json};
use crate::models::PasswordPolicy;
use crate::services::password::{self, SetPasswordOptions, VerifyOutcome};
use crate::services::{refresh_tokens, sessions};
use crate::state::AppState;

pub fn password_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_password, change_password))
}

/// The state of the user's password and the rules a new one must meet.
#[derive(Serialize, utoipa::ToSchema)]
pub struct PasswordStatus {
    /// Passwords are a sign-in method of this tenant.
    pub enabled: bool,
    pub set: bool,
    pub changed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub must_change: bool,
    pub policy: PasswordPolicy,
}

fn status(ctx: &AccountCtx) -> PasswordStatus {
    PasswordStatus {
        enabled: ctx.tenant.settings.auth.password,
        set: ctx.user.has_password(),
        changed_at: ctx.user.password_changed_at,
        expires_at: ctx.user.password_expires_at,
        must_change: ctx.user.must_change_password,
        policy: ctx.tenant.settings.password.clone(),
    }
}

#[utoipa::path(get, path = "/t/{slug}/account/password", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = PasswordStatus), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem)), security(("bearer" = [])))]
async fn get_password(ctx: AccountCtx) -> AppResult<Json<PasswordStatus>> {
    Ok(Json(status(&ctx)))
}

#[derive(Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ChangePassword {
    /// Required while the account has a password.
    pub current_password: Option<String>,
    pub new_password: String,
    /// End every other session and its refresh tokens.
    pub sign_out_others: bool,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct PasswordChanged {
    /// Other sessions ended.
    pub signed_out: u64,
    pub password: PasswordStatus,
}

#[utoipa::path(put, path = "/t/{slug}/account/password", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), request_body = ChangePassword, responses((status = 200, body = PasswordChanged), (status = 400, description = "Wrong current password or policy failure (field errors)", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem)), security(("bearer" = [])))]
async fn change_password(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Json(body): Json<ChangePassword>,
) -> AppResult<Json<PasswordChanged>> {
    if !ctx.tenant.settings.auth.password {
        return Err(AppError::BadRequest(
            "passwords are not a sign-in method of this organisation".into(),
        ));
    }
    ctx.require_recent(&state).await?;
    let policy = &ctx.tenant.settings.password;
    if ctx.user.has_password() {
        let current = body.current_password.unwrap_or_default();
        let outcome = password::verify_and_upgrade(
            &state,
            ctx.tenant.id,
            policy,
            &ctx.user,
            Zeroizing::new(current),
        )
        .await?;
        if outcome == VerifyOutcome::Invalid {
            return Err(AppError::Validation(vec![FieldError {
                field: "current_password".into(),
                message: "is incorrect".into(),
            }]));
        }
    }
    password::set_password(
        &state,
        ctx.tenant.id,
        policy,
        Actor::User { id: ctx.user.id },
        ctx.user.id,
        Zeroizing::new(body.new_password),
        SetPasswordOptions {
            by_user: true,
            notify: true,
            ..Default::default()
        },
    )
    .await?;
    let mut signed_out = 0;
    if body.sign_out_others {
        for s in sessions::list_live_for_user(&state, ctx.tenant.id, ctx.user.id).await? {
            if Some(s.id) == ctx.session_id {
                continue;
            }
            if sessions::revoke(&state, ctx.tenant.id, s.id).await? {
                signed_out += 1;
            }
            refresh_tokens::revoke_for_session(&state, ctx.tenant.id, ctx.actor(), s.id).await?;
        }
    }
    let user = crate::services::users::get(&state, ctx.tenant.id, ctx.user.id).await?;
    let refreshed = AccountCtx { user, ..ctx };
    Ok(Json(PasswordChanged {
        signed_out,
        password: status(&refreshed),
    }))
}
