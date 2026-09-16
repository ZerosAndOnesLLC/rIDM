//! `GET /t/{slug}/account/me`: who the token belongs to and how they signed in.

use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AccountCtx, Json};
use crate::state::AppState;

pub fn me_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(me))
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AccountMe {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub phone: Option<String>,
    pub phone_verified: bool,
    pub tenant: AccountTenant,
    /// When the sign-in behind this token happened.
    pub auth_time: Option<DateTime<Utc>>,
    /// Authentication context class of the session (`urn:ridm:acr:mfa` after a second step).
    pub acr: Option<String>,
    /// Methods the session was authenticated with.
    pub amr: Vec<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AccountTenant {
    pub slug: String,
    pub display_name: String,
}

#[utoipa::path(get, path = "/t/{slug}/account/me", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = AccountMe), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Token of another tenant or inactive account", body = crate::error::Problem)), security(("bearer" = [])))]
async fn me(ctx: AccountCtx) -> AppResult<Json<AccountMe>> {
    Ok(Json(AccountMe {
        id: ctx.user.id,
        username: ctx.user.username.clone(),
        email: ctx.user.email.clone(),
        email_verified: ctx.user.email_verified,
        phone: ctx.user.phone.clone(),
        phone_verified: ctx.user.phone_verified,
        tenant: AccountTenant {
            slug: ctx.tenant.slug.clone(),
            display_name: ctx.tenant.display_name.clone(),
        },
        auth_time: ctx.auth_time,
        acr: ctx.acr.clone(),
        amr: ctx.amr.clone(),
    }))
}
