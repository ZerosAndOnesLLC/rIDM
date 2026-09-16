//! `/t/{slug}/account/profile`: the user's own profile, shaped by the
//! tenant's profile schema. Attributes the schema marks `editable_by: user`
//! may change; the rest are shown read-only and kept as they are.

use axum::extract::State;
use ridm_core::events::Actor;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::error::{AppError, AppResult};
use crate::middleware::{AccountCtx, Json};
use crate::models::{AttributeDef, User, UserUpdate};
use crate::services::contact_changes::{self, PendingChanges};
use crate::services::{messaging, profile_schema, users};
use crate::state::AppState;
use crate::util::patch::double_option;

pub fn profile_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get_profile, patch_profile))
}

/// The user's profile with the schema the console renders it by.
#[derive(Serialize, utoipa::ToSchema)]
pub struct Profile {
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub phone: Option<String>,
    pub phone_verified: bool,
    pub locale: Option<String>,
    /// Values of the declared attributes (undeclared ones are internal).
    pub attributes: Value,
    /// The declared attributes in form order; `editable_by` says which
    /// the user may change.
    pub schema: Vec<AttributeDef>,
    /// Email or phone changes awaiting their code, masked.
    pub pending: PendingChanges,
    /// Locales the tenant supports, for the locale picker.
    pub locales: Vec<String>,
}

pub(super) async fn view(state: &AppState, ctx: &AccountCtx, user: &User) -> AppResult<Profile> {
    let schema = profile_schema::get(state, ctx.tenant.id).await?;
    let mut defs = schema.attributes.clone();
    defs.sort_by(|a, b| a.order.cmp(&b.order).then(a.name.cmp(&b.name)));
    let values: Map<String, Value> = defs
        .iter()
        .filter_map(|d| {
            user.attributes
                .get(&d.name)
                .map(|v| (d.name.clone(), v.clone()))
        })
        .collect();
    let mut locales = ctx.tenant.settings.locale.supported.clone();
    if !locales.contains(&ctx.tenant.settings.locale.default) {
        locales.insert(0, ctx.tenant.settings.locale.default.clone());
    }
    Ok(Profile {
        username: user.username.clone(),
        email: user.email.clone(),
        email_verified: user.email_verified,
        phone: user.phone.clone(),
        phone_verified: user.phone_verified,
        locale: user.locale.clone(),
        attributes: Value::Object(values),
        schema: defs,
        pending: contact_changes::pending(state, ctx.tenant.id, user.id).await?,
        locales,
    })
}

#[utoipa::path(get, path = "/t/{slug}/account/profile", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Profile), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem)), security(("bearer" = [])))]
async fn get_profile(State(state): State<AppState>, ctx: AccountCtx) -> AppResult<Json<Profile>> {
    Ok(Json(view(&state, &ctx, &ctx.user).await?))
}

/// A merge patch: only the fields present change. `attributes` replaces
/// the user-editable attributes (those left out are cleared; attributes
/// the user may not edit are kept whether sent unchanged or not).
#[derive(Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ProfilePatch {
    pub attributes: Option<Value>,
    #[serde(deserialize_with = "double_option")]
    pub locale: Option<Option<String>>,
}

#[utoipa::path(patch, path = "/t/{slug}/account/profile", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), request_body = ProfilePatch, responses((status = 200, body = Profile), (status = 400, description = "Validation failed", body = crate::error::Problem), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem)), security(("bearer" = [])))]
async fn patch_profile(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Json(body): Json<ProfilePatch>,
) -> AppResult<Json<Profile>> {
    let locale = match body.locale {
        Some(Some(l)) => {
            let l = messaging::validate_locale(&l)?;
            let supported = &ctx.tenant.settings.locale;
            if l != supported.default && !supported.supported.contains(&l) {
                return Err(AppError::BadRequest(
                    "locale is not one this organisation supports".into(),
                ));
            }
            Some(Some(l))
        }
        Some(None) => Some(None),
        None => None,
    };
    let patch = UserUpdate {
        attributes: body.attributes,
        locale,
        ..Default::default()
    };
    let user = users::update(
        &state,
        ctx.tenant.id,
        Actor::User { id: ctx.user.id },
        ctx.user.id,
        patch,
    )
    .await?;
    Ok(Json(view(&state, &ctx, &user).await?))
}
