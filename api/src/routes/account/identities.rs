//! `/t/{slug}/account/identities`: the upstream accounts linked to the
//! user's own, linking another (through a one-time ticket the browser
//! takes to the broker) and unlinking one.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::{AccountCtx, Json};
use crate::models::{LinkedIdentity, PublicIdentityProvider};
use crate::services::{broker, identity_providers};
use crate::state::AppState;

pub fn identities_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_identities))
        .routes(routes!(start_link))
        .routes(routes!(unlink_identity))
}

/// The user's linked identities and the providers they could still link.
#[derive(Serialize, utoipa::ToSchema)]
pub struct Identities {
    pub linked: Vec<LinkedIdentity>,
    /// Enabled providers without a link yet.
    pub available: Vec<PublicIdentityProvider>,
}

#[utoipa::path(get, path = "/t/{slug}/account/identities", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Identities), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list_identities(
    State(state): State<AppState>,
    ctx: AccountCtx,
) -> AppResult<Json<Identities>> {
    let linked = broker::identities_of(&state, ctx.tenant.id, ctx.user.id).await?;
    let available = identity_providers::list(&state, ctx.tenant.id)
        .await?
        .iter()
        .filter(|p| p.enabled && p.redirects() && !linked.iter().any(|l| l.idp_id == p.id))
        .map(PublicIdentityProvider::from)
        .collect();
    Ok(Json(Identities { linked, available }))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LinkRequest {
    pub alias: String,
    /// The console page to return to (a path on the UI), default the security page.
    pub return_to: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct LinkStart {
    /// Send the browser here; the provider brings it back to `return_to`
    /// with `?linked=1` or `?link_error=<code>`.
    pub url: String,
}

/// Needs a recent sign-in (with the second step once there is one).
#[utoipa::path(post, path = "/t/{slug}/account/identities/link", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), request_body = LinkRequest, responses((status = 200, body = LinkStart), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem), (status = 404, description = "No such provider", body = crate::error::Problem)), security(("bearer" = [])))]
async fn start_link(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Json(body): Json<LinkRequest>,
) -> AppResult<Json<LinkStart>> {
    ctx.require_recent(&state).await?;
    let idp = identity_providers::get(&state, ctx.tenant.id, &body.alias).await?;
    // A directory identity is linked by signing in with the directory
    // password, not through a redirect.
    if !idp.enabled || !idp.redirects() {
        return Err(AppError::NotFound("identity provider"));
    }
    let return_to = body
        .return_to
        .filter(|p| p.starts_with('/') && !p.starts_with("//"));
    let ticket =
        broker::create_link_ticket(&state, ctx.tenant.id, ctx.user.id, idp.id, return_to).await?;
    let issuer = match &ctx.tenant.settings.custom_domain {
        Some(host) => format!("https://{host}"),
        None => state.config.issuer_for(&ctx.tenant.slug),
    };
    let mut url = url::Url::parse(&format!("{issuer}/broker/{}/start", idp.alias))
        .map_err(|e| AppError::Internal(e.to_string()))?;
    url.query_pairs_mut().append_pair("ticket", &ticket);
    Ok(Json(LinkStart {
        url: url.to_string(),
    }))
}

#[derive(Deserialize)]
struct IdpPath {
    idp_id: Uuid,
}

#[utoipa::path(delete, path = "/t/{slug}/account/identities/{idp_id}", tag = "account", params(("slug" = String, Path, description = "Tenant slug"), ("idp_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem), (status = 404, description = "Not linked", body = crate::error::Problem)), security(("bearer" = [])))]
async fn unlink_identity(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Path(IdpPath { idp_id }): Path<IdpPath>,
) -> AppResult<StatusCode> {
    ctx.require_recent(&state).await?;
    if !broker::unlink(&state, ctx.tenant.id, ctx.actor(), ctx.user.id, idp_id).await? {
        return Err(AppError::NotFound("identity"));
    }
    Ok(StatusCode::NO_CONTENT)
}
