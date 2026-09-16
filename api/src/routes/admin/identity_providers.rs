//! Admin API: upstream identity providers (`/admin/tenants/{slug}/identity-providers`).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{IdentityProvider, IdentityProviderUpdate, NewIdentityProvider};
use crate::services::identity_providers::{self, Discovery, Preset};
use crate::state::AppState;

pub fn identity_providers_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(presets))
        .routes(routes!(discover))
        .routes(routes!(list, create))
        .routes(routes!(get_one, update, delete))
}

const P_READ: &str = "ridm:idps:read";
const P_WRITE: &str = "ridm:idps:write";

#[derive(Deserialize)]
struct IdpPath {
    /// Row id or alias.
    idp: String,
}

/// A provider with the callback URL the upstream must be told.
#[derive(Serialize, utoipa::ToSchema)]
pub struct IdentityProviderView {
    #[serde(flatten)]
    pub provider: IdentityProvider,
    pub callback_url: String,
}

fn view(
    state: &AppState,
    tenant: &crate::models::Tenant,
    p: IdentityProvider,
) -> IdentityProviderView {
    let issuer = match &tenant.settings.custom_domain {
        Some(host) => format!("https://{host}"),
        None => state.config.issuer_for(&tenant.slug),
    };
    let callback_url = format!("{issuer}/broker/{}/callback", p.alias);
    IdentityProviderView {
        provider: p,
        callback_url,
    }
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/identity-providers/presets", tag = "identity_providers", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Vec<Preset>), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem)), security(("bearer" = [])))]
async fn presets(
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<Vec<Preset>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(identity_providers::PRESETS.to_vec()))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoverBody {
    pub issuer: String,
}

/// Fetch an issuer's OpenID discovery document (to preview the endpoints).
#[utoipa::path(post, path = "/admin/tenants/{slug}/identity-providers/discover", tag = "identity_providers", params(("slug" = String, Path, description = "Tenant slug")), request_body = DiscoverBody, responses((status = 200, body = Discovery), (status = 400, description = "Not an issuer, or its document is unusable", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 503, description = "The issuer could not be reached", body = crate::error::Problem)), security(("bearer" = [])))]
async fn discover(
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<DiscoverBody>,
) -> AppResult<Json<Discovery>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(identity_providers::discover(&body.issuer).await?))
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/identity-providers", tag = "identity_providers", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Vec<IdentityProviderView>), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<Vec<IdentityProviderView>>> {
    admin.require(tenant.id, P_READ)?;
    let rows = identity_providers::list(&state, tenant.id).await?;
    Ok(Json(
        rows.into_iter().map(|p| view(&state, &tenant, p)).collect(),
    ))
}

/// A `preset` fills in the protocol, endpoints, scopes and mappers; an OIDC
/// provider's endpoints are discovered from its `issuer` when left out.
#[utoipa::path(post, path = "/admin/tenants/{slug}/identity-providers", tag = "identity_providers", params(("slug" = String, Path, description = "Tenant slug")), request_body = NewIdentityProvider, responses((status = 201, body = IdentityProviderView), (status = 400, description = "Validation failed", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem), (status = 409, description = "Alias in use", body = crate::error::Problem), (status = 503, description = "The issuer could not be reached", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<NewIdentityProvider>,
) -> AppResult<(StatusCode, Json<IdentityProviderView>)> {
    admin.require(tenant.id, P_WRITE)?;
    let row = identity_providers::create(&state, tenant.id, admin.actor(), body).await?;
    Ok((StatusCode::CREATED, Json(view(&state, &tenant, row))))
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/identity-providers/{idp}", tag = "identity_providers", params(("slug" = String, Path, description = "Tenant slug"), ("idp" = String, Path, description = "Row id or alias")), responses((status = 200, body = IdentityProviderView), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(IdpPath { idp }): Path<IdpPath>,
) -> AppResult<Json<IdentityProviderView>> {
    admin.require(tenant.id, P_READ)?;
    let row = identity_providers::get(&state, tenant.id, &idp).await?;
    Ok(Json(view(&state, &tenant, row)))
}

/// A merge patch; `client_secret: null` clears the secret. A new `issuer`
/// re-discovers the endpoints unless the patch names them.
#[utoipa::path(patch, path = "/admin/tenants/{slug}/identity-providers/{idp}", tag = "identity_providers", params(("slug" = String, Path, description = "Tenant slug"), ("idp" = String, Path, description = "Row id or alias")), request_body = IdentityProviderUpdate, responses((status = 200, body = IdentityProviderView), (status = 400, description = "Validation failed", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem), (status = 409, description = "Alias in use", body = crate::error::Problem)), security(("bearer" = [])))]
async fn update(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(IdpPath { idp }): Path<IdpPath>,
    Json(body): Json<IdentityProviderUpdate>,
) -> AppResult<Json<IdentityProviderView>> {
    admin.require(tenant.id, P_WRITE)?;
    let row = identity_providers::update(&state, tenant.id, admin.actor(), &idp, body).await?;
    Ok(Json(view(&state, &tenant, row)))
}

/// Deleting a provider drops the identities linked through it; the users
/// keep their accounts.
#[utoipa::path(delete, path = "/admin/tenants/{slug}/identity-providers/{idp}", tag = "identity_providers", params(("slug" = String, Path, description = "Tenant slug"), ("idp" = String, Path, description = "Row id or alias")), responses((status = 204, description = "No content"), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(IdpPath { idp }): Path<IdpPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    identity_providers::delete(&state, tenant.id, admin.actor(), &idp).await?;
    Ok(StatusCode::NO_CONTENT)
}
