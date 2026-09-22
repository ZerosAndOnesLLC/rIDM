//! Admin API: the certificate authorities `tls_client_auth` clients may
//! present certificates from (`/admin/tenants/{slug}/mtls/trust-anchors`).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{MtlsTrustAnchor, NewMtlsTrustAnchor};
use crate::services::mtls_trust_anchors;
use crate::state::AppState;

pub fn mtls_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(delete))
}

/// Trusted client-certificate authorities are part of the tenant configuration.
const P_READ: &str = "ridm:tenants:read";
const P_WRITE: &str = "ridm:tenants:write";

#[derive(Deserialize)]
struct AnchorPath {
    anchor: Uuid,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/mtls/trust-anchors", tag = "mtls", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Vec<MtlsTrustAnchor>), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<Vec<MtlsTrustAnchor>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(mtls_trust_anchors::list(&state, tenant.id).await?))
}

/// `{name, certificate_pem}`: one CA certificate (root or intermediate).
#[utoipa::path(post, path = "/admin/tenants/{slug}/mtls/trust-anchors", tag = "mtls", params(("slug" = String, Path, description = "Tenant slug")), request_body = NewMtlsTrustAnchor, responses((status = 201, body = MtlsTrustAnchor), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem), (status = 409, description = "Already trusted", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<NewMtlsTrustAnchor>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let a = mtls_trust_anchors::create(&state, tenant.id, admin.actor(), body).await?;
    Ok((StatusCode::CREATED, axum::Json(a)).into_response())
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/mtls/trust-anchors/{anchor}", tag = "mtls", params(("slug" = String, Path, description = "Tenant slug"), ("anchor" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(AnchorPath { anchor }): Path<AnchorPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    mtls_trust_anchors::delete(&state, tenant.id, admin.actor(), anchor).await?;
    Ok(StatusCode::NO_CONTENT)
}
