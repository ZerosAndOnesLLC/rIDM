//! Admin API: download tickets for the exports (`/admin/download-tickets`).
//! See [`crate::services::download_tickets`].

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::error::{AppError, AppResult};
use crate::middleware::{AdminCtx, Json, bearer_with_scheme, resolve_tenant};
use crate::services::download_tickets::{self, Export, TICKET_TTL_SECS};
use crate::state::AppState;

pub fn downloads_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(create))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct NewDownloadTicket {
    /// The export to download, as its path and query, e.g.
    /// `/admin/tenants/acme/users/export?format=csv`.
    path: String,
}

#[derive(Serialize, utoipa::ToSchema)]
struct DownloadTicket {
    /// The export's URL with the ticket: one `GET` of it, without an
    /// `Authorization` header, within `expires_in` seconds.
    url: String,
    expires_in: u64,
}

/// What the export itself requires of the caller (the permission its
/// handler checks).
async fn may_export(state: &AppState, caller: &AdminCtx, export: &Export) -> AppResult<()> {
    let (slug, permission) = match export {
        Export::GlobalAudit => return caller.require_global("ridm:audit:read"),
        Export::TenantConfig { slug } => (slug, "ridm:tenants:export"),
        Export::Users { slug } => (slug, "ridm:users:read"),
        Export::Audit { slug } => (slug, "ridm:audit:read"),
    };
    let tenant = resolve_tenant(state, slug)
        .await?
        .ok_or(AppError::NotFound("tenant"))?;
    caller.require(tenant.id, permission)
}

/// A single-use URL for one of the exports, so a browser can download it
/// with its own download manager (streamed to disk) instead of holding it in
/// memory. The caller must hold what the export itself requires.
#[utoipa::path(post, path = "/admin/download-tickets", tag = "downloads", request_body = NewDownloadTicket, responses((status = 201, body = DownloadTicket), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    headers: HeaderMap,
    Json(body): Json<NewDownloadTicket>,
) -> AppResult<Response> {
    let target: axum::http::uri::PathAndQuery = body
        .path
        .parse()
        .map_err(|_| AppError::BadRequest("path must be a path and query".into()))?;
    let export = Export::of_path(target.path()).ok_or_else(|| {
        AppError::BadRequest("download tickets are for the export routes only".into())
    })?;
    // Checked now as the export will check it, so a refusal shows here rather
    // than as a failed download.
    may_export(&state, &admin, &export).await?;
    // The ticket stands for the credential this request came with.
    let (scheme, token) = bearer_with_scheme(&headers).ok_or_else(|| {
        AppError::BadRequest("a download ticket is asked for with a token".into())
    })?;
    let url = download_tickets::issue(
        &state,
        scheme,
        &token,
        target.path(),
        target.query().unwrap_or_default(),
    )
    .await?;
    // The URL is a credential for a minute: never cached, never compressed.
    Ok(crate::middleware::security_headers::no_store(
        (
            StatusCode::CREATED,
            Json(DownloadTicket {
                url,
                expires_in: TICKET_TTL_SECS,
            }),
        )
            .into_response(),
    ))
}
