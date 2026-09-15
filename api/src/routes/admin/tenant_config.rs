//! Admin API: tenant configuration as code (`/admin/tenants/{slug}/export`
//! and `/import`).

use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::services::tenant_config::{self, ApplyReport, TenantConfig};
use crate::state::AppState;

pub fn tenant_config_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(export))
        .routes(routes!(import))
}

/// Deterministic JSON (sorted keys and collections, natural keys, no secrets).
#[utoipa::path(get, path = "/admin/tenants/{slug}/export", tag = "tenant_config", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = TenantConfig), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn export(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Response> {
    admin.require(tenant.id, "ridm:tenants:export")?;
    let doc = tenant_config::export(&state, &tenant).await?;
    let body = serde_json::to_string_pretty(&doc)? + "\n";
    let mut res = body.into_response();
    let h = res.headers_mut();
    if let Ok(v) = "application/json".parse() {
        h.insert(header::CONTENT_TYPE, v);
    }
    if let Ok(v) = format!("attachment; filename=\"tenant-{}.json\"", tenant.slug).parse() {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Ok(v) = "no-store".parse() {
        h.insert(header::CACHE_CONTROL, v);
    }
    Ok(res)
}

#[derive(Deserialize, Default, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(default)]
struct ImportQuery {
    /// Plan only.
    dry_run: bool,
    /// Also delete configuration the document does not mention.
    prune: bool,
}

/// `?dry_run=true` returns the plan (creates, updates with field diffs, and
/// with `prune` deletes). Without it the plan is applied; the report lists
/// what was applied, any per-item errors, and the secrets of clients and
/// webhooks the import created (shown once). Applying the same document
/// again yields an empty plan.
#[utoipa::path(post, path = "/admin/tenants/{slug}/import", tag = "tenant_config", params(("slug" = String, Path, description = "Tenant slug"), ImportQuery), request_body = TenantConfig, responses((status = 200, body = ApplyReport), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn import(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Query(q): Query<ImportQuery>,
    Json(doc): Json<TenantConfig>,
) -> AppResult<Response> {
    admin.require(tenant.id, "ridm:tenants:import")?;
    let report = if q.dry_run {
        ApplyReport {
            dry_run: true,
            plan: tenant_config::plan(&state, &tenant, doc, q.prune).await?,
            applied: 0,
            errors: vec![],
            secrets: Default::default(),
        }
    } else {
        tenant_config::apply(&state, &tenant, admin.actor(), doc, q.prune).await?
    };
    let mut res = axum::Json(report).into_response();
    if let Ok(v) = "no-store".parse() {
        res.headers_mut().insert(header::CACHE_CONTROL, v);
    }
    Ok(res)
}
