//! Admin API: the audit log. Per tenant under `/admin/tenants/{slug}/audit`
//! (list, export, chain verification) and the global chain under
//! `/admin/audit` for global administrators.

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{AuditEvent, AuditFilter};
use crate::services::audit::{self, ExportFormat, Verification};
use crate::state::AppState;
use crate::util::cursor::Page;

pub fn audit_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(export))
        .routes(routes!(verify))
        .routes(routes!(global_list))
        .routes(routes!(global_export))
        .routes(routes!(global_verify))
}

const P_READ: &str = "ridm:audit:read";

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ListQuery {
    #[serde(flatten)]
    pub filter: AuditFilterQuery,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

/// `AuditFilter` spelled out for the query string.
#[derive(Deserialize, Default, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(default)]
pub struct AuditFilterQuery {
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    pub to: Option<chrono::DateTime<chrono::Utc>>,
    pub name: Option<String>,
    pub actor_id: Option<Uuid>,
    pub subject_id: Option<Uuid>,
    /// Rows an administrator caused while impersonating someone.
    pub impersonator_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
}

impl From<AuditFilterQuery> for AuditFilter {
    fn from(q: AuditFilterQuery) -> Self {
        Self {
            from: q.from,
            to: q.to,
            name: q.name,
            actor_id: q.actor_id,
            subject_id: q.subject_id,
            impersonator_id: q.impersonator_id,
            user_id: q.user_id,
        }
    }
}

/// `?from=&to=&name=&actor_id=&subject_id=&impersonator_id=&user_id=&cursor=&limit=`; `name`
/// matches exactly, or as a prefix when it ends with `.` or `*`.
#[utoipa::path(get, path = "/admin/tenants/{slug}/audit", tag = "audit", params(("slug" = String, Path, description = "Tenant slug"), AuditFilterQuery, ("cursor" = Option<String>, Query), ("limit" = Option<u32>, Query)), responses((status = 200, body = Page<AuditEvent>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Page<AuditEvent>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(
        audit::list(
            &state,
            Some(tenant.id),
            &q.filter.into(),
            q.cursor.as_deref(),
            q.limit,
        )
        .await?,
    ))
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ExportQuery {
    #[serde(flatten)]
    pub filter: AuditFilterQuery,
    pub format: Option<ExportFormat>,
}

fn stream_export(
    state: AppState,
    tenant_id: Option<Uuid>,
    q: ExportQuery,
    filename: &str,
) -> Response {
    let format = q.format.unwrap_or(ExportFormat::Json);
    let (content_type, ext) = match format {
        ExportFormat::Json => ("application/json", "json"),
        ExportFormat::Csv => ("text/csv; charset=utf-8", "csv"),
    };
    let mut res =
        Body::from_stream(audit::export(state, tenant_id, q.filter.into(), format)).into_response();
    let h = res.headers_mut();
    if let Ok(v) = content_type.parse() {
        h.insert(header::CONTENT_TYPE, v);
    }
    if let Ok(v) = format!("attachment; filename=\"{filename}.{ext}\"").parse() {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Ok(v) = "no-store".parse() {
        h.insert(header::CACHE_CONTROL, v);
    }
    res
}

/// Oldest first, streamed, with the chain hashes so the file can be verified offline.
#[utoipa::path(get, path = "/admin/tenants/{slug}/audit/export", tag = "audit", params(("slug" = String, Path, description = "Tenant slug"), AuditFilterQuery, ("format" = Option<String>, Query, description = "json (default) or csv")), responses((status = 200, description = "Streamed file"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn export(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Query(q): Query<ExportQuery>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_READ)?;
    let name = format!("audit-{}", tenant.slug);
    Ok(stream_export(state, Some(tenant.id), q, &name))
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/audit/verify", tag = "audit", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Verification), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn verify(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<Verification>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(audit::verify(&state, Some(tenant.id)).await?))
}

#[utoipa::path(get, path = "/admin/audit", tag = "audit", params(AuditFilterQuery, ("cursor" = Option<String>, Query), ("limit" = Option<u32>, Query)), responses((status = 200, body = Page<AuditEvent>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn global_list(
    State(state): State<AppState>,
    admin: AdminCtx,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Page<AuditEvent>>> {
    admin.require_global(P_READ)?;
    Ok(Json(
        audit::list(&state, None, &q.filter.into(), q.cursor.as_deref(), q.limit).await?,
    ))
}

#[utoipa::path(get, path = "/admin/audit/export", tag = "audit", params(AuditFilterQuery, ("format" = Option<String>, Query, description = "json (default) or csv")), responses((status = 200, description = "Streamed file"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn global_export(
    State(state): State<AppState>,
    admin: AdminCtx,
    Query(q): Query<ExportQuery>,
) -> AppResult<Response> {
    admin.require_global(P_READ)?;
    Ok(stream_export(state, None, q, "audit-global"))
}

#[utoipa::path(get, path = "/admin/audit/verify", tag = "audit", responses((status = 200, body = Verification), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn global_verify(
    State(state): State<AppState>,
    admin: AdminCtx,
) -> AppResult<Json<Verification>> {
    admin.require_global(P_READ)?;
    Ok(Json(audit::verify(&state, None).await?))
}
