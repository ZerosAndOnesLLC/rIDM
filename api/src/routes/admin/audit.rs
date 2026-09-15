//! Admin API: the audit log. Per tenant under `/admin/tenants/{slug}/audit`
//! (list, export, chain verification) and the global chain under
//! `/admin/audit` for global administrators.

use axum::Router;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{AuditEvent, AuditFilter};
use crate::services::audit::{self, ExportFormat, Verification};
use crate::state::AppState;
use crate::util::cursor::Page;

pub fn audit_router() -> Router<AppState> {
    let base = "/admin/tenants/{slug}/audit";
    Router::new()
        .route(base, get(list))
        .route(&format!("{base}/export"), get(export))
        .route(&format!("{base}/verify"), get(verify))
        .route("/admin/audit", get(global_list))
        .route("/admin/audit/export", get(global_export))
        .route("/admin/audit/verify", get(global_verify))
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
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct AuditFilterQuery {
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    pub to: Option<chrono::DateTime<chrono::Utc>>,
    pub name: Option<String>,
    pub actor_id: Option<Uuid>,
    pub subject_id: Option<Uuid>,
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
            user_id: q.user_id,
        }
    }
}

/// `?from=&to=&name=&actor_id=&subject_id=&user_id=&cursor=&limit=`; `name`
/// matches exactly, or as a prefix when it ends with `.` or `*`.
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

async fn verify(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<Verification>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(audit::verify(&state, Some(tenant.id)).await?))
}

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

async fn global_export(
    State(state): State<AppState>,
    admin: AdminCtx,
    Query(q): Query<ExportQuery>,
) -> AppResult<Response> {
    admin.require_global(P_READ)?;
    Ok(stream_export(state, None, q, "audit-global"))
}

async fn global_verify(
    State(state): State<AppState>,
    admin: AdminCtx,
) -> AppResult<Json<Verification>> {
    admin.require_global(P_READ)?;
    Ok(Json(audit::verify(&state, None).await?))
}
