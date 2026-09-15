//! Admin API: IP rules (`/admin/tenants/{slug}/ip-rules`).

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{IpRule, IpRuleUpdate, NewIpRule};
use crate::services::ip_rules;
use crate::state::AppState;

pub fn ip_rules_router() -> Router<AppState> {
    let base = "/admin/tenants/{slug}/ip-rules";
    Router::new().route(base, get(list).post(create)).route(
        &format!("{base}/{{rule}}"),
        get(get_one).patch(update).delete(delete),
    )
}

/// IP rules are part of the tenant configuration.
const P_READ: &str = "ridm:tenants:read";
const P_WRITE: &str = "ridm:tenants:write";

#[derive(Deserialize)]
struct RulePath {
    rule: Uuid,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ListQuery {
    /// Only rules bound to this client.
    client_id: Option<Uuid>,
    /// Only tenant-wide rules.
    tenant_wide: bool,
}

async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Vec<IpRule>>> {
    admin.require(tenant.id, P_READ)?;
    let scope = match (q.client_id, q.tenant_wide) {
        (Some(c), _) => Some(Some(c)),
        (None, true) => Some(None),
        (None, false) => None,
    };
    Ok(Json(ip_rules::list(&state, tenant.id, scope).await?))
}

/// `{cidr, action?: allow|deny (default deny), client_id?, description?}`.
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<NewIpRule>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let r = ip_rules::create(&state, tenant.id, admin.actor(), body).await?;
    Ok((StatusCode::CREATED, axum::Json(r)).into_response())
}

async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RulePath { rule }): Path<RulePath>,
) -> AppResult<Json<IpRule>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(ip_rules::get(&state, tenant.id, rule).await?))
}

async fn update(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RulePath { rule }): Path<RulePath>,
    Json(body): Json<IpRuleUpdate>,
) -> AppResult<Json<IpRule>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        ip_rules::update(&state, tenant.id, admin.actor(), rule, body).await?,
    ))
}

async fn delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RulePath { rule }): Path<RulePath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    ip_rules::delete(&state, tenant.id, admin.actor(), rule).await?;
    Ok(StatusCode::NO_CONTENT)
}
