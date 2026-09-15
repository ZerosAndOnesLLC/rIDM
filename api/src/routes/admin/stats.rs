//! Admin API: dashboard statistics per tenant.

use axum::extract::{Query, State};
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::services::stats::{self, TenantStats};
use crate::state::AppState;

pub fn stats_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(tenant_stats))
}

const P_READ: &str = "ridm:tenants:read";

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct StatsQuery {
    /// Window in days ending now (default 30, at most 365).
    days: Option<u32>,
}

/// Sign-ins and failures per day, live sessions, users and second-factor
/// adoption, and the most authorized clients, for the dashboard.
#[utoipa::path(get, path = "/admin/tenants/{slug}/stats", tag = "tenants", params(("slug" = String, Path, description = "Tenant slug"), StatsQuery), responses((status = 200, body = TenantStats), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn tenant_stats(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Query(q): Query<StatsQuery>,
) -> AppResult<Json<TenantStats>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(
        stats::tenant_stats(&state, tenant.id, q.days.unwrap_or(30)).await?,
    ))
}
