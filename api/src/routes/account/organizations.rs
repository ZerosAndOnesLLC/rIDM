//! `/t/{slug}/account/organizations`: the organizations the signed-in user
//! belongs to, and which one this session acts in.

use axum::extract::State;
use serde::Serialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AccountCtx, Json};
use crate::services::organizations;
use crate::state::AppState;

pub fn organizations_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(list_organizations))
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AccountOrganization {
    pub id: Uuid,
    pub slug: String,
    pub display_name: String,
    /// The user's primary organization.
    pub primary: bool,
}

/// Read-only: membership is managed by an administrator, by an invitation or
/// by a verified auto-join domain. To act in another one, sign in again.
#[utoipa::path(get, path = "/t/{slug}/account/organizations", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Vec<AccountOrganization>), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list_organizations(
    State(state): State<AppState>,
    ctx: AccountCtx,
) -> AppResult<Json<Vec<AccountOrganization>>> {
    let orgs = organizations::of_user(&state, ctx.tenant.id, ctx.user.id).await?;
    Ok(Json(
        orgs.into_iter()
            .map(|o| AccountOrganization {
                primary: ctx.user.org_id == Some(o.id),
                id: o.id,
                slug: o.slug,
                display_name: o.display_name,
            })
            .collect(),
    ))
}
