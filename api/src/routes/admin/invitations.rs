//! Admin API: invitations (`/admin/tenants/{slug}/invitations`). The
//! invitation token travels only in the email; the API never returns it.

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{Invitation, NewInvitation};
use crate::services::invitations;
use crate::state::AppState;
use crate::util::cursor::Page;

pub fn invitations_router() -> Router<AppState> {
    let base = "/admin/tenants/{slug}/invitations";
    Router::new()
        .route(base, get(list).post(create))
        .route(
            &format!("{base}/{{invitation}}"),
            get(get_one).delete(revoke),
        )
        .route(&format!("{base}/{{invitation}}/resend"), post(resend))
}

const P_READ: &str = "ridm:invitations:read";
const P_WRITE: &str = "ridm:invitations:write";

#[derive(Deserialize)]
struct InvitationPath {
    invitation: Uuid,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ListQuery {
    /// Only invitations that can still be accepted.
    open_only: bool,
    cursor: Option<String>,
    limit: Option<u32>,
}

async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Page<Invitation>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(
        invitations::list(&state, tenant.id, q.open_only, q.cursor.as_deref(), q.limit).await?,
    ))
}

/// Emails the invitee; roles and groups are granted on acceptance, so they
/// are checked against the caller's own admin permissions here.
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<NewInvitation>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    for r in &body.roles {
        let granted = crate::services::admin_access::permissions_of_grant(
            &state,
            tenant.id,
            crate::services::admin_access::Grant::Role(*r),
        )
        .await?;
        admin.require_can_grant(granted.iter().map(String::as_str))?;
    }
    for g in &body.groups {
        let granted = crate::services::admin_access::permissions_of_grant(
            &state,
            tenant.id,
            crate::services::admin_access::Grant::Group(*g),
        )
        .await?;
        admin.require_can_grant(granted.iter().map(String::as_str))?;
    }
    let inv = invitations::create(&state, &tenant, admin.actor(), body).await?;
    Ok((StatusCode::CREATED, axum::Json(inv)).into_response())
}

async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(InvitationPath { invitation }): Path<InvitationPath>,
) -> AppResult<Json<Invitation>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(invitations::get(&state, tenant.id, invitation).await?))
}

/// New token and expiry, emailed again; the previous link stops working.
async fn resend(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(InvitationPath { invitation }): Path<InvitationPath>,
) -> AppResult<Json<Invitation>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        invitations::resend(&state, &tenant, admin.actor(), invitation).await?,
    ))
}

async fn revoke(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(InvitationPath { invitation }): Path<InvitationPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    invitations::revoke(&state, tenant.id, admin.actor(), invitation).await?;
    Ok(StatusCode::NO_CONTENT)
}
