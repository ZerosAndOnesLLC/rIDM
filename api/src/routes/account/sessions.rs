//! `/t/{slug}/account/sessions`: where the user is signed in. Ending a
//! session (or all of them) needs a recent sign-in.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::{AccountCtx, Json};
use crate::services::sessions::SsoSession;
use crate::services::{logout, sessions};
use crate::state::AppState;

pub fn sessions_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_sessions, revoke_all_sessions))
        .routes(routes!(revoke_session))
}

/// A live browser session of the user.
#[derive(Serialize, utoipa::ToSchema)]
pub struct AccountSession {
    pub id: Uuid,
    /// The session this request was made from.
    pub current: bool,
    pub auth_time: DateTime<Utc>,
    pub amr: Vec<String>,
    pub acr: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl AccountSession {
    fn from(s: SsoSession, current: Option<Uuid>) -> Self {
        Self {
            id: s.id,
            current: Some(s.id) == current,
            auth_time: s.auth_time,
            amr: s.amr,
            acr: s.acr,
            ip: s.ip,
            user_agent: s.user_agent,
            created_at: s.created_at,
            last_seen_at: s.last_seen_at,
            expires_at: s.expires_at.min(s.idle_expires_at),
        }
    }
}

#[utoipa::path(get, path = "/t/{slug}/account/sessions", tag = "account", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Vec<AccountSession>), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list_sessions(
    State(state): State<AppState>,
    ctx: AccountCtx,
) -> AppResult<Json<Vec<AccountSession>>> {
    let mut live = sessions::list_live_for_user(&state, ctx.tenant.id, ctx.user.id).await?;
    // Newest first, the current one on top.
    live.sort_by_key(|s| std::cmp::Reverse(s.last_seen_at));
    let mut out: Vec<AccountSession> = live
        .into_iter()
        .map(|s| AccountSession::from(s, ctx.session_id))
        .collect();
    out.sort_by_key(|s| !s.current);
    Ok(Json(out))
}

#[derive(Deserialize)]
struct SessionPath {
    session_id: Uuid,
}

#[utoipa::path(delete, path = "/t/{slug}/account/sessions/{session_id}", tag = "account", params(("slug" = String, Path, description = "Tenant slug"), ("session_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke_session(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Path(SessionPath { session_id }): Path<SessionPath>,
) -> AppResult<StatusCode> {
    ctx.require_recent(&state).await?;
    let live = sessions::list_live_for_user(&state, ctx.tenant.id, ctx.user.id).await?;
    if !live.iter().any(|s| s.id == session_id) {
        return Err(AppError::NotFound("session"));
    }
    logout::end_session(&state, &ctx.tenant, session_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(default)]
pub struct RevokeAllQuery {
    /// Keep the session this request was made from.
    pub keep_current: bool,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct Revoked {
    pub revoked: u64,
}

#[utoipa::path(delete, path = "/t/{slug}/account/sessions", tag = "account", params(("slug" = String, Path, description = "Tenant slug"), RevokeAllQuery), responses((status = 200, body = Revoked), (status = 401, description = "Missing or invalid account token", body = crate::error::Problem), (status = 403, description = "Recent authentication required", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke_all_sessions(
    State(state): State<AppState>,
    ctx: AccountCtx,
    Query(q): Query<RevokeAllQuery>,
) -> AppResult<Json<Revoked>> {
    ctx.require_recent(&state).await?;
    let keep = if q.keep_current { ctx.session_id } else { None };
    let revoked = logout::end_sessions_for_user(&state, &ctx.tenant, ctx.user.id, keep).await?;
    Ok(Json(Revoked { revoked }))
}
