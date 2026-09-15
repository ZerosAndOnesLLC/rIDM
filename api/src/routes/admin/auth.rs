//! Admin API entry points that belong to the auth layer itself.

use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use uuid::Uuid;

use crate::middleware::{AdminCtx, AdminScope};
use crate::services::admin_access::{ADMIN_AUDIENCE, BUILT_IN_ROLES, CATALOGUE, PermissionDef};
use crate::state::AppState;

pub fn auth_router() -> Router<AppState> {
    Router::new()
        .route("/admin/me", get(me))
        .route("/admin/permissions", get(permissions))
}

#[derive(Serialize)]
struct Me {
    user_id: Uuid,
    username: String,
    tenant_id: Uuid,
    tenant_slug: String,
    scope: AdminScope,
    roles: Vec<String>,
    permissions: Vec<String>,
}

/// Who the caller is and what they may do; the admin UI reads this after login.
async fn me(admin: AdminCtx) -> Json<Me> {
    Json(Me {
        user_id: admin.user_id,
        username: admin.username.clone(),
        tenant_id: admin.tenant.id,
        tenant_slug: admin.tenant.slug.clone(),
        scope: admin.scope,
        roles: admin.roles.clone(),
        permissions: admin.permissions.names().to_vec(),
    })
}

#[derive(Serialize)]
struct BuiltInRoleDoc {
    name: &'static str,
    description: &'static str,
    permissions: Vec<&'static str>,
}

#[derive(Serialize)]
struct PermissionModel {
    audience: &'static str,
    permissions: &'static [PermissionDef],
    roles: Vec<BuiltInRoleDoc>,
}

/// The permission catalogue and built-in roles (for role editors and docs).
async fn permissions(_admin: AdminCtx) -> Json<PermissionModel> {
    Json(PermissionModel {
        audience: ADMIN_AUDIENCE,
        permissions: CATALOGUE,
        roles: BUILT_IN_ROLES
            .iter()
            .map(|r| BuiltInRoleDoc {
                name: r.name,
                description: r.description,
                permissions: r.permissions(),
            })
            .collect(),
    })
}
