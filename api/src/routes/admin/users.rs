//! Admin API: users (`/admin/tenants/{slug}/users`) and everything hanging
//! off a user: password, sessions, credentials, trusted devices, roles,
//! groups and consents.
//!
//! Reads need `ridm:users:read`, writes `ridm:users:write`. Handing out a
//! role or a group membership is additionally checked against the caller's
//! own admin permissions so nobody can grant what they do not hold.
//! Signing in as a user needs `ridm:users:impersonate`.

use axum::body::Body;
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::http::header::{self, HeaderMap};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::middleware::client_ip;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{
    Consent, Credential, Group, LinkedIdentity, NewUser, PersonalAccessToken, Principal, Role,
    TrustedDevice, User, UserFilter, UserStatus, UserUpdate,
};
use crate::repos;
use crate::routes::admin::AuditFilterQuery;
use crate::services::admin_access::{self, Grant};
use crate::services::bulk_users::{self, ExportFormat, ImportReport};
use crate::services::password::{self, SetPasswordOptions};
use crate::services::sessions::{self, Impersonator, SsoSession};
use crate::services::{
    broker, consents, groups, impersonation, logout, roles, trusted_devices, users,
};
use crate::state::AppState;
use crate::util::cursor::Page;

pub fn users_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(import))
        .route_layer(DefaultBodyLimit::max(IMPORT_BODY_LIMIT))
        .routes(routes!(list, create))
        .routes(routes!(export))
        .routes(routes!(get_one, update, delete))
        .routes(routes!(set_password))
        .routes(routes!(force_password_change))
        .routes(routes!(unlock))
        .routes(routes!(list_sessions, revoke_sessions))
        .routes(routes!(impersonate))
        .routes(routes!(revoke_session))
        .routes(routes!(credentials))
        .routes(routes!(delete_credential))
        .routes(routes!(devices, revoke_devices))
        .routes(routes!(revoke_device))
        .routes(routes!(user_roles))
        .routes(routes!(assign_role, unassign_role))
        .routes(routes!(user_groups))
        .routes(routes!(join_group, leave_group))
        .routes(routes!(user_consents))
        .routes(routes!(user_audit))
        .routes(routes!(revoke_consent))
        .routes(routes!(user_identities))
        .routes(routes!(unlink_identity))
        .routes(routes!(user_pats))
        .routes(routes!(revoke_pat))
}

const P_READ: &str = "ridm:users:read";
const P_WRITE: &str = "ridm:users:write";
const P_IMPERSONATE: &str = "ridm:users:impersonate";
/// Bulk import is an invitation-side power in the catalogue; creating users
/// with credentials also needs the users permission.
const P_IMPORT: &str = "ridm:invitations:write";
/// 32 MiB of JSON or CSV per import request.
const IMPORT_BODY_LIMIT: usize = 32 * 1024 * 1024;

#[derive(Deserialize)]
struct UserPath {
    user: Uuid,
}

/// A live (not soft-deleted) user of the tenant.
async fn load(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<User> {
    let user = users::get(state, tenant_id, id).await?;
    if user.deleted_at.is_some() {
        return Err(AppError::NotFound("user"));
    }
    Ok(user)
}

/// `UserFilter` spelled out: a flattened struct would read every query
/// value as a string and reject the booleans.
#[derive(Deserialize, Default, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(default)]
struct ListQuery {
    search: Option<String>,
    #[param(inline)]
    status: Option<UserStatus>,
    org_id: Option<Uuid>,
    include_deleted: bool,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/users", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ListQuery), responses((status = 200, body = Page<User>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Page<User>>> {
    admin.require(tenant.id, P_READ)?;
    let filter = UserFilter {
        search: q.search,
        status: q.status,
        org_id: q.org_id,
        include_deleted: q.include_deleted,
    };
    Ok(Json(
        users::list(&state, tenant.id, &filter, q.cursor.as_deref(), q.limit).await?,
    ))
}

/// Password fields accepted alongside the user on creation.
#[derive(Deserialize, Default)]
#[serde(default)]
struct CreatePassword {
    password: Option<String>,
    /// Generate a temporary password (returned once) instead of `password`.
    temporary_password: bool,
}

/// Response to a create or password change that minted a temporary password.
#[derive(Serialize, utoipa::ToSchema)]
struct CreatedUser {
    #[serde(flatten)]
    user: User,
    #[serde(skip_serializing_if = "Option::is_none")]
    temporary_password: Option<String>,
}

fn no_store(mut res: Response) -> Response {
    if let Ok(v) = "no-store".parse() {
        res.headers_mut()
            .insert(axum::http::header::CACHE_CONTROL, v);
    }
    res
}

/// Body: every `NewUser` field plus `password` or `temporary_password: true`.
/// A temporary password is returned exactly once and must be changed at
/// first login; an explicit password is checked against the tenant policy.
#[utoipa::path(post, path = "/admin/tenants/{slug}/users", tag = "users", params(("slug" = String, Path, description = "Tenant slug")), request_body(content = serde_json::Value, description = "NewUser fields plus `password` or `temporary_password: true`"), responses((status = 201, body = CreatedUser), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(mut body): Json<Value>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let Some(fields) = body.as_object_mut() else {
        return Err(AppError::BadRequest("body must be an object".into()));
    };
    let mut pw = CreatePassword::default();
    if let Some(v) = fields.remove("password") {
        pw.password = Some(
            serde_json::from_value(v)
                .map_err(|_| AppError::BadRequest("password must be a string".into()))?,
        );
    }
    if let Some(v) = fields.remove("temporary_password") {
        pw.temporary_password = v
            .as_bool()
            .ok_or_else(|| AppError::BadRequest("temporary_password must be a boolean".into()))?;
    }
    if pw.password.is_some() && pw.temporary_password {
        return Err(AppError::BadRequest(
            "send either password or temporary_password".into(),
        ));
    }
    if let Some(p) = &pw.password {
        let problems = password::check_policy(&tenant.settings.password, p, None);
        if !problems.is_empty() {
            return Err(AppError::BadRequest(format!(
                "password: {}",
                problems.join("; ")
            )));
        }
    }
    let input: NewUser = serde_json::from_value(body)
        .map_err(|e| AppError::BadRequest(format!("invalid user: {e}")))?;
    // As in an import: `locked` and `deleted` are states the system reaches,
    // not ones a new account starts in.
    if matches!(input.status, Some(UserStatus::Locked | UserStatus::Deleted)) {
        return Err(AppError::BadRequest(
            "status must be active, disabled or pending".into(),
        ));
    }
    let user = users::create(&state, tenant.id, admin.actor(), input).await?;
    let mut temporary = None;
    if let Some(p) = pw.password {
        password::set_password(
            &state,
            tenant.id,
            &tenant.settings.password,
            admin.actor(),
            user.id,
            Zeroizing::new(p),
            SetPasswordOptions {
                must_change: false,
                skip_policy: false,
                by_user: false,
                notify: false,
            },
        )
        .await?;
    } else if pw.temporary_password {
        let t = password::set_temporary_password(
            &state,
            tenant.id,
            &tenant.settings.password,
            admin.actor(),
            user.id,
        )
        .await?;
        temporary = Some(t.to_string());
    }
    let user = users::get(&state, tenant.id, user.id).await?;
    Ok(no_store(
        (
            StatusCode::CREATED,
            axum::Json(CreatedUser {
                user,
                temporary_password: temporary,
            }),
        )
            .into_response(),
    ))
}

/// The user plus what an admin page shows at a glance.
#[derive(Serialize, utoipa::ToSchema)]
struct UserDetail {
    #[serde(flatten)]
    user: User,
    password: PasswordSummary,
    roles: Vec<Role>,
    effective_roles: Vec<Role>,
    groups: Vec<Group>,
}

#[derive(Serialize, utoipa::ToSchema)]
struct PasswordSummary {
    set: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    algorithm: Option<String>,
    changed_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    must_change: bool,
}

impl From<&User> for PasswordSummary {
    fn from(u: &User) -> Self {
        Self {
            set: u.has_password(),
            algorithm: u.password_algo.clone(),
            changed_at: u.password_changed_at,
            expires_at: u.password_expires_at,
            must_change: u.must_change_password,
        }
    }
}

async fn direct_roles(state: &AppState, tenant_id: Uuid, user_id: Uuid) -> AppResult<Vec<Role>> {
    let assignments =
        roles::assignments_of(state, tenant_id, Principal::User { id: user_id }).await?;
    let mut out = Vec::with_capacity(assignments.len());
    for a in assignments {
        if let Ok(r) = roles::get(state, tenant_id, a.role_id).await {
            out.push(r);
        }
    }
    Ok(out)
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/users/{user}", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path)), responses((status = 200, body = UserDetail), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
) -> AppResult<Json<UserDetail>> {
    admin.require(tenant.id, P_READ)?;
    let u = load(&state, tenant.id, user).await?;
    let roles_direct = direct_roles(&state, tenant.id, user).await?;
    let effective = roles::effective_roles(&state, tenant.id, user, None).await?;
    let groups = groups::groups_of_user(&state, tenant.id, user, false).await?;
    Ok(Json(UserDetail {
        password: PasswordSummary::from(&u),
        user: u,
        roles: roles_direct,
        effective_roles: effective.to_vec(),
        groups,
    }))
}

/// Partial update: absent = unchanged, `null` clears. `status` covers
/// enable/disable (`active` / `disabled`); `locked` and `deleted` are set by
/// the system, use the unlock and delete routes instead.
#[utoipa::path(patch, path = "/admin/tenants/{slug}/users/{user}", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path)), request_body = UserUpdate, responses((status = 200, body = User), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn update(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
    Json(body): Json<UserUpdate>,
) -> AppResult<Json<User>> {
    admin.require(tenant.id, P_WRITE)?;
    if let Some(s) = body.status
        && !matches!(s, UserStatus::Active | UserStatus::Disabled)
    {
        return Err(AppError::BadRequest(
            "status can only be set to active or disabled".into(),
        ));
    }
    load(&state, tenant.id, user).await?;
    // Disabling ends every session at once (in `users::update`).
    let updated = users::update(&state, tenant.id, admin.actor(), user, body).await?;
    Ok(Json(updated))
}

/// Soft delete; sessions and trusted devices end at once.
#[utoipa::path(delete, path = "/admin/tenants/{slug}/users/{user}", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    load(&state, tenant.id, user).await?;
    // Ends every session too (in `users::delete`).
    users::delete(&state, tenant.id, admin.actor(), user).await?;
    trusted_devices::revoke_all(&state, tenant.id, user).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
struct PasswordBody {
    /// Absent: generate a temporary password and return it once.
    password: Option<String>,
    /// Force a change at next login (always true for temporary passwords).
    must_change: bool,
    /// Skip the tenant policy and history checks.
    skip_policy: bool,
    /// Email the user that their password changed.
    notify: bool,
    /// End the user's sessions so the new password is needed everywhere.
    revoke_sessions: bool,
}

#[derive(Serialize, utoipa::ToSchema)]
struct TemporaryPassword {
    temporary_password: String,
}

#[utoipa::path(put, path = "/admin/tenants/{slug}/users/{user}/password", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path)), request_body(content = PasswordBody, description = "Optional"), responses((status = 200, body = TemporaryPassword), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn set_password(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
    body: Option<Json<PasswordBody>>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    load(&state, tenant.id, user).await?;
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let res = match body.password {
        Some(p) => {
            password::set_password(
                &state,
                tenant.id,
                &tenant.settings.password,
                admin.actor(),
                user,
                Zeroizing::new(p),
                SetPasswordOptions {
                    must_change: body.must_change,
                    skip_policy: body.skip_policy,
                    by_user: false,
                    notify: body.notify,
                },
            )
            .await?;
            StatusCode::NO_CONTENT.into_response()
        }
        None => {
            let t = password::set_temporary_password(
                &state,
                tenant.id,
                &tenant.settings.password,
                admin.actor(),
                user,
            )
            .await?;
            no_store(
                axum::Json(TemporaryPassword {
                    temporary_password: t.to_string(),
                })
                .into_response(),
            )
        }
    };
    if body.revoke_sessions {
        logout::end_sessions_for_user(&state, &tenant, user, None).await?;
    }
    Ok(res)
}

/// Flag the account so the next login demands a new password.
#[utoipa::path(post, path = "/admin/tenants/{slug}/users/{user}/force-password-change", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path)), responses((status = 200, body = User), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn force_password_change(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
) -> AppResult<Json<User>> {
    admin.require(tenant.id, P_WRITE)?;
    load(&state, tenant.id, user).await?;
    let updated = users::update(
        &state,
        tenant.id,
        admin.actor(),
        user,
        UserUpdate {
            must_change_password: Some(true),
            ..Default::default()
        },
    )
    .await?;
    Ok(Json(updated))
}

/// Clear a lockout (failed-attempt counter and `locked` status).
#[utoipa::path(post, path = "/admin/tenants/{slug}/users/{user}/unlock", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path)), responses((status = 200, body = User), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn unlock(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
) -> AppResult<Json<User>> {
    admin.require(tenant.id, P_WRITE)?;
    load(&state, tenant.id, user).await?;
    users::unlock(&state, tenant.id, admin.actor(), user).await?;
    Ok(Json(users::get(&state, tenant.id, user).await?))
}

// --- sessions ---------------------------------------------------------------

#[utoipa::path(get, path = "/admin/tenants/{slug}/users/{user}/sessions", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path)), responses((status = 200, body = Vec<SsoSession>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list_sessions(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
) -> AppResult<Json<Vec<SsoSession>>> {
    admin.require(tenant.id, P_READ)?;
    load(&state, tenant.id, user).await?;
    Ok(Json(
        sessions::list_live_for_user(&state, tenant.id, user).await?,
    ))
}

#[derive(Serialize, utoipa::ToSchema)]
struct Revoked {
    revoked: u64,
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/users/{user}/sessions", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path)), responses((status = 200, body = Revoked), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke_sessions(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
) -> AppResult<Json<Revoked>> {
    admin.require(tenant.id, P_WRITE)?;
    load(&state, tenant.id, user).await?;
    let revoked = logout::end_sessions_for_user(&state, &tenant, user, None).await?;
    Ok(Json(Revoked { revoked }))
}

#[derive(Deserialize)]
struct SessionPath {
    user: Uuid,
    session_id: Uuid,
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/users/{user}/sessions/{session_id}", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path), ("session_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke_session(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(SessionPath { user, session_id }): Path<SessionPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    let live = sessions::list_live_for_user(&state, tenant.id, user).await?;
    if !live.iter().any(|s| s.id == session_id) {
        return Err(AppError::NotFound("session"));
    }
    logout::end_session(&state, &tenant, session_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- impersonation ----------------------------------------------------------

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct ImpersonateBody {
    /// Why: recorded with every audit event of the impersonation (1–500
    /// characters).
    reason: String,
}

#[derive(Serialize, utoipa::ToSchema)]
struct ImpersonationTicket {
    /// Open this in a browser to become the user there. It works once, and
    /// only until `expires_at`.
    url: String,
    expires_at: DateTime<Utc>,
}

/// Sign in as the user: a one-time URL that opens a session as them in the
/// browser that follows it. The tenant must allow impersonation, the user
/// must be active and hold no admin permission, and every token from the
/// session names the caller in `act`.
#[utoipa::path(post, path = "/admin/tenants/{slug}/users/{user}/impersonate", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path)), request_body = ImpersonateBody, responses((status = 200, body = ImpersonationTicket), (status = 400, description = "No reason, or the caller themselves", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing, impersonation off, or the user is an administrator", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem), (status = 409, description = "The user is not active", body = crate::error::Problem)), security(("bearer" = [])))]
async fn impersonate(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ImpersonateBody>,
) -> AppResult<Json<ImpersonationTicket>> {
    admin.require(tenant.id, P_IMPERSONATE)?;
    let ip = client_ip(&state, &headers, Some(peer));
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let issued = impersonation::request(
        &state,
        &tenant,
        user,
        Impersonator {
            user_id: admin.user_id,
            tenant_id: admin.tenant.id,
            username: admin.username.clone(),
        },
        &body.reason,
        (ip, user_agent),
    )
    .await?;
    Ok(Json(ImpersonationTicket {
        url: issued.url,
        expires_at: issued.expires_at,
    }))
}

// --- credentials and devices ------------------------------------------------

#[derive(Serialize, utoipa::ToSchema)]
struct Credentials {
    password: PasswordSummary,
    /// MFA factors, passkeys and recovery codes (metadata only).
    credentials: Vec<Credential>,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/users/{user}/credentials", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path)), responses((status = 200, body = Credentials), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn credentials(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
) -> AppResult<Json<Credentials>> {
    admin.require(tenant.id, P_READ)?;
    let u = load(&state, tenant.id, user).await?;
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    let rows = repos::credentials::list_for_user(&mut *tx, tenant.id, user).await?;
    tx.commit().await?;
    Ok(Json(Credentials {
        password: PasswordSummary::from(&u),
        credentials: rows,
    }))
}

#[derive(Deserialize)]
struct CredentialPath {
    user: Uuid,
    credential_id: Uuid,
}

/// Remove a factor (the user lost the device, say). The password is not a
/// row here; replace it through `PUT .../password`.
#[utoipa::path(delete, path = "/admin/tenants/{slug}/users/{user}/credentials/{credential_id}", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path), ("credential_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete_credential(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(CredentialPath {
        user,
        credential_id,
    }): Path<CredentialPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    load(&state, tenant.id, user).await?;
    // The recovery codes go with the last second factor, as in the account
    // console.
    crate::services::totp::remove_credential(&state, tenant.id, user, credential_id, false)
        .await?
        .ok_or(AppError::NotFound("credential"))?;
    crate::services::notifications::mfa_changed(&state, tenant.id, user, "removed").await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/users/{user}/devices", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path)), responses((status = 200, body = Vec<TrustedDevice>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn devices(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
) -> AppResult<Json<Vec<TrustedDevice>>> {
    admin.require(tenant.id, P_READ)?;
    load(&state, tenant.id, user).await?;
    Ok(Json(trusted_devices::list(&state, tenant.id, user).await?))
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/users/{user}/devices", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path)), responses((status = 200, body = Revoked), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke_devices(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
) -> AppResult<Json<Revoked>> {
    admin.require(tenant.id, P_WRITE)?;
    load(&state, tenant.id, user).await?;
    let revoked = trusted_devices::revoke_all(&state, tenant.id, user).await?;
    Ok(Json(Revoked { revoked }))
}

#[derive(Deserialize)]
struct DevicePath {
    user: Uuid,
    device_id: Uuid,
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/users/{user}/devices/{device_id}", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path), ("device_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke_device(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(DevicePath { user, device_id }): Path<DevicePath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    load(&state, tenant.id, user).await?;
    if !trusted_devices::revoke(&state, tenant.id, admin.actor(), user, device_id).await? {
        return Err(AppError::NotFound("device"));
    }
    Ok(StatusCode::NO_CONTENT)
}

// --- roles and groups -------------------------------------------------------

#[derive(Serialize, utoipa::ToSchema)]
struct UserRoles {
    /// Assigned to the user directly.
    direct: Vec<Role>,
    /// Direct plus inherited through groups and composites.
    effective: Vec<Role>,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/users/{user}/roles", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path)), responses((status = 200, body = UserRoles), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn user_roles(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
) -> AppResult<Json<UserRoles>> {
    admin.require(tenant.id, P_READ)?;
    load(&state, tenant.id, user).await?;
    Ok(Json(UserRoles {
        direct: direct_roles(&state, tenant.id, user).await?,
        effective: roles::effective_roles(&state, tenant.id, user, None)
            .await?
            .to_vec(),
    }))
}

#[derive(Deserialize)]
struct RolePath {
    user: Uuid,
    role_id: Uuid,
}

#[utoipa::path(put, path = "/admin/tenants/{slug}/users/{user}/roles/{role_id}", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path), ("role_id" = Uuid, Path)), responses((status = 200, body = UserRoles), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn assign_role(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RolePath { user, role_id }): Path<RolePath>,
) -> AppResult<Json<UserRoles>> {
    admin.require(tenant.id, P_WRITE)?;
    load(&state, tenant.id, user).await?;
    roles::get(&state, tenant.id, role_id).await?;
    let granted =
        admin_access::permissions_of_grant(&state, tenant.id, Grant::Role(role_id)).await?;
    admin.require_can_grant(granted.iter().map(String::as_str))?;
    roles::assign(
        &state,
        tenant.id,
        admin.actor(),
        role_id,
        Principal::User { id: user },
    )
    .await?;
    Ok(Json(UserRoles {
        direct: direct_roles(&state, tenant.id, user).await?,
        effective: roles::effective_roles(&state, tenant.id, user, None)
            .await?
            .to_vec(),
    }))
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/users/{user}/roles/{role_id}", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path), ("role_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn unassign_role(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(RolePath { user, role_id }): Path<RolePath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    load(&state, tenant.id, user).await?;
    roles::unassign(
        &state,
        tenant.id,
        admin.actor(),
        role_id,
        Principal::User { id: user },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, utoipa::ToSchema)]
struct UserGroups {
    /// Groups the user is a member of.
    direct: Vec<Group>,
    /// Direct plus their ancestors.
    effective: Vec<Group>,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/users/{user}/groups", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path)), responses((status = 200, body = UserGroups), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn user_groups(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
) -> AppResult<Json<UserGroups>> {
    admin.require(tenant.id, P_READ)?;
    load(&state, tenant.id, user).await?;
    Ok(Json(UserGroups {
        direct: groups::groups_of_user(&state, tenant.id, user, false).await?,
        effective: groups::groups_of_user(&state, tenant.id, user, true).await?,
    }))
}

#[derive(Deserialize)]
struct GroupPath {
    user: Uuid,
    group_id: Uuid,
}

#[utoipa::path(put, path = "/admin/tenants/{slug}/users/{user}/groups/{group_id}", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path), ("group_id" = Uuid, Path)), responses((status = 200, body = UserGroups), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn join_group(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(GroupPath { user, group_id }): Path<GroupPath>,
) -> AppResult<Json<UserGroups>> {
    admin.require(tenant.id, P_WRITE)?;
    load(&state, tenant.id, user).await?;
    groups::get(&state, tenant.id, group_id).await?;
    let granted =
        admin_access::permissions_of_grant(&state, tenant.id, Grant::Group(group_id)).await?;
    admin.require_can_grant(granted.iter().map(String::as_str))?;
    groups::add_member(&state, tenant.id, admin.actor(), group_id, user).await?;
    Ok(Json(UserGroups {
        direct: groups::groups_of_user(&state, tenant.id, user, false).await?,
        effective: groups::groups_of_user(&state, tenant.id, user, true).await?,
    }))
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/users/{user}/groups/{group_id}", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path), ("group_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn leave_group(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(GroupPath { user, group_id }): Path<GroupPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    load(&state, tenant.id, user).await?;
    groups::remove_member(&state, tenant.id, admin.actor(), group_id, user).await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- consents ---------------------------------------------------------------

#[utoipa::path(get, path = "/admin/tenants/{slug}/users/{user}/consents", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path)), responses((status = 200, body = Vec<Consent>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn user_consents(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
) -> AppResult<Json<Vec<Consent>>> {
    admin.require(tenant.id, P_READ)?;
    load(&state, tenant.id, user).await?;
    Ok(Json(
        consents::list_for_user(&state, tenant.id, user).await?,
    ))
}

#[derive(Deserialize)]
struct ConsentPath {
    user: Uuid,
    client_id: Uuid,
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/users/{user}/consents/{client_id}", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path), ("client_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke_consent(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(ConsentPath { user, client_id }): Path<ConsentPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    load(&state, tenant.id, user).await?;
    if !consents::revoke(&state, tenant.id, admin.actor(), user, client_id).await? {
        return Err(AppError::NotFound("consent"));
    }
    Ok(StatusCode::NO_CONTENT)
}

// --- linked identities -------------------------------------------------------

#[utoipa::path(get, path = "/admin/tenants/{slug}/users/{user}/identities", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path)), responses((status = 200, body = Vec<LinkedIdentity>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn user_identities(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
) -> AppResult<Json<Vec<LinkedIdentity>>> {
    admin.require(tenant.id, P_READ)?;
    load(&state, tenant.id, user).await?;
    Ok(Json(broker::identities_of(&state, tenant.id, user).await?))
}

#[derive(Deserialize)]
struct IdentityPath {
    user: Uuid,
    idp_id: Uuid,
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/users/{user}/identities/{idp_id}", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path), ("idp_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn unlink_identity(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(IdentityPath { user, idp_id }): Path<IdentityPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    load(&state, tenant.id, user).await?;
    if !broker::unlink(&state, tenant.id, admin.actor(), user, idp_id).await? {
        return Err(AppError::NotFound("identity"));
    }
    Ok(StatusCode::NO_CONTENT)
}

// --- personal access tokens ---------------------------------------------------

#[utoipa::path(get, path = "/admin/tenants/{slug}/users/{user}/pats", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path)), responses((status = 200, body = Vec<PersonalAccessToken>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn user_pats(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
) -> AppResult<Json<Vec<PersonalAccessToken>>> {
    admin.require(tenant.id, P_READ)?;
    load(&state, tenant.id, user).await?;
    Ok(Json(
        crate::services::personal_access_tokens::list(&state, tenant.id, user).await?,
    ))
}

#[derive(Deserialize)]
struct PatPath {
    user: Uuid,
    token_id: Uuid,
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/users/{user}/pats/{token_id}", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path), ("token_id" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke_pat(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(PatPath { user, token_id }): Path<PatPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    load(&state, tenant.id, user).await?;
    if !crate::services::personal_access_tokens::revoke(
        &state,
        tenant.id,
        admin.actor(),
        user,
        token_id,
    )
    .await?
    {
        return Err(AppError::NotFound("token"));
    }
    Ok(StatusCode::NO_CONTENT)
}

// --- bulk import and export -------------------------------------------------

#[derive(Deserialize, Default, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(default)]
struct ImportQuery {
    /// Validate only; nothing is written.
    dry_run: bool,
}

/// `POST .../users/import` with `application/json` (an array of users or
/// `{"users": [...]}`) or `text/csv` (header row; `attr.<name>` columns become
/// profile attributes). Rows are processed independently; the report names
/// every row that failed and why.
#[utoipa::path(post, path = "/admin/tenants/{slug}/users/import", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ImportQuery), request_body(content = Vec<crate::services::bulk_users::ImportRow>, description = "JSON array (or {\"users\": [...]}) as application/json, or CSV with a header row as text/csv"), responses((status = 200, body = ImportReport), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn import(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Query(q): Query<ImportQuery>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> AppResult<Json<ImportReport>> {
    admin.require(tenant.id, P_WRITE)?;
    admin.require(tenant.id, P_IMPORT)?;
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let rows = if content_type.starts_with("text/csv") {
        bulk_users::parse_csv(&body)?
    } else if content_type.starts_with("application/json") {
        bulk_users::parse_json(&body)?
    } else {
        return Err(AppError::BadRequest(
            "send application/json or text/csv".into(),
        ));
    };
    Ok(Json(
        bulk_users::import(
            &state,
            &tenant,
            admin.actor(),
            rows,
            q.dry_run,
            &|perms: &[String]| admin.require_can_grant(perms.iter().map(String::as_str)),
        )
        .await?,
    ))
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct ExportQuery {
    #[serde(default = "default_format")]
    #[param(inline)]
    format: ExportFormat,
}

fn default_format() -> ExportFormat {
    ExportFormat::Json
}

/// `GET .../users/export?format=json|csv`: every live user, streamed page by
/// page, without credentials.
#[utoipa::path(get, path = "/admin/tenants/{slug}/users/export", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ExportQuery), responses((status = 200, description = "Streamed file"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn export(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Query(q): Query<ExportQuery>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_READ)?;
    let (content_type, filename) = match q.format {
        ExportFormat::Json => ("application/json", "users.json"),
        ExportFormat::Csv => ("text/csv; charset=utf-8", "users.csv"),
    };
    let stream = bulk_users::export(state, tenant.id, q.format);
    let mut res = Body::from_stream(stream).into_response();
    let h = res.headers_mut();
    if let Ok(v) = content_type.parse() {
        h.insert(header::CONTENT_TYPE, v);
    }
    if let Ok(v) = format!("attachment; filename=\"{filename}\"").parse() {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Ok(v) = "no-store".parse() {
        h.insert(header::CACHE_CONTROL, v);
    }
    Ok(res)
}

// --- audit ------------------------------------------------------------------

/// Audit rows where the user is the actor or the subject (`ridm:audit:read`).
#[utoipa::path(get, path = "/admin/tenants/{slug}/users/{user}/audit", tag = "users", params(("slug" = String, Path, description = "Tenant slug"), ("user" = Uuid, Path), AuditFilterQuery, ("cursor" = Option<String>, Query), ("limit" = Option<u32>, Query)), responses((status = 200, body = crate::util::cursor::Page<crate::models::AuditEvent>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn user_audit(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(UserPath { user }): Path<UserPath>,
    Query(q): Query<crate::routes::admin::ListQuery>,
) -> AppResult<Json<crate::util::cursor::Page<crate::models::AuditEvent>>> {
    admin.require(tenant.id, "ridm:audit:read")?;
    users::get(&state, tenant.id, user).await?;
    let mut filter: crate::models::AuditFilter = q.filter.into();
    filter.user_id = Some(user);
    Ok(Json(
        crate::services::audit::list(
            &state,
            Some(tenant.id),
            &filter,
            q.cursor.as_deref(),
            q.limit,
        )
        .await?,
    ))
}
