//! Admin API: OAuth/OIDC clients (`/admin/tenants/{slug}/clients`).
//!
//! Creation applies the type-driven defaults of the client service; updates
//! are JSON merge patches over the client's metadata so an auto-saving UI can
//! send just the section that changed. Secrets are shown exactly once, on
//! creation and on rotation; reads return their ids and validity only.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{Client, ClientStatus, NewClient, User};
use crate::repos;
use crate::services::{clients, scopes};
use crate::state::AppState;
use crate::util::cursor::Page;
use crate::util::patch::merge_patch;

pub fn clients_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(get_one, update, delete))
        .routes(routes!(rotate_secret))
        .routes(routes!(revoke_secret))
        .routes(routes!(enable_service_account, disable_service_account))
        .routes(routes!(registration_token))
}

const P_READ: &str = "ridm:clients:read";
const P_WRITE: &str = "ridm:clients:write";

/// Client as returned to administrators: every metadata column, plus the
/// secrets' ids and validity windows (never the secrets or their hashes).
#[derive(Serialize, utoipa::ToSchema)]
pub struct ClientView {
    #[serde(flatten)]
    pub client: Client,
    pub secrets: Vec<SecretView>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct SecretView {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    /// `null` while current; set once a rotation retired the secret.
    pub expires_at: Option<DateTime<Utc>>,
}

impl From<Client> for ClientView {
    fn from(client: Client) -> Self {
        let now = Utc::now();
        let secrets = client
            .secret_hashes
            .iter()
            .filter(|s| s.is_active(now))
            .map(|s| SecretView {
                id: s.id,
                created_at: s.created_at,
                expires_at: s.expires_at,
            })
            .collect();
        Self { client, secrets }
    }
}

/// A view plus a secret that is shown exactly once.
#[derive(Serialize, utoipa::ToSchema)]
struct RevealView {
    #[serde(flatten)]
    view: ClientView,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
}

fn reveal(
    status: StatusCode,
    client: Client,
    secret: Option<zeroize::Zeroizing<String>>,
) -> Response {
    let body = RevealView {
        view: client.into(),
        client_secret: secret.map(|s| s.to_string()),
    };
    let mut res = (status, axum::Json(body)).into_response();
    if let Ok(v) = "no-store".parse() {
        res.headers_mut()
            .insert(axum::http::header::CACHE_CONTROL, v);
    }
    res
}

#[derive(Deserialize)]
struct ClientPath {
    client: String,
}

/// `{client}` is the client's `id` or its public `client_id`.
async fn resolve_client(state: &AppState, tenant_id: Uuid, key: &str) -> AppResult<Client> {
    if let Ok(id) = Uuid::parse_str(key)
        && let Ok(c) = clients::get(state, tenant_id, id).await
    {
        return Ok(c);
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let c = repos::clients::find_by_client_id(&mut *tx, tenant_id, key).await?;
    tx.commit().await?;
    c.ok_or(AppError::NotFound("client"))
}

/// Scopes and audiences must name things the tenant has; a typo here would
/// otherwise only surface as `invalid_scope` / `invalid_target` at the token
/// endpoint.
async fn check_references(state: &AppState, tenant_id: Uuid, c: &NewClient) -> AppResult<()> {
    if let Some(names) = &c.allowed_scopes {
        let (_, unknown) = scopes::resolve(state, tenant_id, names).await?;
        if !unknown.is_empty() {
            return Err(AppError::BadRequest(format!(
                "unknown scope(s): {}",
                unknown.join(", ")
            )));
        }
    }
    if !c.allowed_audiences.is_empty() {
        let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
        for identifier in &c.allowed_audiences {
            if repos::resource_servers::find_by_identifier(&mut *tx, tenant_id, identifier)
                .await?
                .is_none()
            {
                return Err(AppError::BadRequest(format!(
                    "unknown audience `{identifier}` (no such resource server)"
                )));
            }
        }
        tx.commit().await?;
    }
    Ok(())
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct ListQuery {
    search: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/clients", tag = "clients", params(("slug" = String, Path, description = "Tenant slug"), ListQuery), responses((status = 200, body = Page<ClientView>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Page<ClientView>>> {
    admin.require(tenant.id, P_READ)?;
    let page = clients::list(
        &state,
        tenant.id,
        q.search.as_deref(),
        q.cursor.as_deref(),
        q.limit,
    )
    .await?;
    Ok(Json(Page {
        items: page.items.into_iter().map(ClientView::from).collect(),
        next_cursor: page.next_cursor,
    }))
}

#[utoipa::path(post, path = "/admin/tenants/{slug}/clients", tag = "clients", params(("slug" = String, Path, description = "Tenant slug")), request_body = NewClient, responses((status = 201, body = RevealView), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<NewClient>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    check_references(&state, tenant.id, &body).await?;
    let created = clients::create(&state, tenant.id, admin.actor(), body).await?;
    Ok(reveal(
        StatusCode::CREATED,
        created.client,
        created.client_secret,
    ))
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/clients/{client}", tag = "clients", params(("slug" = String, Path, description = "Tenant slug"), ("client" = String, Path)), responses((status = 200, body = ClientView), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(ClientPath { client }): Path<ClientPath>,
) -> AppResult<Json<ClientView>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(
        resolve_client(&state, tenant.id, &client).await?.into(),
    ))
}

/// Columns of the stored row that are not metadata and therefore not patchable.
const NON_METADATA: [&str; 6] = [
    "id",
    "tenant_id",
    "service_account_user_id",
    "status",
    "created_at",
    "updated_at",
];

/// Merge patch over the client's metadata document (every field a `POST`
/// accepts): send only what changed; `null` clears an optional field or
/// resets a defaulted one to its type-driven default. `status` may be sent
/// alongside. Switching to a secret-based auth method mints a secret that is
/// returned once in `client_secret`.
#[utoipa::path(patch, path = "/admin/tenants/{slug}/clients/{client}", tag = "clients", params(("slug" = String, Path, description = "Tenant slug"), ("client" = String, Path)), request_body(content = serde_json::Value, description = "JSON merge patch over the client metadata, plus `status`"), responses((status = 200, body = RevealView), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn update(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(ClientPath { client }): Path<ClientPath>,
    Json(mut patch): Json<Value>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let Some(fields) = patch.as_object_mut() else {
        return Err(AppError::BadRequest("patch must be an object".into()));
    };
    let current = resolve_client(&state, tenant.id, &client).await?;
    let status: Option<ClientStatus> = match fields.remove("status") {
        Some(v) => Some(
            serde_json::from_value(v)
                .map_err(|_| AppError::BadRequest("status must be active or disabled".into()))?,
        ),
        None => None,
    };
    if let Some(id) = fields.get("client_id")
        && id.as_str() != Some(current.client_id.as_str())
    {
        return Err(AppError::BadRequest("client_id cannot be changed".into()));
    }
    for k in NON_METADATA {
        if fields.contains_key(k) {
            return Err(AppError::BadRequest(format!("`{k}` cannot be patched")));
        }
    }
    let (mut client, secret) = if fields.is_empty() {
        (current, None)
    } else {
        let mut doc = serde_json::to_value(&current)?;
        if let Some(map) = doc.as_object_mut() {
            for k in NON_METADATA {
                map.remove(k);
            }
        }
        merge_patch(&mut doc, &patch);
        let input: NewClient = serde_json::from_value(doc)
            .map_err(|e| AppError::BadRequest(format!("invalid client metadata: {e}")))?;
        check_references(&state, tenant.id, &input).await?;
        clients::update_metadata(&state, tenant.id, admin.actor(), current.id, input).await?
    };
    if let Some(s) = status
        && s != client.status
    {
        client = clients::set_status(&state, tenant.id, admin.actor(), client.id, s).await?;
    }
    Ok(reveal(StatusCode::OK, client, secret))
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/clients/{client}", tag = "clients", params(("slug" = String, Path, description = "Tenant slug"), ("client" = String, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(ClientPath { client }): Path<ClientPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    let c = resolve_client(&state, tenant.id, &client).await?;
    clients::delete(&state, tenant.id, admin.actor(), c.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
struct RotateBody {
    /// How long the previous secret keeps working (default 24h, `0` retires
    /// it at once, at most 30 days).
    grace_secs: Option<i64>,
}

/// Generate a new secret (first one, or a rotation with a grace window for
/// the previous secret). The secret is in the response and nowhere else.
#[utoipa::path(post, path = "/admin/tenants/{slug}/clients/{client}/secrets", tag = "clients", params(("slug" = String, Path, description = "Tenant slug"), ("client" = String, Path)), request_body(content = RotateBody, description = "Optional"), responses((status = 201, body = RevealView), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn rotate_secret(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(ClientPath { client }): Path<ClientPath>,
    body: Option<Json<RotateBody>>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let c = resolve_client(&state, tenant.id, &client).await?;
    let grace = body
        .and_then(|Json(b)| b.grace_secs)
        .map(chrono::Duration::seconds);
    let (client, secret) =
        clients::rotate_secret(&state, tenant.id, admin.actor(), c.id, grace).await?;
    Ok(reveal(StatusCode::CREATED, client, Some(secret)))
}

#[derive(Deserialize)]
struct SecretPath {
    client: String,
    secret_id: Uuid,
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/clients/{client}/secrets/{secret_id}", tag = "clients", params(("slug" = String, Path, description = "Tenant slug"), ("client" = String, Path), ("secret_id" = Uuid, Path)), responses((status = 200, body = ClientView), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn revoke_secret(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(SecretPath { client, secret_id }): Path<SecretPath>,
) -> AppResult<Json<ClientView>> {
    admin.require(tenant.id, P_WRITE)?;
    let c = resolve_client(&state, tenant.id, &client).await?;
    let client = clients::revoke_secret(&state, tenant.id, admin.actor(), c.id, secret_id).await?;
    Ok(Json(client.into()))
}

#[derive(Serialize, utoipa::ToSchema)]
struct ServiceAccountView {
    #[serde(flatten)]
    view: ClientView,
    service_account: User,
}

/// Create (or return) the user the client acts as under `client_credentials`.
#[utoipa::path(put, path = "/admin/tenants/{slug}/clients/{client}/service-account", tag = "clients", params(("slug" = String, Path, description = "Tenant slug"), ("client" = String, Path)), responses((status = 200, body = ServiceAccountView), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn enable_service_account(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(ClientPath { client }): Path<ClientPath>,
) -> AppResult<Json<ServiceAccountView>> {
    admin.require(tenant.id, P_WRITE)?;
    let c = resolve_client(&state, tenant.id, &client).await?;
    let (client, user) =
        clients::enable_service_account(&state, tenant.id, admin.actor(), c.id).await?;
    Ok(Json(ServiceAccountView {
        view: client.into(),
        service_account: user,
    }))
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/clients/{client}/service-account", tag = "clients", params(("slug" = String, Path, description = "Tenant slug"), ("client" = String, Path)), responses((status = 200, body = ClientView), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn disable_service_account(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(ClientPath { client }): Path<ClientPath>,
) -> AppResult<Json<ClientView>> {
    admin.require(tenant.id, P_WRITE)?;
    let c = resolve_client(&state, tenant.id, &client).await?;
    let client = clients::disable_service_account(&state, tenant.id, admin.actor(), c.id).await?;
    Ok(Json(client.into()))
}

#[derive(Serialize, utoipa::ToSchema)]
struct RegistrationTokenView {
    registration_access_token: String,
    registration_client_uri: String,
}

/// Issue (replacing any previous one) the RFC 7592 registration access token
/// so the client's owner can manage its metadata without admin access.
#[utoipa::path(post, path = "/admin/tenants/{slug}/clients/{client}/registration-token", tag = "clients", params(("slug" = String, Path, description = "Tenant slug"), ("client" = String, Path)), responses((status = 201, body = RegistrationTokenView), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn registration_token(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(ClientPath { client }): Path<ClientPath>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let c = resolve_client(&state, tenant.id, &client).await?;
    let token = clients::issue_registration_token(&state, tenant.id, c.id).await?;
    let body = RegistrationTokenView {
        registration_access_token: token.to_string(),
        registration_client_uri: format!(
            "{}/register/{}",
            match &tenant.settings.custom_domain {
                Some(host) => format!("https://{host}"),
                None => state.config.issuer_for(&tenant.slug),
            },
            c.client_id
        ),
    };
    let mut res = (StatusCode::CREATED, axum::Json(body)).into_response();
    if let Ok(v) = "no-store".parse() {
        res.headers_mut()
            .insert(axum::http::header::CACHE_CONTROL, v);
    }
    Ok(res)
}
