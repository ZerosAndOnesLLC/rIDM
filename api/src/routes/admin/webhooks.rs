//! Admin API: webhooks (`/admin/tenants/{slug}/webhooks`), their signing
//! secret (shown once on create and rotate), the delivery log, redelivery
//! and test pings.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::security_headers::no_store;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{DeliveryStatus, NewWebhook, Webhook, WebhookDelivery, WebhookUpdate};
use crate::services::webhooks::{self, WebhookWithSecret};
use crate::state::AppState;

pub fn webhooks_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(get_one, update, delete))
        .routes(routes!(rotate_secret))
        .routes(routes!(test))
        .routes(routes!(deliveries))
        .routes(routes!(delivery))
        .routes(routes!(redeliver))
        .routes(routes!(redeliver_dead))
}

/// How many dead deliveries went back on the queue.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct Requeued {
    pub requeued: u64,
}

const P_READ: &str = "ridm:webhooks:read";
const P_WRITE: &str = "ridm:webhooks:write";

#[derive(Deserialize)]
struct WebhookPath {
    webhook: Uuid,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/webhooks", tag = "webhooks", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Vec<Webhook>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn list(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<Vec<Webhook>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(webhooks::list(&state, tenant.id).await?))
}

/// `{name, url, events, enabled?, headers?, max_attempts?}`; the signing
/// `secret` is in the response and nowhere else.
#[utoipa::path(post, path = "/admin/tenants/{slug}/webhooks", tag = "webhooks", params(("slug" = String, Path, description = "Tenant slug")), request_body = NewWebhook, responses((status = 201, body = WebhookWithSecret), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn create(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<NewWebhook>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let w = webhooks::create(&state, tenant.id, admin.actor(), body).await?;
    Ok(no_store(
        (StatusCode::CREATED, axum::Json(w)).into_response(),
    ))
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/webhooks/{webhook}", tag = "webhooks", params(("slug" = String, Path, description = "Tenant slug"), ("webhook" = Uuid, Path)), responses((status = 200, body = Webhook), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(WebhookPath { webhook }): Path<WebhookPath>,
) -> AppResult<Json<Webhook>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(webhooks::get(&state, tenant.id, webhook).await?))
}

#[utoipa::path(patch, path = "/admin/tenants/{slug}/webhooks/{webhook}", tag = "webhooks", params(("slug" = String, Path, description = "Tenant slug"), ("webhook" = Uuid, Path)), request_body = WebhookUpdate, responses((status = 200, body = Webhook), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn update(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(WebhookPath { webhook }): Path<WebhookPath>,
    Json(body): Json<WebhookUpdate>,
) -> AppResult<Json<Webhook>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        webhooks::update(&state, tenant.id, admin.actor(), webhook, body).await?,
    ))
}

#[utoipa::path(delete, path = "/admin/tenants/{slug}/webhooks/{webhook}", tag = "webhooks", params(("slug" = String, Path, description = "Tenant slug"), ("webhook" = Uuid, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(WebhookPath { webhook }): Path<WebhookPath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    webhooks::delete(&state, tenant.id, admin.actor(), webhook).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/admin/tenants/{slug}/webhooks/{webhook}/secret", tag = "webhooks", params(("slug" = String, Path, description = "Tenant slug"), ("webhook" = Uuid, Path)), responses((status = 201, body = WebhookWithSecret), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn rotate_secret(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(WebhookPath { webhook }): Path<WebhookPath>,
) -> AppResult<Response> {
    admin.require(tenant.id, P_WRITE)?;
    let w = webhooks::rotate_secret(&state, tenant.id, admin.actor(), webhook).await?;
    Ok(no_store(
        (StatusCode::CREATED, axum::Json(w)).into_response(),
    ))
}

/// Deliver a `webhook.test` event now and report the attempt.
#[utoipa::path(post, path = "/admin/tenants/{slug}/webhooks/{webhook}/test", tag = "webhooks", params(("slug" = String, Path, description = "Tenant slug"), ("webhook" = Uuid, Path)), responses((status = 200, body = WebhookDelivery), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn test(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(WebhookPath { webhook }): Path<WebhookPath>,
) -> AppResult<Json<WebhookDelivery>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        webhooks::test(&state, tenant.id, admin.actor(), webhook).await?,
    ))
}

#[derive(Deserialize, Default, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(default)]
struct DeliveriesQuery {
    #[param(inline)]
    status: Option<DeliveryStatus>,
    limit: Option<i64>,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/webhooks/{webhook}/deliveries", tag = "webhooks", params(("slug" = String, Path, description = "Tenant slug"), ("webhook" = Uuid, Path), DeliveriesQuery), responses((status = 200, body = Vec<WebhookDelivery>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn deliveries(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(WebhookPath { webhook }): Path<WebhookPath>,
    Query(q): Query<DeliveriesQuery>,
) -> AppResult<Json<Vec<WebhookDelivery>>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(
        webhooks::list_deliveries(&state, tenant.id, webhook, q.status, q.limit.unwrap_or(100))
            .await?,
    ))
}

#[derive(Deserialize)]
struct DeliveryPath {
    webhook: Uuid,
    delivery: Uuid,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/webhooks/{webhook}/deliveries/{delivery}", tag = "webhooks", params(("slug" = String, Path, description = "Tenant slug"), ("webhook" = Uuid, Path), ("delivery" = Uuid, Path)), responses((status = 200, body = WebhookDelivery), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn delivery(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(DeliveryPath { webhook, delivery }): Path<DeliveryPath>,
) -> AppResult<Json<WebhookDelivery>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(
        webhooks::get_delivery(&state, tenant.id, webhook, delivery).await?,
    ))
}

/// Requeue and attempt at once; the returned delivery shows the outcome.
#[utoipa::path(post, path = "/admin/tenants/{slug}/webhooks/{webhook}/deliveries/{delivery}/redeliver", tag = "webhooks", params(("slug" = String, Path, description = "Tenant slug"), ("webhook" = Uuid, Path), ("delivery" = Uuid, Path)), responses((status = 200, body = WebhookDelivery), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn redeliver(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(DeliveryPath { webhook, delivery }): Path<DeliveryPath>,
) -> AppResult<Json<WebhookDelivery>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        webhooks::redeliver(&state, tenant.id, webhook, delivery).await?,
    ))
}

#[utoipa::path(post, path = "/admin/tenants/{slug}/webhooks/{webhook}/deliveries/redeliver-dead", tag = "webhooks", params(("slug" = String, Path, description = "Tenant slug"), ("webhook" = Uuid, Path)), responses((status = 200, body = Requeued), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn redeliver_dead(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(WebhookPath { webhook }): Path<WebhookPath>,
) -> AppResult<Json<Requeued>> {
    admin.require(tenant.id, P_WRITE)?;
    let requeued = webhooks::redeliver_dead(&state, tenant.id, webhook).await?;
    Ok(Json(Requeued { requeued }))
}
