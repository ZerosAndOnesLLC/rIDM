//! Admin API: webhooks (`/admin/tenants/{slug}/webhooks`), their signing
//! secret (shown once on create and rotate), the delivery log, redelivery
//! and test pings.

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::AppResult;
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{DeliveryStatus, NewWebhook, Webhook, WebhookDelivery, WebhookUpdate};
use crate::services::webhooks;
use crate::state::AppState;

pub fn webhooks_router() -> Router<AppState> {
    let base = "/admin/tenants/{slug}/webhooks";
    Router::new()
        .route(base, get(list).post(create))
        .route(
            &format!("{base}/{{webhook}}"),
            get(get_one).patch(update).delete(delete),
        )
        .route(&format!("{base}/{{webhook}}/secret"), post(rotate_secret))
        .route(&format!("{base}/{{webhook}}/test"), post(test))
        .route(&format!("{base}/{{webhook}}/deliveries"), get(deliveries))
        .route(
            &format!("{base}/{{webhook}}/deliveries/{{delivery}}"),
            get(delivery),
        )
        .route(
            &format!("{base}/{{webhook}}/deliveries/{{delivery}}/redeliver"),
            post(redeliver),
        )
}

const P_READ: &str = "ridm:webhooks:read";
const P_WRITE: &str = "ridm:webhooks:write";

#[derive(Deserialize)]
struct WebhookPath {
    webhook: Uuid,
}

fn no_store(mut res: Response) -> Response {
    if let Ok(v) = "no-store".parse() {
        res.headers_mut()
            .insert(axum::http::header::CACHE_CONTROL, v);
    }
    res
}

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

async fn get_one(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(WebhookPath { webhook }): Path<WebhookPath>,
) -> AppResult<Json<Webhook>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(webhooks::get(&state, tenant.id, webhook).await?))
}

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

#[derive(Deserialize, Default)]
#[serde(default)]
struct DeliveriesQuery {
    status: Option<DeliveryStatus>,
    limit: Option<i64>,
}

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
