//! Admin API: messaging (`/admin/tenants/{slug}/messaging`): email and SMS
//! delivery settings with test sends, template overrides per locale with
//! preview, and the outbound delivery log.

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::messaging::{self, EVENTS};
use crate::middleware::{AdminCtx, AdminTenantPath, Json};
use crate::models::{
    EmailProviderConfig, MessageChannel, MessageStatus, MessageTemplate, OutboundMessage,
    SmsProviderConfig,
};
use crate::services::messaging::{
    self as admin_messaging, EmailSettings, Preview, PreviewRequest, SmsSettings, TemplateBody,
    TemplateView, TestSendResult,
};
use crate::state::AppState;

pub fn messaging_router() -> Router<AppState> {
    let base = "/admin/tenants/{slug}/messaging";
    Router::new()
        .route(
            &format!("{base}/email"),
            get(email_get).put(email_put).delete(email_delete),
        )
        .route(&format!("{base}/email/test"), post(email_test))
        .route(
            &format!("{base}/sms"),
            get(sms_get).put(sms_put).delete(sms_delete),
        )
        .route(&format!("{base}/sms/test"), post(sms_test))
        .route(&format!("{base}/templates"), get(templates))
        .route(&format!("{base}/templates/preview"), post(preview))
        .route(
            &format!("{base}/templates/{{channel}}/{{event}}/{{locale}}"),
            get(template_get).put(template_put).delete(template_delete),
        )
        .route(&format!("{base}/log"), get(log))
        .route(
            &format!("{base}/log/{{message}}/redeliver"),
            post(redeliver),
        )
}

const P_READ: &str = "ridm:messaging:read";
const P_WRITE: &str = "ridm:messaging:write";

async fn email_get(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<EmailSettings>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(
        admin_messaging::email_settings(&state, tenant.id).await?,
    ))
}

/// `{type: "smtp", host, port, username?, password?, from, security?}` or
/// `{type: "http", url, auth_header?, from}`; an omitted secret keeps the stored one.
async fn email_put(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(cfg): Json<EmailProviderConfig>,
) -> AppResult<Json<EmailSettings>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        admin_messaging::set_email(&state, tenant.id, cfg).await?,
    ))
}

async fn email_delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<EmailSettings>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(admin_messaging::clear_email(&state, tenant.id).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestSend {
    to: String,
}

async fn email_test(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<TestSend>,
) -> AppResult<Json<TestSendResult>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        admin_messaging::test_email(&state, &tenant, &body.to).await?,
    ))
}

async fn sms_get(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<SmsSettings>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(
        admin_messaging::sms_settings(&state, tenant.id).await?,
    ))
}

async fn sms_put(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(cfg): Json<SmsProviderConfig>,
) -> AppResult<Json<SmsSettings>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        admin_messaging::set_sms(&state, tenant.id, cfg).await?,
    ))
}

async fn sms_delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<SmsSettings>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(admin_messaging::clear_sms(&state, tenant.id).await?))
}

async fn sms_test(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(body): Json<TestSend>,
) -> AppResult<Json<TestSendResult>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        admin_messaging::test_sms(&state, &tenant, &body.to).await?,
    ))
}

#[derive(Serialize)]
struct Templates {
    /// Events rIDM sends messages for; every one has a built-in English template.
    events: Vec<&'static str>,
    channels: [&'static str; 2],
    /// Tenant overrides by channel, event and locale.
    overrides: Vec<MessageTemplate>,
}

async fn templates(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<Templates>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(Templates {
        events: EVENTS.to_vec(),
        channels: ["email", "sms"],
        overrides: admin_messaging::list_overrides(&state, tenant.id).await?,
    }))
}

#[derive(Deserialize)]
struct TemplatePath {
    channel: String,
    event: String,
    locale: String,
}

fn channel(s: &str) -> AppResult<MessageChannel> {
    match s {
        "email" => Ok(MessageChannel::Email),
        "sms" => Ok(MessageChannel::Sms),
        other => Err(AppError::BadRequest(format!(
            "unknown channel `{other}` (email or sms)"
        ))),
    }
}

async fn template_get(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(p): Path<TemplatePath>,
) -> AppResult<Json<TemplateView>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(
        admin_messaging::get_template(&state, tenant.id, channel(&p.channel)?, &p.event, &p.locale)
            .await?,
    ))
}

async fn template_put(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(p): Path<TemplatePath>,
    Json(body): Json<TemplateBody>,
) -> AppResult<Json<TemplateView>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(
        admin_messaging::put_template(
            &state,
            tenant.id,
            channel(&p.channel)?,
            &p.event,
            &p.locale,
            body,
        )
        .await?,
    ))
}

async fn template_delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(p): Path<TemplatePath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    admin_messaging::delete_template(&state, tenant.id, channel(&p.channel)?, &p.event, &p.locale)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Render a stored template or an unsaved draft with sample variables.
async fn preview(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Json(req): Json<PreviewRequest>,
) -> AppResult<Json<Preview>> {
    admin.require(tenant.id, P_READ)?;
    Ok(Json(admin_messaging::preview(&state, &tenant, req).await?))
}

/// A delivery log entry without the message body (bodies carry links and
/// codes that must not be readable after the fact).
#[derive(Serialize)]
struct LogEntry {
    id: Uuid,
    channel: MessageChannel,
    event: String,
    recipient: String,
    subject: Option<String>,
    status: MessageStatus,
    attempts: i32,
    max_attempts: i32,
    next_attempt_at: DateTime<Utc>,
    last_error: Option<String>,
    created_at: DateTime<Utc>,
    sent_at: Option<DateTime<Utc>>,
}

impl From<OutboundMessage> for LogEntry {
    fn from(m: OutboundMessage) -> Self {
        Self {
            id: m.id,
            channel: m.channel,
            event: m.event,
            recipient: m.recipient,
            subject: m.subject,
            status: m.status,
            attempts: m.attempts,
            max_attempts: m.max_attempts,
            next_attempt_at: m.next_attempt_at,
            last_error: m.last_error,
            created_at: m.created_at,
            sent_at: m.sent_at,
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LogQuery {
    status: Option<MessageStatus>,
    limit: Option<i64>,
}

async fn log(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Query(q): Query<LogQuery>,
) -> AppResult<Json<Vec<LogEntry>>> {
    admin.require(tenant.id, P_READ)?;
    let rows = messaging::recent(&state, tenant.id, q.status, q.limit.unwrap_or(100)).await?;
    Ok(Json(rows.into_iter().map(LogEntry::from).collect()))
}

#[derive(Deserialize)]
struct MessagePath {
    message: Uuid,
}

/// Put a dead message back in the queue.
async fn redeliver(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
    Path(MessagePath { message }): Path<MessagePath>,
) -> AppResult<StatusCode> {
    admin.require(tenant.id, P_WRITE)?;
    messaging::redeliver(&state, tenant.id, message).await?;
    Ok(StatusCode::ACCEPTED)
}
