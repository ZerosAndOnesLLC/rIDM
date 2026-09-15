//! Admin API: messaging (`/admin/tenants/{slug}/messaging`): email and SMS
//! delivery settings with test sends, template overrides per locale with
//! preview, and the outbound delivery log.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
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

pub fn messaging_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(email_get, email_put, email_delete))
        .routes(routes!(email_test))
        .routes(routes!(sms_get, sms_put, sms_delete))
        .routes(routes!(sms_test))
        .routes(routes!(templates))
        .routes(routes!(preview))
        .routes(routes!(template_get, template_put, template_delete))
        .routes(routes!(log))
        .routes(routes!(redeliver))
}

const P_READ: &str = "ridm:messaging:read";
const P_WRITE: &str = "ridm:messaging:write";

#[utoipa::path(get, path = "/admin/tenants/{slug}/messaging/email", tag = "messaging", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = EmailSettings), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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
#[utoipa::path(put, path = "/admin/tenants/{slug}/messaging/email", tag = "messaging", params(("slug" = String, Path, description = "Tenant slug")), request_body = EmailProviderConfig, responses((status = 200, body = EmailSettings), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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

#[utoipa::path(delete, path = "/admin/tenants/{slug}/messaging/email", tag = "messaging", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = EmailSettings), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn email_delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<EmailSettings>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(admin_messaging::clear_email(&state, tenant.id).await?))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct TestSend {
    to: String,
}

#[utoipa::path(post, path = "/admin/tenants/{slug}/messaging/email/test", tag = "messaging", params(("slug" = String, Path, description = "Tenant slug")), request_body = TestSend, responses((status = 200, body = TestSendResult), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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

#[utoipa::path(get, path = "/admin/tenants/{slug}/messaging/sms", tag = "messaging", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = SmsSettings), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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

#[utoipa::path(put, path = "/admin/tenants/{slug}/messaging/sms", tag = "messaging", params(("slug" = String, Path, description = "Tenant slug")), request_body = SmsProviderConfig, responses((status = 200, body = SmsSettings), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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

#[utoipa::path(delete, path = "/admin/tenants/{slug}/messaging/sms", tag = "messaging", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = SmsSettings), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
async fn sms_delete(
    State(state): State<AppState>,
    admin: AdminCtx,
    AdminTenantPath(tenant): AdminTenantPath,
) -> AppResult<Json<SmsSettings>> {
    admin.require(tenant.id, P_WRITE)?;
    Ok(Json(admin_messaging::clear_sms(&state, tenant.id).await?))
}

#[utoipa::path(post, path = "/admin/tenants/{slug}/messaging/sms/test", tag = "messaging", params(("slug" = String, Path, description = "Tenant slug")), request_body = TestSend, responses((status = 200, body = TestSendResult), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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

#[derive(Serialize, utoipa::ToSchema)]
struct Templates {
    /// Events rIDM sends messages for; every one has a built-in English template.
    events: Vec<&'static str>,
    channels: [&'static str; 2],
    /// Tenant overrides by channel, event and locale.
    overrides: Vec<MessageTemplate>,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/messaging/templates", tag = "messaging", params(("slug" = String, Path, description = "Tenant slug")), responses((status = 200, body = Templates), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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

#[utoipa::path(get, path = "/admin/tenants/{slug}/messaging/templates/{channel}/{event}/{locale}", tag = "messaging", params(("slug" = String, Path, description = "Tenant slug"), ("channel" = String, Path), ("event" = String, Path), ("locale" = String, Path)), responses((status = 200, body = TemplateView), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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

#[utoipa::path(put, path = "/admin/tenants/{slug}/messaging/templates/{channel}/{event}/{locale}", tag = "messaging", params(("slug" = String, Path, description = "Tenant slug"), ("channel" = String, Path), ("event" = String, Path), ("locale" = String, Path)), request_body = TemplateBody, responses((status = 200, body = TemplateView), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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

#[utoipa::path(delete, path = "/admin/tenants/{slug}/messaging/templates/{channel}/{event}/{locale}", tag = "messaging", params(("slug" = String, Path, description = "Tenant slug"), ("channel" = String, Path), ("event" = String, Path), ("locale" = String, Path)), responses((status = 204, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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
#[utoipa::path(post, path = "/admin/tenants/{slug}/messaging/templates/preview", tag = "messaging", params(("slug" = String, Path, description = "Tenant slug")), request_body = PreviewRequest, responses((status = 200, body = Preview), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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
#[derive(Serialize, utoipa::ToSchema)]
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

#[derive(Deserialize, Default, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(default)]
struct LogQuery {
    #[param(inline)]
    status: Option<MessageStatus>,
    limit: Option<i64>,
}

#[utoipa::path(get, path = "/admin/tenants/{slug}/messaging/log", tag = "messaging", params(("slug" = String, Path, description = "Tenant slug"), LogQuery), responses((status = 200, body = Vec<LogEntry>), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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
#[utoipa::path(post, path = "/admin/tenants/{slug}/messaging/log/{message}/redeliver", tag = "messaging", params(("slug" = String, Path, description = "Tenant slug"), ("message" = Uuid, Path)), responses((status = 202, description = "No content"), (status = 400, description = "Bad request", body = crate::error::Problem), (status = 401, description = "Missing or invalid admin token", body = crate::error::Problem), (status = 403, description = "Permission missing", body = crate::error::Problem), (status = 404, description = "Not found", body = crate::error::Problem)), security(("bearer" = [])))]
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
