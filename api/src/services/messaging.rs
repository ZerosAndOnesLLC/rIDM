//! Messaging administration: per-tenant email and SMS delivery settings
//! (stored encrypted, secrets redacted on read), test sends through the
//! configured sender, template overrides per locale, and previews.

use ridm_core::providers::{EmailAddress, EmailMessage, SmsMessage};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::messaging::{self, Template};
use crate::models::{
    EmailProviderConfig, MessageChannel, MessageTemplate, ProviderKind, SmsProviderConfig,
    SmtpConfig, Tenant,
};
use crate::repos;
use crate::services::{provider_settings, users};
use crate::state::AppState;

// --- email -------------------------------------------------------------------

/// Where email for the tenant goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EmailSource {
    /// The tenant's own configuration.
    Tenant,
    /// The server-wide SMTP defaults.
    ServerDefault,
    /// Nothing configured: email is not sent.
    None,
}

/// Email settings as shown to administrators (no password or auth header).
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EmailSettingsView {
    Smtp {
        host: String,
        port: u16,
        username: Option<String>,
        password_set: bool,
        from: String,
        security: String,
    },
    Http {
        url: String,
        auth_header_set: bool,
        from: String,
    },
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct EmailSettings {
    pub source: EmailSource,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub settings: Option<EmailSettingsView>,
}

fn email_view(cfg: &EmailProviderConfig) -> EmailSettingsView {
    match cfg {
        EmailProviderConfig::Smtp(s) => EmailSettingsView::Smtp {
            host: s.host.clone(),
            port: s.port,
            username: s.username.clone(),
            password_set: s.password.as_deref().is_some_and(|p| !p.is_empty()),
            from: s.from.clone(),
            security: s.security.clone(),
        },
        EmailProviderConfig::Http {
            url,
            auth_header,
            from,
        } => EmailSettingsView::Http {
            url: url.clone(),
            auth_header_set: auth_header.as_deref().is_some_and(|h| !h.is_empty()),
            from: from.clone(),
        },
    }
}

pub async fn email_settings(state: &AppState, tenant_id: Uuid) -> AppResult<EmailSettings> {
    if let Some(cfg) =
        provider_settings::get::<EmailProviderConfig>(state, tenant_id, ProviderKind::Smtp).await?
    {
        return Ok(EmailSettings {
            source: EmailSource::Tenant,
            settings: Some(email_view(&cfg)),
        });
    }
    Ok(match &state.config.smtp {
        Some(d) => EmailSettings {
            source: EmailSource::ServerDefault,
            settings: Some(EmailSettingsView::Smtp {
                host: d.host.clone(),
                port: d.port,
                username: d.username.clone(),
                password_set: d.password.is_some(),
                from: d.from.clone(),
                security: d.security.clone(),
            }),
        },
        None => EmailSettings {
            source: EmailSource::None,
            settings: None,
        },
    })
}

fn require_url(field: &str, raw: &str, https_only: bool) -> AppResult<()> {
    let u = url::Url::parse(raw)
        .map_err(|_| AppError::BadRequest(format!("{field}: `{raw}` is not a valid URL")))?;
    match u.scheme() {
        "https" => Ok(()),
        "http" if !https_only => Ok(()),
        "http" => {
            let host = u.host_str().unwrap_or_default();
            if matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
                Ok(())
            } else {
                Err(AppError::BadRequest(format!(
                    "{field}: plain http is only allowed for loopback addresses"
                )))
            }
        }
        other => Err(AppError::BadRequest(format!(
            "{field}: scheme `{other}` is not allowed"
        ))),
    }
}

/// Store the tenant's email configuration. For SMTP, an absent or empty
/// `password` keeps the password already stored (so the UI never has to
/// echo it back).
pub async fn set_email(
    state: &AppState,
    tenant_id: Uuid,
    mut cfg: EmailProviderConfig,
) -> AppResult<EmailSettings> {
    match &mut cfg {
        EmailProviderConfig::Smtp(s) => {
            if s.host.trim().is_empty() || s.port == 0 {
                return Err(AppError::BadRequest("host and port are required".into()));
            }
            if s.from.trim().is_empty() {
                return Err(AppError::BadRequest("from is required".into()));
            }
            if !matches!(s.security.as_str(), "starttls" | "tls" | "none") {
                return Err(AppError::BadRequest(
                    "security must be starttls, tls or none".into(),
                ));
            }
            if s.password.as_deref().is_none_or(str::is_empty)
                && let Some(current) = provider_settings::get::<EmailProviderConfig>(
                    state,
                    tenant_id,
                    ProviderKind::Smtp,
                )
                .await?
                && let EmailProviderConfig::Smtp(prev) = &*current
            {
                s.password = prev.password.clone();
            }
            // The sender constructor validates `security`, the address and
            // the host (no private IP literal; names are vetted at send time).
            messaging::SmtpEmailSender::for_tenant(&SmtpConfig {
                password: None,
                ..s.clone()
            })?;
        }
        EmailProviderConfig::Http { url, from, .. } => {
            require_url("url", url, true)?;
            if from.trim().is_empty() {
                return Err(AppError::BadRequest("from is required".into()));
            }
        }
    }
    provider_settings::set(state, tenant_id, ProviderKind::Smtp, &cfg).await?;
    email_settings(state, tenant_id).await
}

pub async fn clear_email(state: &AppState, tenant_id: Uuid) -> AppResult<EmailSettings> {
    provider_settings::clear(state, tenant_id, ProviderKind::Smtp).await?;
    email_settings(state, tenant_id).await
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TestSendResult {
    /// Backend that took the message (`smtp`, `http`, `mock`).
    pub sender: &'static str,
    pub to: String,
}

/// Send a test email straight through the configured sender (no queue), so
/// misconfiguration surfaces as an error in the response.
pub async fn test_email(state: &AppState, tenant: &Tenant, to: &str) -> AppResult<TestSendResult> {
    let to = users::normalize_email(to)?;
    let sender = state
        .senders
        .email(state, tenant.id)
        .await?
        .ok_or_else(|| AppError::BadRequest("no email delivery is configured".into()))?;
    let msg = EmailMessage {
        to: vec![EmailAddress {
            email: to.clone(),
            name: None,
        }],
        from: None,
        reply_to: None,
        subject: format!("Test message from {}", tenant.display_name),
        text: format!(
            "This is a test message from rIDM for tenant {} ({}). If you can read this, email delivery works.",
            tenant.display_name, tenant.slug
        ),
        html: None,
        headers: vec![],
    };
    sender
        .send(&msg)
        .await
        .map_err(|e| AppError::Unavailable(format!("test send failed: {e}")))?;
    Ok(TestSendResult {
        sender: sender.name(),
        to,
    })
}

// --- sms ----------------------------------------------------------------------

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SmsSettings {
    pub configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub auth_header_set: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

pub async fn sms_settings(state: &AppState, tenant_id: Uuid) -> AppResult<SmsSettings> {
    Ok(
        match provider_settings::get::<SmsProviderConfig>(state, tenant_id, ProviderKind::Sms)
            .await?
        {
            Some(cfg) => SmsSettings {
                configured: true,
                url: Some(cfg.url.clone()),
                auth_header_set: cfg.auth_header.as_deref().is_some_and(|h| !h.is_empty()),
                from: cfg.from.clone(),
            },
            None => SmsSettings {
                configured: false,
                url: None,
                auth_header_set: false,
                from: None,
            },
        },
    )
}

/// Store the SMS gateway; an absent or empty `auth_header` keeps the stored one.
pub async fn set_sms(
    state: &AppState,
    tenant_id: Uuid,
    mut cfg: SmsProviderConfig,
) -> AppResult<SmsSettings> {
    require_url("url", &cfg.url, true)?;
    if cfg.auth_header.as_deref().is_none_or(str::is_empty)
        && let Some(current) =
            provider_settings::get::<SmsProviderConfig>(state, tenant_id, ProviderKind::Sms).await?
    {
        cfg.auth_header = current.auth_header.clone();
    }
    provider_settings::set(state, tenant_id, ProviderKind::Sms, &cfg).await?;
    sms_settings(state, tenant_id).await
}

pub async fn clear_sms(state: &AppState, tenant_id: Uuid) -> AppResult<SmsSettings> {
    provider_settings::clear(state, tenant_id, ProviderKind::Sms).await?;
    sms_settings(state, tenant_id).await
}

pub async fn test_sms(state: &AppState, tenant: &Tenant, to: &str) -> AppResult<TestSendResult> {
    let to = users::normalize_phone(to)?;
    let sender = state
        .senders
        .sms(state, tenant.id)
        .await?
        .ok_or_else(|| AppError::BadRequest("no SMS delivery is configured".into()))?;
    sender
        .send(&SmsMessage {
            to: to.clone(),
            body: format!(
                "Test message from {}: SMS delivery works.",
                tenant.display_name
            ),
        })
        .await
        .map_err(|e| AppError::Unavailable(format!("test send failed: {e}")))?;
    Ok(TestSendResult {
        sender: sender.name(),
        to,
    })
}

// --- templates -----------------------------------------------------------------

pub fn validate_event(event: &str) -> AppResult<()> {
    if messaging::EVENTS.contains(&event) {
        Ok(())
    } else {
        Err(AppError::BadRequest(format!(
            "unknown event `{event}` (one of {})",
            messaging::EVENTS.join(", ")
        )))
    }
}

pub fn validate_locale(locale: &str) -> AppResult<String> {
    let l = locale.trim();
    let ok = !l.is_empty()
        && l.len() <= 16
        && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !l.starts_with('-')
        && !l.ends_with('-');
    if ok {
        Ok(l.to_string())
    } else {
        Err(AppError::BadRequest(
            "locale must be a BCP 47 tag such as `en` or `pt-BR`".into(),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TemplateSource {
    /// Stored by an administrator for this exact locale.
    Override,
    /// rIDM's built-in English default.
    Builtin,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TemplateView {
    pub source: TemplateSource,
    pub channel: MessageChannel,
    pub event: String,
    pub locale: String,
    pub subject: Option<String>,
    pub body_text: String,
    pub body_html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn list_overrides(state: &AppState, tenant_id: Uuid) -> AppResult<Vec<MessageTemplate>> {
    let mut tx = db::read_tx(&state.db, tenant_id).await?;
    let rows = repos::messages::list_templates(&mut *tx, tenant_id).await?;
    tx.commit().await?;
    Ok(rows)
}

/// The template an administrator would edit for this exact locale: the
/// stored override, or the built-in default as a starting point.
pub async fn get_template(
    state: &AppState,
    tenant_id: Uuid,
    channel: MessageChannel,
    event: &str,
    locale: &str,
) -> AppResult<TemplateView> {
    validate_event(event)?;
    let locale = validate_locale(locale)?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let stored =
        repos::messages::find_template(&mut *tx, tenant_id, channel, event, &locale).await?;
    tx.commit().await?;
    if let Some(t) = stored {
        return Ok(TemplateView {
            source: TemplateSource::Override,
            channel,
            event: event.to_string(),
            locale,
            subject: t.subject,
            body_text: t.body_text,
            body_html: t.body_html,
            updated_at: Some(t.updated_at),
        });
    }
    let b = messaging::builtin_template(channel, event).ok_or_else(|| {
        AppError::BadRequest(format!("no {} template for `{event}`", channel.as_str()))
    })?;
    Ok(TemplateView {
        source: TemplateSource::Builtin,
        channel,
        event: event.to_string(),
        locale,
        subject: b.subject,
        body_text: b.body_text,
        body_html: b.body_html,
        updated_at: None,
    })
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TemplateBody {
    pub subject: Option<String>,
    pub body_text: String,
    pub body_html: Option<String>,
}

fn to_template(channel: MessageChannel, body: &TemplateBody) -> AppResult<Template> {
    if body.body_text.trim().is_empty() {
        return Err(AppError::BadRequest("body_text is required".into()));
    }
    match channel {
        MessageChannel::Email => {
            if body.subject.as_deref().is_none_or(|s| s.trim().is_empty()) {
                return Err(AppError::BadRequest(
                    "email templates need a subject".into(),
                ));
            }
        }
        MessageChannel::Sms => {
            if body.subject.is_some() || body.body_html.is_some() {
                return Err(AppError::BadRequest(
                    "SMS templates have only body_text".into(),
                ));
            }
        }
    }
    let t = Template {
        subject: body.subject.clone(),
        body_text: body.body_text.clone(),
        body_html: body.body_html.clone(),
    };
    messaging::validate(&t)?;
    Ok(t)
}

pub async fn put_template(
    state: &AppState,
    tenant_id: Uuid,
    channel: MessageChannel,
    event: &str,
    locale: &str,
    body: TemplateBody,
) -> AppResult<TemplateView> {
    validate_event(event)?;
    let locale = validate_locale(locale)?;
    let t = to_template(channel, &body)?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let row = repos::messages::upsert_template(
        &mut *tx,
        tenant_id,
        channel,
        event,
        &locale,
        t.subject.as_deref(),
        &t.body_text,
        t.body_html.as_deref(),
    )
    .await?;
    tx.commit().await?;
    Ok(TemplateView {
        source: TemplateSource::Override,
        channel,
        event: event.to_string(),
        locale,
        subject: row.subject,
        body_text: row.body_text,
        body_html: row.body_html,
        updated_at: Some(row.updated_at),
    })
}

/// Remove the override; the locale falls back through the chain to the built-in.
pub async fn delete_template(
    state: &AppState,
    tenant_id: Uuid,
    channel: MessageChannel,
    event: &str,
    locale: &str,
) -> AppResult<()> {
    let locale = validate_locale(locale)?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let row = repos::messages::find_template(&mut *tx, tenant_id, channel, event, &locale)
        .await?
        .ok_or(AppError::NotFound("template override"))?;
    repos::messages::delete_template(&mut *tx, tenant_id, row.id).await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PreviewRequest {
    pub channel: Option<MessageChannel>,
    pub event: String,
    /// Locale to resolve when no draft is given (default: tenant default).
    pub locale: Option<String>,
    /// An unsaved draft to render instead of the stored/built-in template.
    pub draft: Option<TemplateBody>,
    /// Extra variables merged over the sample data.
    pub vars: Option<Value>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Preview {
    pub subject: Option<String>,
    pub body_text: String,
    pub body_html: Option<String>,
    /// The variables the preview was rendered with.
    pub vars: Value,
}

pub async fn preview(state: &AppState, tenant: &Tenant, req: PreviewRequest) -> AppResult<Preview> {
    validate_event(&req.event)?;
    let channel = req.channel.unwrap_or(MessageChannel::Email);
    let template = match &req.draft {
        Some(d) => to_template(channel, d)?,
        None => {
            let locale = req
                .locale
                .as_deref()
                .unwrap_or(&tenant.settings.locale.default);
            messaging::resolve(
                state,
                tenant.id,
                &tenant.settings.locale.default,
                channel,
                &req.event,
                locale,
            )
            .await?
        }
    };
    // The event's real variables (`messaging::vars`), with sample values.
    let mut vars = messaging::vars::sample(&req.event, tenant)
        .ok_or_else(|| AppError::BadRequest(format!("unknown event `{}`", req.event)))?;
    if let Some(extra) = req.vars {
        if !extra.is_object() {
            return Err(AppError::BadRequest("vars must be an object".into()));
        }
        crate::util::patch::merge_patch(&mut vars, &extra);
    }
    let r = messaging::render(&template, &vars)?;
    Ok(Preview {
        subject: r.subject,
        body_text: r.body_text,
        body_html: r.body_html,
        vars,
    })
}
