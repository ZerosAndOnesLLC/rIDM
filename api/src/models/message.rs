use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum MessageChannel {
    Email,
    Sms,
}

impl MessageChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Sms => "sms",
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum MessageStatus {
    Queued,
    Sending,
    Sent,
    Dead,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct MessageTemplate {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub channel: MessageChannel,
    pub event: String,
    pub locale: String,
    pub subject: Option<String>,
    pub body_text: String,
    pub body_html: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct OutboundMessage {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub channel: MessageChannel,
    pub event: String,
    pub recipient: String,
    pub subject: Option<String>,
    pub body_text: String,
    pub body_html: Option<String>,
    pub headers: serde_json::Value,
    pub status: MessageStatus,
    pub attempts: i32,
    pub max_attempts: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub sent_at: Option<DateTime<Utc>>,
}

/// Per-tenant SMTP configuration (encrypted at rest).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    pub from: String,
    /// `starttls` (default), `tls`, or `none`.
    #[serde(default = "default_security")]
    pub security: String,
}

fn default_security() -> String {
    "starttls".into()
}

/// Per-tenant email delivery: SMTP, or an HTTP webhook receiving JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EmailProviderConfig {
    Smtp(SmtpConfig),
    Http {
        url: String,
        #[serde(default)]
        auth_header: Option<String>,
        from: String,
    },
}

/// SMS delivery through any HTTP gateway.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SmsProviderConfig {
    pub url: String,
    #[serde(default)]
    pub auth_header: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
}
