use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct Webhook {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub url: String,
    #[serde(skip)]
    pub secret_enc: Vec<u8>,
    #[serde(skip)]
    pub key_version: i32,
    /// Event names: exact (`user.created`), prefix (`user.*`) or `*`.
    pub events: Vec<String>,
    pub enabled: bool,
    /// Static headers sent with every delivery.
    pub headers: serde_json::Value,
    pub max_attempts: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Webhook {
    /// Does this webhook want `event_name`?
    pub fn wants(&self, event_name: &str) -> bool {
        self.events.iter().any(|pattern| match pattern.as_str() {
            "*" => true,
            p => match p.strip_suffix(".*").or_else(|| p.strip_suffix('*')) {
                Some(prefix) => event_name.starts_with(prefix),
                None => p == event_name,
            },
        })
    }
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NewWebhook {
    pub name: String,
    pub url: String,
    pub events: Vec<String>,
    pub enabled: Option<bool>,
    pub headers: Option<serde_json::Value>,
    pub max_attempts: Option<i32>,
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct WebhookUpdate {
    pub name: Option<String>,
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub headers: Option<serde_json::Value>,
    pub max_attempts: Option<i32>,
}

impl WebhookUpdate {
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.url.is_none()
            && self.events.is_none()
            && self.enabled.is_none()
            && self.headers.is_none()
            && self.max_attempts.is_none()
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum DeliveryStatus {
    Pending,
    Sending,
    Delivered,
    Failed,
    Dead,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct WebhookDelivery {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub webhook_id: Uuid,
    pub event_id: Uuid,
    pub event_name: String,
    /// The event document as sent.
    pub payload: serde_json::Value,
    pub status: DeliveryStatus,
    pub attempts: i32,
    pub max_attempts: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub last_status: Option<i32>,
    pub last_error: Option<String>,
    /// First bytes of the last response body, for diagnostics.
    pub response_snippet: Option<String>,
    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
}
