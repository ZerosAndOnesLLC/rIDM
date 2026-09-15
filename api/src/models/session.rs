use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Postgres mirror row of a browser session.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SessionRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub auth_time: DateTime<Utc>,
    pub amr: Vec<String>,
    pub acr: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub device_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl SessionRow {
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now && self.idle_expires_at > now
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TrustedDevice {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    #[serde(skip)]
    pub device_hash: Vec<u8>,
    pub name: Option<String>,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl TrustedDevice {
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}
