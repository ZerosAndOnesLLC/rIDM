use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Invitation {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub roles: Vec<Uuid>,
    pub groups: Vec<Uuid>,
    pub org_id: Option<Uuid>,
    #[serde(skip)]
    pub token_hash: Vec<u8>,
    pub invited_by: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl Invitation {
    pub fn is_open(&self, now: DateTime<Utc>) -> bool {
        self.accepted_at.is_none() && self.revoked_at.is_none() && self.expires_at > now
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NewInvitation {
    pub email: String,
    pub roles: Vec<Uuid>,
    pub groups: Vec<Uuid>,
    pub org_id: Option<Uuid>,
    /// Days until expiry (default 7).
    pub expires_days: Option<u32>,
}
