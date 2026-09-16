use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A bearer token a provisioning system uses against `/scim/v2/{tenant}`.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct ScimToken {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    #[serde(skip)]
    pub token_hash: Vec<u8>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl ScimToken {
    pub fn is_usable(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|t| t > now)
    }
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NewScimToken {
    pub name: String,
    /// Days until the token expires; absent for a token without expiry.
    pub expires_in_days: Option<u32>,
}

/// The token is returned once, here.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CreatedScimToken {
    #[serde(flatten)]
    pub record: ScimToken,
    pub token: String,
}

/// The tenant's tokens and where a provisioning system should point.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ScimTokens {
    /// `{PUBLIC_URL}/scim/v2/{slug}`.
    pub base_url: String,
    pub tokens: Vec<ScimToken>,
}
