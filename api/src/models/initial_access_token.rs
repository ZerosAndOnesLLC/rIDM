use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An initial access token for dynamic client registration (RFC 7591 §1.2):
/// what `POST /t/{slug}/register` demands under `dcr.mode =
/// initial_access_token`.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct InitialAccessToken {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub description: Option<String>,
    #[serde(skip)]
    pub token_hash: Vec<u8>,
    /// Registrations it allows in all; `null` for no limit.
    pub max_uses: Option<i32>,
    /// Registrations made with it so far.
    pub uses: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl InitialAccessToken {
    pub fn is_usable(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none()
            && self.expires_at.is_none_or(|t| t > now)
            && self.max_uses.is_none_or(|m| self.uses < m)
    }
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NewInitialAccessToken {
    /// What the token is for (at most 200 characters).
    pub description: Option<String>,
    /// Seconds until the token expires; absent for a token without expiry.
    pub expires_in_secs: Option<u64>,
    /// Registrations it allows; absent for no limit.
    pub max_uses: Option<u32>,
}

/// The token is returned once, here.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CreatedInitialAccessToken {
    #[serde(flatten)]
    pub record: InitialAccessToken,
    pub token: String,
}
