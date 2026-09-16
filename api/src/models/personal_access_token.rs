use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The scope that admits a personal access token to the self-service
/// account API; every other scope is an admin permission name.
pub const PAT_SCOPE_ACCOUNT: &str = "account";

/// A long-lived bearer token a user minted for scripts and integrations.
/// The token itself is shown once; only its hash is kept.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct PersonalAccessToken {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    #[serde(skip)]
    pub token_hash: Vec<u8>,
    /// `account` and/or admin permission names, each held by the user when
    /// the token was made; at use they are narrowed to what the user still holds.
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl PersonalAccessToken {
    pub fn is_usable(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|e| e > now)
    }
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NewPersonalAccessToken {
    pub name: String,
    /// `account` for the self-service API, and admin permission names.
    pub scopes: Vec<String>,
    /// Days until it expires; none means the tenant's maximum (or never
    /// when the tenant sets no maximum).
    pub expires_in_days: Option<u32>,
}

/// A freshly minted token: the secret is only ever returned here.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CreatedPersonalAccessToken {
    /// The bearer token, shown once.
    pub token: String,
    #[serde(flatten)]
    pub record: PersonalAccessToken,
}
