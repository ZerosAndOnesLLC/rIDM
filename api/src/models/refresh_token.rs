use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct RefreshToken {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// All tokens descending from one grant share a family; reuse of a
    /// consumed member revokes the family.
    pub family_id: Uuid,
    pub client_id: String,
    pub user_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    #[serde(skip)]
    pub token_hash: Vec<u8>,
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
    /// Authentication context of the login this family descends from: the
    /// ID token minted on refresh must repeat it (OIDC Core §12.2).
    pub auth_time: Option<DateTime<Utc>>,
    pub amr: Vec<String>,
    pub acr: Option<String>,
    pub expires_at: DateTime<Utc>,
    /// DPoP key thumbprint the token is bound to (public clients, RFC 9449 §5).
    pub dpop_jkt: Option<String>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl RefreshToken {
    pub fn is_usable(&self, now: DateTime<Utc>) -> bool {
        self.consumed_at.is_none() && self.revoked_at.is_none() && self.expires_at > now
    }
}
