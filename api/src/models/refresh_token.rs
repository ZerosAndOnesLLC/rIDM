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
    /// Organization the sign-in this family descends from acted in; every
    /// token minted from it repeats it as `org_id`.
    pub org_id: Option<Uuid>,
    /// The administrator behind the sign-in this family descends from, when
    /// it was an impersonation: every token minted from it repeats this
    /// `act` claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<serde_json::Value>,
    pub expires_at: DateTime<Utc>,
    /// DPoP key thumbprint the token is bound to (public clients, RFC 9449 §5).
    pub dpop_jkt: Option<String>,
    /// Client certificate thumbprint the token is bound to (public clients,
    /// RFC 8705 §4).
    pub mtls_x5t: Option<String>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl RefreshToken {
    /// Granted `offline_access`: the family may outlive the SSO session it
    /// was issued in (OIDC Core §11). Without it the family ends with the
    /// session.
    pub fn is_offline(&self) -> bool {
        self.scopes.iter().any(|s| s == "offline_access")
    }

    pub fn is_usable(&self, now: DateTime<Utc>) -> bool {
        self.consumed_at.is_none() && self.revoked_at.is_none() && self.expires_at > now
    }
}
