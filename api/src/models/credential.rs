use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A user's non-password credential (MFA factors, passkeys, recovery codes),
/// as listed to administrators and the user: the encrypted material stays
/// in the row and is never part of this view.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct Credential {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    /// `password`, `totp`, `webauthn`, `recovery_code`, `email_otp` or `sms_otp`.
    #[sqlx(rename = "type")]
    pub kind: String,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}
