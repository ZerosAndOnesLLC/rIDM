use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum IpRuleAction {
    Allow,
    Deny,
}

/// An allow or deny rule for a CIDR, for the whole tenant or one client.
/// Enforcement is Phase 9.2; this is the configuration.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct IpRule {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: Option<Uuid>,
    pub action: IpRuleAction,
    /// Normalized network (`203.0.113.0/24`, `2001:db8::/32`).
    pub cidr: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NewIpRule {
    pub client_id: Option<Uuid>,
    pub action: Option<IpRuleAction>,
    /// A network in CIDR notation, or a single address.
    pub cidr: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct IpRuleUpdate {
    pub action: Option<IpRuleAction>,
    pub cidr: Option<String>,
    #[serde(deserialize_with = "crate::util::patch::double_option")]
    pub description: Option<Option<String>>,
}
