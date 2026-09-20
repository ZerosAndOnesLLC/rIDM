use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::util::patch::double_option;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum OrganizationStatus {
    Active,
    /// Kept for its history, but no one signs in as a member of it.
    Disabled,
}

/// A grouping within one tenant: a customer, business unit or team. Users may
/// belong to several; `users.org_id` names the one they belong to first.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct Organization {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub slug: String,
    pub display_name: String,
    pub description: Option<String>,
    pub status: OrganizationStatus,
    pub attributes: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NewOrganization {
    pub slug: String,
    pub display_name: String,
    pub description: Option<String>,
    pub attributes: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct OrganizationUpdate {
    pub slug: Option<String>,
    pub display_name: Option<String>,
    #[serde(deserialize_with = "double_option")]
    pub description: Option<Option<String>>,
    pub status: Option<OrganizationStatus>,
    pub attributes: Option<serde_json::Value>,
}

impl OrganizationUpdate {
    pub fn is_empty(&self) -> bool {
        self.slug.is_none()
            && self.display_name.is_none()
            && self.description.is_none()
            && self.status.is_none()
            && self.attributes.is_none()
    }
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(default)]
pub struct OrganizationFilter {
    /// Matches the slug or the display name.
    pub search: Option<String>,
    #[param(inline)]
    pub status: Option<OrganizationStatus>,
}

/// An email domain an organization claims. Users with a verified address at a
/// verified `auto_join` domain become members as they sign in.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct OrganizationDomain {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    pub domain: String,
    /// The value to publish as a DNS TXT record to prove control of the domain.
    pub verification: String,
    pub verified_at: Option<DateTime<Utc>>,
    pub auto_join: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NewOrganizationDomain {
    pub domain: String,
    /// Auto-join takes effect once the domain is verified.
    pub auto_join: bool,
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct OrganizationDomainUpdate {
    pub auto_join: Option<bool>,
}
