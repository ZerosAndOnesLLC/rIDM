use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct Scope {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub claims: Vec<String>,
    pub resource_server_id: Option<Uuid>,
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Scopes every tenant has (seeded by migration 0008; `features` by the
/// Phase 12.5 migration).
pub const STANDARD_SCOPES: [&str; 7] = [
    "openid",
    "profile",
    "email",
    "phone",
    "address",
    "offline_access",
    "features",
];

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NewScope {
    pub name: String,
    pub description: Option<String>,
    pub claims: Vec<String>,
    pub resource_server_id: Option<Uuid>,
    pub is_default: bool,
}

/// Partial scope update; the name is immutable.
#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ScopeUpdate {
    #[serde(deserialize_with = "crate::util::patch::double_option")]
    pub description: Option<Option<String>>,
    pub claims: Option<Vec<String>>,
    pub is_default: Option<bool>,
    /// Bind to (or, with `null`, unbind from) a resource server.
    #[serde(deserialize_with = "crate::util::patch::double_option")]
    pub resource_server_id: Option<Option<Uuid>>,
}

impl ScopeUpdate {
    pub fn is_empty(&self) -> bool {
        self.description.is_none()
            && self.claims.is_none()
            && self.is_default.is_none()
            && self.resource_server_id.is_none()
    }
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NewResourceServer {
    /// Audience value (`aud`) tokens for this API carry; 1-512 characters.
    pub identifier: String,
    pub name: String,
    pub token_ttl_secs: Option<i32>,
    pub signing_alg: Option<String>,
    pub allow_offline_access: Option<bool>,
}

/// Partial resource server update; the identifier is immutable.
#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceServerUpdate {
    pub name: Option<String>,
    #[serde(deserialize_with = "crate::util::patch::double_option")]
    pub token_ttl_secs: Option<Option<i32>>,
    #[serde(deserialize_with = "crate::util::patch::double_option")]
    pub signing_alg: Option<Option<String>>,
    pub allow_offline_access: Option<bool>,
}

impl ResourceServerUpdate {
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.token_ttl_secs.is_none()
            && self.signing_alg.is_none()
            && self.allow_offline_access.is_none()
    }
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NewPermission {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct Consent {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub scopes: Vec<String>,
    pub granted_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct ResourceServer {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub identifier: String,
    pub name: String,
    pub token_ttl_secs: Option<i32>,
    pub signing_alg: Option<String>,
    pub allow_offline_access: bool,
    /// Seeded by a migration (`urn:ridm:admin`); cannot be changed or deleted.
    pub built_in: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct Permission {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub resource_server_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A stored claim mapper row; `config` is the [`crate::models::ClaimMapper`] document.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct ClaimMapperRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: Option<Uuid>,
    pub name: String,
    pub config: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
