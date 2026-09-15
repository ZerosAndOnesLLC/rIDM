use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
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

/// Scopes every tenant has (seeded by migration 0008).
pub const STANDARD_SCOPES: [&str; 6] = [
    "openid",
    "profile",
    "email",
    "phone",
    "address",
    "offline_access",
];

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NewScope {
    pub name: String,
    pub description: Option<String>,
    pub claims: Vec<String>,
    pub resource_server_id: Option<Uuid>,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Consent {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub scopes: Vec<String>,
    pub granted_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
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

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Permission {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub resource_server_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A stored claim mapper row; `config` is the [`crate::models::ClaimMapper`] document.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ClaimMapperRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: Option<Uuid>,
    pub name: String,
    pub config: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
