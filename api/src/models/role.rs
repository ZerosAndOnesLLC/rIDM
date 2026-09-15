use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::util::patch::double_option;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct Role {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// Client-scoped role when set; realm-wide otherwise.
    pub client_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NewRole {
    pub name: String,
    pub client_id: Option<Uuid>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RoleUpdate {
    pub name: Option<String>,
    #[serde(deserialize_with = "double_option")]
    pub description: Option<Option<String>>,
}

impl RoleUpdate {
    pub fn is_empty(&self) -> bool {
        self.name.is_none() && self.description.is_none()
    }
}

/// Who a role is assigned to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Principal {
    User { id: Uuid },
    Group { id: Uuid },
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RoleAssignment {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub role_id: Uuid,
    pub user_id: Option<Uuid>,
    pub group_id: Option<Uuid>,
    pub org_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}
