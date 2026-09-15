use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::util::patch::double_option;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Group {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub attributes: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NewGroup {
    pub name: String,
    pub parent_id: Option<Uuid>,
    pub description: Option<String>,
    pub attributes: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GroupUpdate {
    pub name: Option<String>,
    #[serde(deserialize_with = "double_option")]
    pub parent_id: Option<Option<Uuid>>,
    #[serde(deserialize_with = "double_option")]
    pub description: Option<Option<String>>,
    pub attributes: Option<serde_json::Value>,
}

impl GroupUpdate {
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.parent_id.is_none()
            && self.description.is_none()
            && self.attributes.is_none()
    }
}
