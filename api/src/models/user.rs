use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::util::patch::double_option;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    Active,
    Disabled,
    Locked,
    Pending,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub org_id: Option<Uuid>,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub phone: Option<String>,
    pub phone_verified: bool,
    #[serde(skip)]
    pub password_hash: Option<String>,
    #[serde(skip)]
    pub password_algo: Option<String>,
    pub must_change_password: bool,
    pub password_expires_at: Option<DateTime<Utc>>,
    pub password_changed_at: Option<DateTime<Utc>>,
    pub status: UserStatus,
    pub attributes: serde_json::Value,
    pub locale: Option<String>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub failed_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn has_password(&self) -> bool {
        self.password_hash.is_some()
    }

    pub fn is_locked_now(&self) -> bool {
        self.status == UserStatus::Locked
            || self.locked_until.is_some_and(|until| until > Utc::now())
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NewUser {
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub phone: Option<String>,
    pub phone_verified: bool,
    pub status: Option<UserStatus>,
    pub attributes: Option<serde_json::Value>,
    pub locale: Option<String>,
    pub org_id: Option<Uuid>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct UserUpdate {
    pub username: Option<String>,
    #[serde(deserialize_with = "double_option")]
    pub email: Option<Option<String>>,
    pub email_verified: Option<bool>,
    #[serde(deserialize_with = "double_option")]
    pub phone: Option<Option<String>>,
    pub phone_verified: Option<bool>,
    pub status: Option<UserStatus>,
    pub attributes: Option<serde_json::Value>,
    #[serde(deserialize_with = "double_option")]
    pub locale: Option<Option<String>>,
    #[serde(deserialize_with = "double_option")]
    pub org_id: Option<Option<Uuid>>,
    pub must_change_password: Option<bool>,
}

impl UserUpdate {
    pub fn is_empty(&self) -> bool {
        self.username.is_none()
            && self.email.is_none()
            && self.email_verified.is_none()
            && self.phone.is_none()
            && self.phone_verified.is_none()
            && self.status.is_none()
            && self.attributes.is_none()
            && self.locale.is_none()
            && self.org_id.is_none()
            && self.must_change_password.is_none()
    }
}

/// Filters for listing users.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct UserFilter {
    /// Case-insensitive prefix match on username or email.
    pub search: Option<String>,
    pub status: Option<UserStatus>,
    pub org_id: Option<Uuid>,
    pub include_deleted: bool,
}
