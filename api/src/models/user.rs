use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::util::patch::double_option;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    Active,
    Disabled,
    Locked,
    Pending,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
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
    /// The provisioning system's identifier (SCIM `externalId`), unique per tenant.
    pub external_id: Option<String>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub failed_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub terms_accepted_at: Option<DateTime<Utc>>,
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

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
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
    pub external_id: Option<String>,
    /// Required profile attributes may be missing for now (an account made
    /// from an upstream identity fills them in at the profile step). Never
    /// set from a request body.
    #[serde(skip)]
    #[schema(ignore)]
    pub defer_required: bool,
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
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
    #[serde(deserialize_with = "double_option")]
    pub external_id: Option<Option<String>>,
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
            && self.external_id.is_none()
    }
}

/// Filters for listing users.
#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default)]
pub struct UserFilter {
    /// Case-insensitive prefix match on username or email.
    pub search: Option<String>,
    pub status: Option<UserStatus>,
    pub org_id: Option<Uuid>,
    pub include_deleted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> User {
        User {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            org_id: None,
            username: "u".into(),
            email: None,
            email_verified: false,
            phone: None,
            phone_verified: false,
            password_hash: None,
            password_algo: None,
            must_change_password: false,
            password_expires_at: None,
            password_changed_at: None,
            status: UserStatus::Active,
            attributes: serde_json::json!({}),
            locale: None,
            external_id: None,
            last_login_at: None,
            failed_attempts: 0,
            locked_until: None,
            deleted_at: None,
            terms_accepted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn lock_state_considers_status_and_temporary_lock() {
        let mut u = user();
        assert!(!u.is_locked_now());
        u.locked_until = Some(Utc::now() + chrono::Duration::minutes(5));
        assert!(u.is_locked_now());
        u.locked_until = Some(Utc::now() - chrono::Duration::minutes(5));
        assert!(
            !u.is_locked_now(),
            "an expired temporary lock is not a lock"
        );
        u.status = UserStatus::Locked;
        assert!(u.is_locked_now());
    }

    #[test]
    fn password_hash_never_serializes() {
        let mut u = user();
        u.password_hash = Some("$argon2id$secret".into());
        u.password_algo = Some("argon2id".into());
        let json = serde_json::to_string(&u).unwrap();
        assert!(!json.contains("password_hash"));
        assert!(!json.contains("secret"));
        assert!(!json.contains("password_algo"));
    }

    #[test]
    fn patch_is_empty_detection() {
        assert!(UserUpdate::default().is_empty());
        let p: UserUpdate = serde_json::from_str(r#"{"email": null}"#).unwrap();
        assert!(!p.is_empty(), "clearing a field is a change");
    }
}
