//! An LDAP / Active Directory identity provider's directory settings.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use uuid::Uuid;

/// Which directory server it is: it picks the defaults (attributes,
/// filters) and how a password is written.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum LdapVendor {
    ActiveDirectory,
    Openldap,
    #[default]
    Other,
}

impl LdapVendor {
    pub fn default_user_object_filter(self) -> &'static str {
        match self {
            Self::ActiveDirectory => "(&(objectCategory=person)(objectClass=user))",
            _ => "(objectClass=inetOrgPerson)",
        }
    }

    pub fn default_username_attribute(self) -> &'static str {
        match self {
            Self::ActiveDirectory => "sAMAccountName",
            _ => "uid",
        }
    }

    pub fn default_uuid_attribute(self) -> &'static str {
        match self {
            Self::ActiveDirectory => "objectGUID",
            _ => "entryUUID",
        }
    }

    pub fn default_group_object_filter(self) -> &'static str {
        match self {
            Self::ActiveDirectory => "(objectClass=group)",
            _ => "(objectClass=groupOfNames)",
        }
    }

    /// The operational attribute holding an entry's last modification
    /// (generalized time), which incremental sync filters on.
    pub fn modified_attribute(self) -> &'static str {
        match self {
            Self::ActiveDirectory => "whenChanged",
            _ => "modifyTimestamp",
        }
    }
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum LdapScope {
    /// The base and everything below it.
    #[default]
    Subtree,
    /// The base's direct children only.
    One,
}

/// Whether rIDM writes back to the directory.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum LdapEditMode {
    /// The directory is the only source: rIDM refuses to change a directory
    /// user's password, email or mapped attributes.
    #[default]
    ReadOnly,
    /// Password changes and resets, email and mapped attribute edits are
    /// written to the directory (as the service account) before rIDM
    /// stores them.
    Writable,
}

/// What a group's member attribute holds.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum LdapMembership {
    /// Member DNs (`groupOfNames`, Active Directory).
    #[default]
    Dn,
    /// Usernames (`posixGroup`'s `memberUid`).
    Username,
}

/// A secret that is accepted but never written out, not by `Debug` and
/// not by `Serialize`.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct WriteOnly(pub String);

impl std::fmt::Debug for WriteOnly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Written out as `null`, whatever it holds.
impl Serialize for WriteOnly {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_none()
    }
}

/// What an administrator sets for a directory. Attributes and filters left
/// out take the vendor's defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct LdapSettings {
    /// `ldaps://host[:port]`, or `ldap://host[:port]` with `starttls`.
    /// Plain `ldap://` is accepted for loopback hosts only.
    pub url: String,
    /// Upgrade an `ldap://` connection with StartTLS.
    pub starttls: bool,
    /// PEM certificate(s) the directory's certificate must chain to (an
    /// internal CA); none trusts the platform's roots.
    pub ca_certificate: Option<String>,
    pub vendor: LdapVendor,
    /// The service account that searches (and, when writable, writes);
    /// none searches anonymously.
    pub bind_dn: Option<String>,
    /// The service account's password. Write-only: never returned; left
    /// out on an update it is kept, an empty string clears it.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, write_only)]
    pub bind_password: Option<WriteOnly>,
    /// Where users are searched.
    pub users_dn: String,
    /// Which entries are users, e.g. `(objectClass=inetOrgPerson)`.
    pub user_object_filter: Option<String>,
    pub search_scope: LdapScope,
    /// The attribute a new account's username comes from (`uid`,
    /// `sAMAccountName`).
    pub username_attribute: Option<String>,
    /// The attributes a sign-in identifier is matched against; the username
    /// attribute and `mail` when empty.
    pub login_attributes: Vec<String>,
    /// The attribute that never changes for an entry (`entryUUID`,
    /// `objectGUID`): what the linked identity is keyed by.
    pub uuid_attribute: Option<String>,
    pub edit_mode: LdapEditMode,
    /// Incremental sync every this many minutes (5–10080); 0 turns the
    /// periodic sync off (users are still imported and refreshed when they
    /// sign in).
    pub sync_interval_minutes: i32,
    /// A full sync, which also disables the users who left the directory
    /// (or were disabled in it), every this many hours (1–720).
    pub full_sync_interval_hours: i32,
    /// Where groups are searched; none turns group sync off.
    pub groups_dn: Option<String>,
    pub group_object_filter: Option<String>,
    /// The attribute a synced group's name comes from (`cn`).
    pub group_name_attribute: Option<String>,
    /// The attribute listing a group's members (`member`, `memberUid`).
    pub group_member_attribute: Option<String>,
    pub group_membership: LdapMembership,
    /// The rIDM group synced groups are created under; none makes them
    /// top-level.
    pub group_parent_id: Option<Uuid>,
    /// Seconds a connection or an operation may take (1–60).
    pub timeout_secs: i32,
}

impl Default for LdapSettings {
    fn default() -> Self {
        Self {
            url: String::new(),
            starttls: false,
            ca_certificate: None,
            vendor: LdapVendor::Other,
            bind_dn: None,
            bind_password: None,
            users_dn: String::new(),
            user_object_filter: None,
            search_scope: LdapScope::Subtree,
            username_attribute: None,
            login_attributes: vec![],
            uuid_attribute: None,
            edit_mode: LdapEditMode::ReadOnly,
            sync_interval_minutes: 60,
            full_sync_interval_hours: 24,
            groups_dn: None,
            group_object_filter: None,
            group_name_attribute: None,
            group_member_attribute: None,
            group_membership: LdapMembership::Dn,
            group_parent_id: None,
            timeout_secs: 10,
        }
    }
}

/// What one sync pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default)]
pub struct LdapSyncStats {
    /// A full pass (it may disable users); otherwise incremental.
    pub full: bool,
    /// Directory user entries read.
    pub read: u64,
    pub created: u64,
    pub updated: u64,
    /// Disabled because the entry left the directory or was disabled there.
    pub disabled: u64,
    /// Enabled again because the entry came back.
    pub enabled: u64,
    /// Entries that could not be imported (no usable uuid or username, or
    /// the link policy refused them); the log says why.
    pub skipped: u64,
    pub groups_created: u64,
    pub groups_updated: u64,
    pub groups_deleted: u64,
    pub memberships_added: u64,
    pub memberships_removed: u64,
}

/// The directory side of an `ldap` identity provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct LdapUpstream {
    #[serde(skip)]
    pub idp_id: Uuid,
    #[serde(skip)]
    pub tenant_id: Uuid,
    pub url: String,
    pub starttls: bool,
    pub ca_certificate: Option<String>,
    pub vendor: LdapVendor,
    pub bind_dn: Option<String>,
    /// A bind password is stored (it is never returned).
    #[sqlx(skip)]
    pub bind_password_set: bool,
    pub users_dn: String,
    pub user_object_filter: String,
    pub search_scope: LdapScope,
    pub username_attribute: String,
    pub login_attributes: Vec<String>,
    pub uuid_attribute: String,
    pub edit_mode: LdapEditMode,
    pub sync_interval_minutes: i32,
    pub full_sync_interval_hours: i32,
    pub groups_dn: Option<String>,
    pub group_object_filter: String,
    pub group_name_attribute: String,
    pub group_member_attribute: String,
    pub group_membership: LdapMembership,
    pub group_parent_id: Option<Uuid>,
    pub timeout_secs: i32,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_full_sync_at: Option<DateTime<Utc>>,
    /// Why the last sync failed, until one succeeds.
    pub last_sync_error: Option<String>,
    #[schema(value_type = Option<LdapSyncStats>)]
    pub last_sync_stats: Option<Json<LdapSyncStats>>,
    #[serde(skip)]
    pub sync_cursor: Option<String>,
    #[serde(skip)]
    pub created_at: DateTime<Utc>,
    #[serde(skip)]
    pub updated_at: DateTime<Utc>,
}

impl LdapUpstream {
    pub fn settings(&self) -> LdapSettings {
        LdapSettings {
            url: self.url.clone(),
            starttls: self.starttls,
            ca_certificate: self.ca_certificate.clone(),
            vendor: self.vendor,
            bind_dn: self.bind_dn.clone(),
            bind_password: None,
            users_dn: self.users_dn.clone(),
            user_object_filter: Some(self.user_object_filter.clone()),
            search_scope: self.search_scope,
            username_attribute: Some(self.username_attribute.clone()),
            login_attributes: self.login_attributes.clone(),
            uuid_attribute: Some(self.uuid_attribute.clone()),
            edit_mode: self.edit_mode,
            sync_interval_minutes: self.sync_interval_minutes,
            full_sync_interval_hours: self.full_sync_interval_hours,
            groups_dn: self.groups_dn.clone(),
            group_object_filter: Some(self.group_object_filter.clone()),
            group_name_attribute: Some(self.group_name_attribute.clone()),
            group_member_attribute: Some(self.group_member_attribute.clone()),
            group_membership: self.group_membership,
            group_parent_id: self.group_parent_id,
            timeout_secs: self.timeout_secs,
        }
    }
}
