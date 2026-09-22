//! A Kerberos identity provider's settings: the service, its keytab and
//! how a client principal finds its rIDM account.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use uuid::Uuid;

use super::WriteOnly;
use crate::kerberos::KeytabEntryInfo;

/// How a client principal names a user.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum KerberosNameForm {
    /// The name without the realm: `alice`.
    #[default]
    LocalPart,
    /// The whole principal: `alice@EXAMPLE.COM`.
    Principal,
}

/// What an administrator sets for a Kerberos provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct KerberosSettings {
    /// The service tickets are issued for, `HTTP/<host>@<REALM>`, where
    /// `<host>` is the name browsers use for rIDM. Taken from the keytab
    /// when it holds one service only.
    pub service_principal: Option<String>,
    /// The service's keytab file, base64. Write-only: never returned; left
    /// out on an update it is kept, an empty string clears it.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, write_only)]
    pub keytab: Option<WriteOnly>,
    /// The client realms whose users may sign in; the service's realm when
    /// empty.
    pub realms: Vec<String>,
    pub name_form: KerberosNameForm,
    /// An LDAP identity provider that owns these users: the name is looked
    /// up in the directory and the user imported or refreshed through it.
    pub ldap_idp_id: Option<Uuid>,
    /// The directory attribute holding the name (`sAMAccountName` or
    /// `userPrincipalName` on Active Directory, `uid` or `krbPrincipalName`
    /// elsewhere, by the name form, when unset).
    pub ldap_attribute: Option<String>,
    /// Without a directory: sign in the local account whose username is the
    /// name.
    pub match_username: bool,
    /// Without a directory: create an account (named by the name) for a
    /// principal no account matches.
    pub create_users: bool,
    /// The networks (CIDRs) from which the login page tries Kerberos on its
    /// own; elsewhere users click the provider's button.
    pub trusted_networks: Vec<String>,
    /// Allowed clock difference with clients, 30–900 seconds.
    pub max_skew_seconds: i32,
}

impl Default for KerberosSettings {
    fn default() -> Self {
        Self {
            service_principal: None,
            keytab: None,
            realms: vec![],
            name_form: KerberosNameForm::LocalPart,
            ldap_idp_id: None,
            ldap_attribute: None,
            match_username: true,
            create_users: false,
            trusted_networks: vec![],
            max_skew_seconds: 300,
        }
    }
}

/// The Kerberos side of a `kerberos` identity provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct KerberosUpstream {
    #[serde(skip)]
    pub idp_id: Uuid,
    #[serde(skip)]
    pub tenant_id: Uuid,
    pub service_principal: String,
    pub realms: Vec<String>,
    /// What the stored keytab holds (never a key).
    #[schema(value_type = Vec<KeytabEntryInfo>)]
    pub keytab_entries: Json<Vec<KeytabEntryInfo>>,
    /// A keytab is stored (it is never returned).
    #[sqlx(skip)]
    pub keytab_set: bool,
    /// This build of rIDM can accept tickets (the `kerberos` feature).
    #[sqlx(skip)]
    pub supported: bool,
    pub name_form: KerberosNameForm,
    pub ldap_idp_id: Option<Uuid>,
    pub ldap_attribute: Option<String>,
    pub match_username: bool,
    pub create_users: bool,
    pub trusted_networks: Vec<String>,
    pub max_skew_seconds: i32,
    #[serde(skip)]
    pub created_at: DateTime<Utc>,
    #[serde(skip)]
    pub updated_at: DateTime<Utc>,
}

impl KerberosUpstream {
    pub fn settings(&self) -> KerberosSettings {
        KerberosSettings {
            service_principal: Some(self.service_principal.clone()),
            keytab: None,
            realms: self.realms.clone(),
            name_form: self.name_form,
            ldap_idp_id: self.ldap_idp_id,
            ldap_attribute: self.ldap_attribute.clone(),
            match_username: self.match_username,
            create_users: self.create_users,
            trusted_networks: self.trusted_networks.clone(),
            max_skew_seconds: self.max_skew_seconds,
        }
    }
}
