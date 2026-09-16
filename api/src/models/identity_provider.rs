use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use uuid::Uuid;

use crate::util::patch::double_option;

/// The protocol an upstream provider speaks.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum IdpKind {
    /// OpenID Connect: an ID token proves the identity.
    Oidc,
    /// Plain OAuth 2.0: the userinfo endpoint describes the identity.
    Oauth2,
}

/// What happens when an upstream identity signs in for the first time and
/// a local account with the same email address exists.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum LinkPolicy {
    /// Link when both sides have verified the address; otherwise refuse and
    /// ask the user to link from their account page.
    VerifiedEmail,
    /// Never link by email: an existing address is refused, the user links
    /// from their account page after signing in the usual way.
    Explicit,
    /// Never link: a new account is created every time (without the email
    /// when another account holds it).
    AlwaysNew,
}

/// How the client authenticates at the token endpoint.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum IdpAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    /// Public client: PKCE only.
    None,
}

/// Where the identity's fields come from in the upstream claims (ID token,
/// then userinfo). Values are claim names; a dot descends into an object.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct IdpMappers {
    /// The stable identifier; `sub` when unset (`id` for GitHub).
    pub subject: Option<String>,
    /// `preferred_username` when unset.
    pub username: Option<String>,
    /// `email` when unset.
    pub email: Option<String>,
    /// `email_verified` when unset.
    pub email_verified: Option<String>,
    /// Profile attribute name → claim name, written on every sign-in.
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct IdentityProvider {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub alias: String,
    pub kind: IdpKind,
    pub display_name: String,
    /// `google`, `microsoft`, `github`, `apple`, `gitlab` or none.
    pub preset: Option<String>,
    pub enabled: bool,
    /// Not offered on the login page; reachable through a direct link.
    pub hidden: bool,
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub client_id: String,
    #[serde(skip)]
    pub client_secret_enc: Vec<u8>,
    #[serde(skip)]
    pub key_version: i32,
    /// A client secret is stored (it is never returned).
    pub client_secret_set: bool,
    pub token_endpoint_auth_method: IdpAuthMethod,
    pub scopes: Vec<String>,
    pub pkce: bool,
    pub link_policy: LinkPolicy,
    pub trust_email: bool,
    #[schema(value_type = IdpMappers)]
    pub mappers: Json<IdpMappers>,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl IdentityProvider {
    /// Offered on the login page.
    pub fn offered(&self) -> bool {
        self.enabled && !self.hidden
    }
}

/// Fields of a new provider. A `preset` fills in everything the preset
/// knows (kind, endpoints, scopes, mappers); explicit values win.
#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NewIdentityProvider {
    pub alias: String,
    pub kind: Option<IdpKind>,
    pub display_name: Option<String>,
    pub preset: Option<String>,
    pub enabled: Option<bool>,
    pub hidden: Option<bool>,
    /// OIDC: the endpoints are discovered from it when left out.
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub token_endpoint_auth_method: Option<IdpAuthMethod>,
    pub scopes: Option<Vec<String>>,
    pub pkce: Option<bool>,
    pub link_policy: Option<LinkPolicy>,
    pub trust_email: Option<bool>,
    pub mappers: Option<IdpMappers>,
    pub sort_order: Option<i32>,
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityProviderUpdate {
    pub alias: Option<String>,
    pub kind: Option<IdpKind>,
    pub display_name: Option<String>,
    pub enabled: Option<bool>,
    pub hidden: Option<bool>,
    #[serde(deserialize_with = "double_option")]
    pub issuer: Option<Option<String>>,
    #[serde(deserialize_with = "double_option")]
    pub authorization_endpoint: Option<Option<String>>,
    #[serde(deserialize_with = "double_option")]
    pub token_endpoint: Option<Option<String>>,
    #[serde(deserialize_with = "double_option")]
    pub userinfo_endpoint: Option<Option<String>>,
    #[serde(deserialize_with = "double_option")]
    pub jwks_uri: Option<Option<String>>,
    pub client_id: Option<String>,
    /// A new secret, or `null` to clear it.
    #[serde(deserialize_with = "double_option")]
    pub client_secret: Option<Option<String>>,
    pub token_endpoint_auth_method: Option<IdpAuthMethod>,
    pub scopes: Option<Vec<String>>,
    pub pkce: Option<bool>,
    pub link_policy: Option<LinkPolicy>,
    pub trust_email: Option<bool>,
    pub mappers: Option<IdpMappers>,
    pub sort_order: Option<i32>,
}

impl IdentityProviderUpdate {
    pub fn is_empty(&self) -> bool {
        self.alias.is_none()
            && self.kind.is_none()
            && self.display_name.is_none()
            && self.enabled.is_none()
            && self.hidden.is_none()
            && self.issuer.is_none()
            && self.authorization_endpoint.is_none()
            && self.token_endpoint.is_none()
            && self.userinfo_endpoint.is_none()
            && self.jwks_uri.is_none()
            && self.client_id.is_none()
            && self.client_secret.is_none()
            && self.token_endpoint_auth_method.is_none()
            && self.scopes.is_none()
            && self.pkce.is_none()
            && self.link_policy.is_none()
            && self.trust_email.is_none()
            && self.mappers.is_none()
            && self.sort_order.is_none()
    }
}

/// A provider as the login page and the account console see it.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PublicIdentityProvider {
    pub alias: String,
    pub display_name: String,
    pub preset: Option<String>,
}

impl From<&IdentityProvider> for PublicIdentityProvider {
    fn from(p: &IdentityProvider) -> Self {
        Self {
            alias: p.alias.clone(),
            display_name: p.display_name.clone(),
            preset: p.preset.clone(),
        }
    }
}

/// An upstream identity a user signs in with.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct FederatedIdentity {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub idp_id: Uuid,
    pub external_subject: String,
    pub external_email: Option<String>,
    pub external_username: Option<String>,
    pub linked_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

/// A linked identity with its provider, for listings.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct LinkedIdentity {
    pub idp_id: Uuid,
    pub alias: String,
    pub display_name: String,
    pub preset: Option<String>,
    pub external_subject: String,
    pub external_email: Option<String>,
    pub external_username: Option<String>,
    pub linked_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}
