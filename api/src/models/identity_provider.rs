use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use uuid::Uuid;

use super::{LdapSettings, LdapUpstream, NameIdFormat, SloBinding};
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
    /// SAML 2.0: a signed assertion posted to rIDM's assertion consumer
    /// service proves the identity (rIDM is the service provider).
    Saml,
    /// LDAP or Active Directory: a bind as the user with the password they
    /// typed proves the identity (the directory owns the password), and a
    /// job syncs users and groups.
    Ldap,
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
    /// The SAML settings of a `saml` provider.
    #[sqlx(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml: Option<SamlUpstream>,
    /// The directory settings of an `ldap` provider.
    #[sqlx(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<LdapUpstream>,
}

impl IdentityProvider {
    /// Offered on the login page. A directory has no button: its users
    /// sign in with the password form.
    pub fn offered(&self) -> bool {
        self.enabled && !self.hidden && self.kind != IdpKind::Ldap
    }

    /// Reached through a browser redirect (a login-page button, or linking
    /// from the account console); a directory is not.
    pub fn redirects(&self) -> bool {
        self.kind != IdpKind::Ldap
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
    /// Required for a `saml` provider, refused for any other.
    pub saml: Option<SamlUpstreamSettings>,
    /// Required for an `ldap` provider, refused for any other.
    pub ldap: Option<LdapSettings>,
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
    /// A `saml` provider's settings, replaced as a whole.
    pub saml: Option<SamlUpstreamSettings>,
    /// An `ldap` provider's settings, replaced as a whole (a missing
    /// `bind_password` keeps the stored one).
    pub ldap: Option<LdapSettings>,
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
            && self.saml.is_none()
            && self.ldap.is_none()
    }
}

/// What an administrator sets for a SAML identity provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SamlUpstreamSettings {
    /// The IdP's entity ID, the `Issuer` of its messages.
    pub entity_id: String,
    /// Its single sign-on service.
    pub sso_url: String,
    /// How `AuthnRequest`s reach it.
    pub sso_binding: SloBinding,
    /// Its single logout service; none leaves sign-out local.
    pub slo_url: Option<String>,
    pub slo_binding: SloBinding,
    /// base64 (or PEM) certificates it signs with; several during its
    /// key rollover. Nothing unsigned is accepted, so one is required.
    pub signing_certificates: Vec<String>,
    /// The NameID format to ask for (`NameIDPolicy`); none leaves it to
    /// the IdP.
    pub name_id_format: Option<NameIdFormat>,
    /// Sign `AuthnRequest`s and `LogoutRequest`s with the tenant's SAML key.
    pub sign_requests: bool,
    /// The assertion itself must be signed; a signed `Response` around an
    /// unsigned assertion is refused.
    pub want_assertions_signed: bool,
    /// Refuse assertions that are not encrypted (to the tenant's SAML key).
    pub require_encrypted_assertions: bool,
    /// Ask the IdP to authenticate the user again (`ForceAuthn`).
    pub force_authn: bool,
    /// Authentication context classes to ask for (Comparison `exact`).
    pub authn_context_class_refs: Vec<String>,
    /// Accept unsolicited responses (IdP-initiated sign-in).
    pub allow_unsolicited: bool,
    /// Where an unsolicited sign-in lands: this client's
    /// `initiate_login_uri`; the account console when unset.
    pub unsolicited_client_id: Option<String>,
    /// The IdP's metadata URL, refreshed daily: its endpoints and
    /// certificates replace the ones above.
    pub metadata_url: Option<String>,
}

impl Default for SamlUpstreamSettings {
    fn default() -> Self {
        Self {
            entity_id: String::new(),
            sso_url: String::new(),
            sso_binding: SloBinding::Redirect,
            slo_url: None,
            slo_binding: SloBinding::Redirect,
            signing_certificates: vec![],
            name_id_format: None,
            sign_requests: true,
            want_assertions_signed: true,
            require_encrypted_assertions: false,
            force_authn: false,
            authn_context_class_refs: vec![],
            allow_unsolicited: false,
            unsolicited_client_id: None,
            metadata_url: None,
        }
    }
}

/// The SAML side of a `saml` identity provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct SamlUpstream {
    #[serde(skip)]
    pub idp_id: Uuid,
    #[serde(skip)]
    pub tenant_id: Uuid,
    pub entity_id: String,
    pub sso_url: String,
    pub sso_binding: SloBinding,
    pub slo_url: Option<String>,
    pub slo_binding: SloBinding,
    pub signing_certificates: Vec<String>,
    pub name_id_format: Option<NameIdFormat>,
    pub sign_requests: bool,
    pub want_assertions_signed: bool,
    pub require_encrypted_assertions: bool,
    pub force_authn: bool,
    pub authn_context_class_refs: Vec<String>,
    pub allow_unsolicited: bool,
    pub unsolicited_client_id: Option<String>,
    pub metadata_url: Option<String>,
    /// When the metadata URL was last read successfully.
    pub metadata_refreshed_at: Option<DateTime<Utc>>,
    /// Why the last refresh failed, until one succeeds.
    pub metadata_error: Option<String>,
    #[serde(skip)]
    pub created_at: DateTime<Utc>,
    #[serde(skip)]
    pub updated_at: DateTime<Utc>,
}

impl SamlUpstream {
    pub fn settings(&self) -> SamlUpstreamSettings {
        SamlUpstreamSettings {
            entity_id: self.entity_id.clone(),
            sso_url: self.sso_url.clone(),
            sso_binding: self.sso_binding,
            slo_url: self.slo_url.clone(),
            slo_binding: self.slo_binding,
            signing_certificates: self.signing_certificates.clone(),
            name_id_format: self.name_id_format,
            sign_requests: self.sign_requests,
            want_assertions_signed: self.want_assertions_signed,
            require_encrypted_assertions: self.require_encrypted_assertions,
            force_authn: self.force_authn,
            authn_context_class_refs: self.authn_context_class_refs.clone(),
            allow_unsolicited: self.allow_unsolicited,
            unsolicited_client_id: self.unsolicited_client_id.clone(),
            metadata_url: self.metadata_url.clone(),
        }
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
