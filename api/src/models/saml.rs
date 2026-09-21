use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use uuid::Uuid;

use crate::saml::ns;
use crate::saml::xmlenc::{DataEncryption, KeyTransport};

/// The subject identifier an SP receives.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum NameIdFormat {
    /// Opaque, stable and different for every SP (pairwise).
    #[default]
    Persistent,
    /// Opaque and new on every sign-in.
    Transient,
    /// The user's email address.
    Email,
    /// The user's id.
    Unspecified,
}

impl NameIdFormat {
    pub fn urn(self) -> &'static str {
        match self {
            Self::Persistent => ns::nameid::PERSISTENT,
            Self::Transient => ns::nameid::TRANSIENT,
            Self::Email => ns::nameid::EMAIL,
            Self::Unspecified => ns::nameid::UNSPECIFIED,
        }
    }

    pub fn from_urn(urn: &str) -> Option<Self> {
        Some(match urn {
            ns::nameid::PERSISTENT => Self::Persistent,
            ns::nameid::TRANSIENT => Self::Transient,
            ns::nameid::EMAIL => Self::Email,
            ns::nameid::UNSPECIFIED => Self::Unspecified,
            _ => return None,
        })
    }
}

/// Binding rIDM uses to send an SP its logout messages.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum SloBinding {
    #[default]
    Redirect,
    Post,
}

/// `NameFormat` of a released attribute.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AttributeNameFormat {
    #[default]
    Basic,
    Uri,
    Unspecified,
}

impl AttributeNameFormat {
    pub fn urn(self) -> &'static str {
        match self {
            Self::Basic => ns::ATTRNAME_BASIC,
            Self::Uri => ns::ATTRNAME_URI,
            Self::Unspecified => ns::ATTRNAME_UNSPECIFIED,
        }
    }
}

/// One released attribute: the value of a claim, under the SP's name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SamlAttribute {
    /// A claim the client's scopes, the profile schema or a claim mapper
    /// produce (`email`, `name`, `groups`, `roles`, ...).
    pub claim: String,
    /// The attribute's `Name`, e.g. `urn:oid:0.9.2342.19200300.100.1.3`.
    pub name: String,
    #[serde(default)]
    pub name_format: AttributeNameFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
}

/// The SAML side of a `saml` client.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct SamlServiceProvider {
    /// The client's row id.
    pub client_id: Uuid,
    #[serde(skip)]
    pub tenant_id: Uuid,
    pub entity_id: String,
    /// HTTP-POST assertion consumer services; the position is the index
    /// and the first is the default.
    pub acs_urls: Vec<String>,
    pub slo_url: Option<String>,
    pub slo_binding: SloBinding,
    pub name_id_format: NameIdFormat,
    /// base64 DER certificates the SP signs requests with.
    pub signing_certificates: Vec<String>,
    /// base64 DER certificate assertions are encrypted to.
    pub encryption_certificate: Option<String>,
    pub require_signed_requests: bool,
    pub sign_response: bool,
    pub sign_assertion: bool,
    pub encrypt_assertion: bool,
    pub data_encryption: DataEncryption,
    pub key_transport: KeyTransport,
    pub allow_idp_initiated: bool,
    pub default_relay_state: Option<String>,
    #[schema(value_type = Vec<SamlAttribute>)]
    pub attributes: Json<Vec<SamlAttribute>>,
    pub assertion_ttl_secs: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Lifecycle of a SAML signing key: `pending` (in metadata, not signing)
/// → `active` (signing) → `retiring` (in metadata, not signing) → deleted.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum SamlKeyStatus {
    Pending,
    Active,
    Retiring,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SamlSigningKey {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub private_key_enc: Vec<u8>,
    pub key_version: i32,
    /// Self-signed X.509 certificate, DER.
    pub certificate: Vec<u8>,
    pub status: SamlKeyStatus,
    pub not_after: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
