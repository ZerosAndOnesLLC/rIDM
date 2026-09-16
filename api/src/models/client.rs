use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use uuid::Uuid;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ClientType {
    /// Browser app, public, PKCE.
    Spa,
    /// Server-side web app, confidential.
    Web,
    /// Mobile / desktop, public, PKCE, loopback redirects allowed.
    Native,
    /// Service-to-service, client_credentials only.
    Machine,
    /// Input-constrained device, device authorization grant.
    Device,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    None,
    ClientSecretBasic,
    ClientSecretPost,
    PrivateKeyJwt,
}

impl TokenEndpointAuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::PrivateKeyJwt => "private_key_jwt",
        }
    }

    pub fn uses_secret(self) -> bool {
        matches!(self, Self::ClientSecretBasic | Self::ClientSecretPost)
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AccessTokenFormat {
    Jwt,
    Opaque,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ClientSubjectType {
    Public,
    Pairwise,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ClientStatus {
    Active,
    Disabled,
}

/// Grant types (RFC 6749 §4, RFC 8628, RFC 8693).
pub mod grants {
    pub const AUTHORIZATION_CODE: &str = "authorization_code";
    pub const REFRESH_TOKEN: &str = "refresh_token";
    pub const CLIENT_CREDENTIALS: &str = "client_credentials";
    pub const DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
    pub const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
    pub const ALL: [&str; 5] = [
        AUTHORIZATION_CODE,
        REFRESH_TOKEN,
        CLIENT_CREDENTIALS,
        DEVICE_CODE,
        TOKEN_EXCHANGE,
    ];
}

/// One of up to two active client secrets (rotation with a grace window).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ClientSecretHash {
    pub id: Uuid,
    /// base64url(SHA-256(secret)). Secrets are 256-bit random, so a fast hash suffices.
    pub hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl ClientSecretHash {
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_none_or(|t| t > now)
    }
}

/// `id_token_encryption` column.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IdTokenEncryptionConfig {
    /// `RSA-OAEP-256` or `RSA-OAEP`.
    pub alg: String,
    /// `A256GCM` or `A128GCM`.
    pub enc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct Client {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    pub name: String,
    pub client_type: ClientType,
    pub description: Option<String>,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    #[serde(skip)]
    #[schema(ignore)]
    pub secret_hashes: Json<Vec<ClientSecretHash>>,
    pub jwks: Option<serde_json::Value>,
    pub jwks_uri: Option<String>,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub allowed_grants: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub allowed_audiences: Vec<String>,
    pub access_token_ttl_secs: Option<i32>,
    pub refresh_token_ttl_secs: Option<i32>,
    pub id_token_ttl_secs: Option<i32>,
    pub access_token_format: AccessTokenFormat,
    #[schema(value_type = Option<IdTokenEncryptionConfig>)]
    pub id_token_encryption: Option<Json<IdTokenEncryptionConfig>>,
    pub subject_type: ClientSubjectType,
    pub sector_identifier_uri: Option<String>,
    pub require_pkce: bool,
    pub require_consent: bool,
    pub cors_origins: Vec<String>,
    pub initiate_login_uri: Option<String>,
    pub backchannel_logout_uri: Option<String>,
    pub frontchannel_logout_uri: Option<String>,
    /// Every access token must be sender-constrained with a DPoP proof
    /// (RFC 9449 §5.2 `dpop_bound_access_tokens`).
    pub dpop_bound_access_tokens: bool,
    pub service_account_user_id: Option<Uuid>,
    #[serde(skip)]
    pub registration_access_token_hash: Option<Vec<u8>>,
    pub status: ClientStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Client {
    pub fn is_public(&self) -> bool {
        self.token_endpoint_auth_method == TokenEndpointAuthMethod::None
    }

    pub fn is_active(&self) -> bool {
        self.status == ClientStatus::Active
    }

    pub fn allows_grant(&self, grant: &str) -> bool {
        self.allowed_grants.iter().any(|g| g == grant)
    }

    /// Secrets that can still authenticate the client right now.
    pub fn active_secrets(&self) -> Vec<&ClientSecretHash> {
        let now = Utc::now();
        self.secret_hashes
            .iter()
            .filter(|s| s.is_active(now))
            .collect()
    }
}

/// Input for creating a client. Missing fields take type-driven defaults.
#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NewClient {
    /// Generated when absent.
    pub client_id: Option<String>,
    pub name: String,
    pub client_type: Option<ClientType>,
    pub description: Option<String>,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,
    pub jwks: Option<serde_json::Value>,
    pub jwks_uri: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub allowed_grants: Option<Vec<String>>,
    pub allowed_scopes: Option<Vec<String>>,
    pub allowed_audiences: Vec<String>,
    pub access_token_ttl_secs: Option<i32>,
    pub refresh_token_ttl_secs: Option<i32>,
    pub id_token_ttl_secs: Option<i32>,
    pub access_token_format: Option<AccessTokenFormat>,
    pub id_token_encryption: Option<IdTokenEncryptionConfig>,
    pub subject_type: Option<ClientSubjectType>,
    pub sector_identifier_uri: Option<String>,
    pub require_pkce: Option<bool>,
    pub require_consent: Option<bool>,
    pub cors_origins: Vec<String>,
    pub initiate_login_uri: Option<String>,
    pub backchannel_logout_uri: Option<String>,
    pub frontchannel_logout_uri: Option<String>,
    pub dpop_bound_access_tokens: Option<bool>,
}
