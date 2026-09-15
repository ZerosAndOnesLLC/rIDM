use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JWS algorithms rIDM can sign with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum SigningAlg {
    RS256,
    RS384,
    RS512,
    ES256,
    EdDSA,
}

impl SigningAlg {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
            Self::ES256 => "ES256",
            Self::EdDSA => "EdDSA",
        }
    }

    pub const ALL: [SigningAlg; 5] = [
        Self::RS256,
        Self::RS384,
        Self::RS512,
        Self::ES256,
        Self::EdDSA,
    ];

    /// JWK key type.
    pub fn kty(self) -> &'static str {
        match self {
            Self::RS256 | Self::RS384 | Self::RS512 => "RSA",
            Self::ES256 => "EC",
            Self::EdDSA => "OKP",
        }
    }
}

impl std::str::FromStr for SigningAlg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|a| a.as_str().eq_ignore_ascii_case(s))
            .ok_or_else(|| format!("unsupported signing algorithm `{s}`"))
    }
}

impl std::fmt::Display for SigningAlg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle: pending (published, not yet signing) → active (signing) →
/// retiring (published for verification only) → revoked (unpublished).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    Pending,
    Active,
    Retiring,
    Revoked,
}

impl KeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Retiring => "retiring",
            Self::Revoked => "revoked",
        }
    }

    /// Keys in these states appear in the JWKS document.
    pub fn is_published(self) -> bool {
        matches!(self, Self::Pending | Self::Active | Self::Retiring)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SigningKey {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub kid: String,
    pub alg: SigningAlg,
    /// Public half as a JWK (`kty`, `kid`, `alg`, `use`, and the key parameters).
    pub public_jwk: serde_json::Value,
    #[serde(skip)]
    pub private_key_enc: Vec<u8>,
    /// Master-key generation that encrypted `private_key_enc`.
    pub key_version: i32,
    pub status: KeyStatus,
    pub not_before: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// RSA modulus size for new RSA keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RsaBits {
    B2048,
    B3072,
    B4096,
}

impl RsaBits {
    pub fn bits(self) -> usize {
        match self {
            Self::B2048 => 2048,
            Self::B3072 => 3072,
            Self::B4096 => 4096,
        }
    }
}
