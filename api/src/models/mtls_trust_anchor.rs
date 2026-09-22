use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A certificate authority whose certificates the tenant's `tls_client_auth`
/// clients may authenticate with (RFC 8705 §2.1). It may be a root or an
/// intermediate: a client's chain only has to reach it.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct MtlsTrustAnchor {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    /// The CA certificate, PEM.
    pub certificate_pem: String,
    /// RFC 4514 subject of the CA certificate.
    pub subject: String,
    /// base64url(SHA-256(DER)).
    pub fingerprint: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NewMtlsTrustAnchor {
    pub name: String,
    /// One CA certificate, PEM.
    pub certificate_pem: String,
}
