use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One audit row: a domain event as recorded, with its place in the
/// tenant's hash chain.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct AuditEvent {
    pub id: Uuid,
    /// `None` for global (cross-tenant) events.
    pub tenant_id: Option<Uuid>,
    /// Position in the chain (per tenant, or the global chain).
    pub seq: i64,
    pub occurred_at: DateTime<Utc>,
    pub recorded_at: DateTime<Utc>,
    /// Dotted event name (`user.created`).
    pub name: String,
    /// `user`, `client`, `admin` or `system`.
    pub actor_type: String,
    pub actor_id: Option<Uuid>,
    /// The main entity the event is about (user, client, role, ...), when it has one.
    pub subject_id: Option<Uuid>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    /// The event's `kind` document (`type` plus its fields).
    pub payload: serde_json::Value,
    #[serde(with = "hex_bytes")]
    #[schema(value_type = Option<String>)]
    pub prev_hash: Option<Vec<u8>>,
    #[serde(with = "hex_bytes")]
    #[schema(value_type = String)]
    pub hash: Vec<u8>,
}

/// Hashes are shown as lowercase hex.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub trait HexLike {
        fn to_hex(&self) -> Option<String>;
        fn from_hex(s: Option<String>) -> Result<Self, String>
        where
            Self: Sized;
    }

    impl HexLike for Vec<u8> {
        fn to_hex(&self) -> Option<String> {
            Some(hex::encode(self))
        }
        fn from_hex(s: Option<String>) -> Result<Self, String> {
            hex::decode(s.unwrap_or_default()).map_err(|e| e.to_string())
        }
    }

    impl HexLike for Option<Vec<u8>> {
        fn to_hex(&self) -> Option<String> {
            self.as_ref().map(hex::encode)
        }
        fn from_hex(s: Option<String>) -> Result<Self, String> {
            s.map(|s| hex::decode(s).map_err(|e| e.to_string()))
                .transpose()
        }
    }

    pub fn serialize<S: Serializer, T: HexLike>(v: &T, s: S) -> Result<S::Ok, S::Error> {
        v.to_hex().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: HexLike>(d: D) -> Result<T, D::Error> {
        let raw: Option<String> = Option::deserialize(d)?;
        T::from_hex(raw).map_err(serde::de::Error::custom)
    }
}

/// Filters for listing audit events.
#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(default)]
pub struct AuditFilter {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    /// Exact event name, or a prefix when it ends with `.` or `*` (`user.`).
    pub name: Option<String>,
    pub actor_id: Option<Uuid>,
    pub subject_id: Option<Uuid>,
    /// Rows where the user is the actor or the subject.
    pub user_id: Option<Uuid>,
}

/// Audit retention, per tenant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default)]
pub struct AuditPolicy {
    /// Days to keep audit rows (0 = forever).
    pub retention_days: u32,
}

impl Default for AuditPolicy {
    fn default() -> Self {
        Self {
            retention_days: 365,
        }
    }
}
