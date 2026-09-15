//! Typed domain events. Every state-changing domain action emits exactly one
//! event; audit, webhooks, notifications and cache invalidation subscribe.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Who caused the event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Actor {
    User { id: Uuid },
    Client { id: Uuid },
    Admin { id: Uuid },
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    /// `None` for global (cross-tenant) events such as master-key rotation.
    pub tenant_id: Option<Uuid>,
    pub occurred_at: DateTime<Utc>,
    pub actor: Actor,
    /// Client IP as seen through trusted proxies, when the event came from a request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    pub kind: EventKind,
}

impl Event {
    pub fn new(tenant_id: Option<Uuid>, actor: Actor, kind: EventKind) -> Self {
        Self {
            id: Uuid::now_v7(),
            tenant_id,
            occurred_at: Utc::now(),
            actor,
            ip: None,
            user_agent: None,
            kind,
        }
    }

    pub fn with_request(mut self, ip: Option<String>, user_agent: Option<String>) -> Self {
        self.ip = ip;
        self.user_agent = user_agent;
        self
    }

    /// Stable dotted name (`user.created`) used by audit, webhooks and metrics.
    pub fn name(&self) -> &'static str {
        self.kind.name()
    }
}

/// The event catalogue. Variants are added phase by phase; the `name()` string
/// is part of the public webhook contract and must never change once shipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventKind {
    // Tenants
    TenantCreated {
        tenant_id: Uuid,
    },
    TenantUpdated {
        tenant_id: Uuid,
    },
    TenantDeleted {
        tenant_id: Uuid,
    },
    ProfileSchemaUpdated {
        tenant_id: Uuid,
    },
    /// First-run bootstrap created the global admin.
    Bootstrapped {
        admin_user_id: Uuid,
    },

    // Users
    UserCreated {
        user_id: Uuid,
    },
    UserUpdated {
        user_id: Uuid,
    },
    UserDeleted {
        user_id: Uuid,
    },
    /// Password set by an admin, reset flow, or the user; `by_user` tells which.
    PasswordChanged {
        user_id: Uuid,
        by_user: bool,
    },
    /// A legacy or weaker hash was replaced after a successful verification.
    PasswordHashUpgraded {
        user_id: Uuid,
        from_algo: String,
    },

    // Groups
    GroupCreated {
        group_id: Uuid,
    },
    GroupUpdated {
        group_id: Uuid,
    },
    GroupDeleted {
        group_id: Uuid,
    },
    GroupMemberAdded {
        group_id: Uuid,
        user_id: Uuid,
    },
    GroupMemberRemoved {
        group_id: Uuid,
        user_id: Uuid,
    },

    // Roles
    RoleCreated {
        role_id: Uuid,
    },
    RoleUpdated {
        role_id: Uuid,
    },
    RoleDeleted {
        role_id: Uuid,
    },
    RoleAssigned {
        role_id: Uuid,
        user_id: Option<Uuid>,
        group_id: Option<Uuid>,
    },
    RoleUnassigned {
        role_id: Uuid,
        user_id: Option<Uuid>,
        group_id: Option<Uuid>,
    },
    RoleCompositeAdded {
        parent_role_id: Uuid,
        child_role_id: Uuid,
    },
    RoleCompositeRemoved {
        parent_role_id: Uuid,
        child_role_id: Uuid,
    },

    // Tokens
    RefreshTokenReuseDetected {
        family_id: Uuid,
        client_id: String,
        user_id: Option<Uuid>,
    },
    TokensRevoked {
        user_id: Option<Uuid>,
        session_id: Option<Uuid>,
        count: u64,
    },

    // Keys
    SigningKeyCreated {
        key_id: Uuid,
        kid: String,
        alg: String,
    },
    SigningKeyStatusChanged {
        key_id: Uuid,
        kid: String,
        status: String,
    },
    MasterKeyRotated {
        new_version: u32,
    },

    // Generic cache invalidation hint (entity kind + id), used until every
    // entity has a dedicated event.
    CacheInvalidate {
        entity: String,
        id: String,
    },
}

impl EventKind {
    pub fn name(&self) -> &'static str {
        match self {
            Self::TenantCreated { .. } => "tenant.created",
            Self::TenantUpdated { .. } => "tenant.updated",
            Self::TenantDeleted { .. } => "tenant.deleted",
            Self::ProfileSchemaUpdated { .. } => "tenant.profile_schema_updated",
            Self::Bootstrapped { .. } => "system.bootstrapped",
            Self::UserCreated { .. } => "user.created",
            Self::UserUpdated { .. } => "user.updated",
            Self::UserDeleted { .. } => "user.deleted",
            Self::PasswordChanged { .. } => "user.password_changed",
            Self::PasswordHashUpgraded { .. } => "user.password_hash_upgraded",
            Self::GroupCreated { .. } => "group.created",
            Self::GroupUpdated { .. } => "group.updated",
            Self::GroupDeleted { .. } => "group.deleted",
            Self::GroupMemberAdded { .. } => "group.member_added",
            Self::GroupMemberRemoved { .. } => "group.member_removed",
            Self::RoleCreated { .. } => "role.created",
            Self::RoleUpdated { .. } => "role.updated",
            Self::RoleDeleted { .. } => "role.deleted",
            Self::RoleAssigned { .. } => "role.assigned",
            Self::RoleUnassigned { .. } => "role.unassigned",
            Self::RoleCompositeAdded { .. } => "role.composite_added",
            Self::RoleCompositeRemoved { .. } => "role.composite_removed",
            Self::RefreshTokenReuseDetected { .. } => "token.refresh_reuse_detected",
            Self::TokensRevoked { .. } => "token.revoked",
            Self::SigningKeyCreated { .. } => "signing_key.created",
            Self::SigningKeyStatusChanged { .. } => "signing_key.status_changed",
            Self::MasterKeyRotated { .. } => "master_key.rotated",
            Self::CacheInvalidate { .. } => "cache.invalidate",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serializes_with_tagged_kind() {
        let e = Event::new(
            Some(Uuid::nil()),
            Actor::System,
            EventKind::UserCreated {
                user_id: Uuid::nil(),
            },
        );
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(json["kind"]["type"], "user_created");
        assert_eq!(json["actor"]["type"], "system");
        assert_eq!(e.name(), "user.created");
        let back: Event = serde_json::from_value(json).unwrap();
        assert_eq!(back, e);
    }
}
