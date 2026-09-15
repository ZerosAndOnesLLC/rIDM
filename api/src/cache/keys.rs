//! Cache key and channel names. Centralised so invalidation and lookups can
//! never drift apart.

use uuid::Uuid;

pub const PREFIX: &str = "ridm";

/// Pub/sub channel carrying L1 invalidation messages between nodes.
pub const INVALIDATION_CHANNEL: &str = "ridm:cache:invalidate";

pub fn tenant_by_slug(slug: &str) -> String {
    format!("{PREFIX}:tenant:slug:{slug}")
}

pub fn tenant_by_id(id: Uuid) -> String {
    format!("{PREFIX}:tenant:id:{id}")
}

/// Per-tenant version token folded into role-derived cache keys. Bumped on any
/// role, group, membership, assignment or composite change.
pub fn roles_version(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:roles:ver")
}

pub fn effective_roles(tenant_id: Uuid, version: &str, user_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:roles:{version}:user:{user_id}")
}

pub fn profile_schema(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:profile_schema")
}

/// Published (active + retiring) keys of a tenant, i.e. the JWKS document.
pub fn jwks(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:jwks")
}

pub fn tenant_by_email_domain(domain: &str) -> String {
    format!("{PREFIX}:tenant:domain:{domain}")
}
