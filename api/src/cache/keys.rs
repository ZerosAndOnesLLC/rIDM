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

/// Parsed signing key material (L1 only; never written to Redis).
pub fn signing_key_material(key_id: Uuid) -> String {
    format!("{PREFIX}:signing_key:{key_id}:material")
}

/// Denylisted access-token `jti` (instant revocation before expiry).
pub fn jti_denied(tenant_id: Uuid, jti: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:jti:{jti}")
}

pub fn client_by_client_id(tenant_id: Uuid, client_id: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:client:{client_id}")
}

pub fn scopes(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:scopes")
}

pub fn mappers(tenant_id: Uuid, client_id: Option<Uuid>) -> String {
    match client_id {
        Some(c) => format!("{PREFIX}:t:{tenant_id}:mappers:{c}"),
        None => format!("{PREFIX}:t:{tenant_id}:mappers:global"),
    }
}

pub fn discovery(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:discovery")
}

pub fn sso_session(tenant_id: Uuid, session_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:session:{session_id}")
}

pub fn auth_code(tenant_id: Uuid, code_hash: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:code:{code_hash}")
}

pub fn login_flow(tenant_id: Uuid, flow_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:flow:{flow_id}")
}

pub fn client_jwks(tenant_id: Uuid, client_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:client:{client_id}:jwks")
}

pub fn client_assertion_jti(tenant_id: Uuid, client_id: Uuid, jti: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:client:{client_id}:assertion:{jti}")
}

pub fn code_family(tenant_id: Uuid, code_hash: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:code_family:{code_hash}")
}

/// Clients that obtained tokens within a browser session (for logout notification).
pub fn session_clients(tenant_id: Uuid, session_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:session:{session_id}:clients")
}

pub fn logout_flow(tenant_id: Uuid, flow_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:logout:{flow_id}")
}

pub fn par_request(tenant_id: Uuid, id: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:par:{id}")
}

pub fn dcr_initial_token(tenant_id: Uuid, token_hash: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:dcr:iat:{token_hash}")
}

/// Decrypted provider configuration (L1 only; never stored in Redis).
pub fn provider_settings(tenant_id: Uuid, kind: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:provider:{kind}")
}

/// One-time code bound to a login flow and channel.
pub fn flow_otp(tenant_id: Uuid, flow_id: Uuid, channel: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:flow:{flow_id}:otp:{channel}")
}

/// Magic-link token (hashed) → flow.
pub fn magic_link(tenant_id: Uuid, token_hash: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:magic:{token_hash}")
}

/// Send rate limit per identifier.
pub fn passwordless_sends(tenant_id: Uuid, identifier: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:pwless:sends:{identifier}")
}

/// Email verification token (hashed) → user (and optional flow to resume).
pub fn email_verification(tenant_id: Uuid, token_hash: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:verify:{token_hash}")
}

/// Password reset token (hashed) → user.
pub fn password_reset(tenant_id: Uuid, token_hash: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:reset:{token_hash}")
}
