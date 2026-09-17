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

/// Admin permissions of a user, derived from effective roles (same version token).
pub fn admin_permissions(tenant_id: Uuid, version: &str, user_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:admin_perms:{version}:user:{user_id}")
}

pub fn profile_schema(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:profile_schema")
}

/// Per-tenant version token folded into the JWKS cache key. Bumped on every
/// signing-key change, so a document read before that change cannot be stored
/// after it (deleting the key would leave that race open).
pub fn keys_version(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:keys:ver")
}

/// Published (pending + active + retiring) keys of a tenant, i.e. the JWKS
/// document, under the keys version.
pub fn jwks(tenant_id: Uuid, version: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:jwks:{version}")
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

/// Enabled webhooks of a tenant (dispatcher lookup).
pub fn webhooks(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:webhooks")
}

/// Per-tenant version token folded into mapper cache keys, bumped on any
/// claim mapper change (tenant-wide mappers reach every client's cache).
pub fn mappers_version(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:mappers:ver")
}

/// Effective mappers of one client under a mappers version token.
pub fn mappers(tenant_id: Uuid, version: &str, client_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:mappers:{version}:{client_id}")
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

/// Pending email/SMS second-factor enrolment (the destination being proven).
pub fn otp_factor_enrolment(tenant_id: Uuid, flow_id: Uuid, channel: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:flow:{flow_id}:mfa:{channel}:enrol")
}

/// Claimed while a second-factor code sent moments ago is still fresh, so a
/// repeated request reuses it instead of sending again.
pub fn otp_factor_cooldown(tenant_id: Uuid, flow_id: Uuid, channel: &str, purpose: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:flow:{flow_id}:mfa:{channel}:{purpose}:cooldown")
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

/// Set of live session ids per user (for concurrency limits and sign-out-everywhere).
pub fn user_sessions(tenant_id: Uuid, user_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:user:{user_id}:sessions")
}

/// Pending TOTP enrolment (secret awaiting its first code), bound to a login flow.
pub fn totp_enrolment(tenant_id: Uuid, flow_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:flow:{flow_id}:totp:enrol")
}

/// A TOTP time step already accepted for a credential (replay guard).
pub fn totp_used_step(tenant_id: Uuid, credential_id: Uuid, step: u64) -> String {
    format!("{PREFIX}:t:{tenant_id}:totp:{credential_id}:used:{step}")
}

/// Pending passkey ceremony state (registration or assertion challenge),
/// bound to a login flow (or another scope) and the ceremony kind.
pub fn passkey_ceremony(tenant_id: Uuid, scope: Uuid, kind: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:flow:{scope}:passkey:{kind}")
}

/// Pending email or phone change from the account console: the destination
/// a code went to, awaiting its proof.
pub fn contact_change(tenant_id: Uuid, user_id: Uuid, channel: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:user:{user_id}:contact:{channel}:pending")
}

/// The code proving a pending contact change.
pub fn contact_change_code(tenant_id: Uuid, user_id: Uuid, channel: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:user:{user_id}:contact:{channel}:code")
}

/// Claimed while a contact-change code sent moments ago is still fresh.
pub fn contact_change_cooldown(tenant_id: Uuid, user_id: Uuid, channel: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:user:{user_id}:contact:{channel}:cooldown")
}

/// A pending upstream sign-in or link: the state parameter (hashed) → what
/// the callback continues.
pub fn broker_state(tenant_id: Uuid, state_hash: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:broker:state:{state_hash}")
}

/// A one-time ticket the account console hands the browser to start
/// linking an identity to the signed-in user.
pub fn broker_link_ticket(tenant_id: Uuid, ticket_hash: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:broker:link:{ticket_hash}")
}

/// An upstream provider's JWK set.
pub fn idp_jwks(tenant_id: Uuid, idp_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:idp:{idp_id}:jwks")
}

/// The enabled providers of a tenant, for the login page.
pub fn identity_providers(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:idps")
}

/// A pending device authorization (RFC 8628), by the device code's hash.
pub fn device_code(tenant_id: Uuid, device_hash: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:device:{device_hash}")
}

/// The user code shown on the device → the device code's hash.
pub fn device_user_code(tenant_id: Uuid, user_code: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:device:user:{user_code}")
}

/// Wrong user-code guesses per address.
pub fn device_guesses(tenant_id: Uuid, ip: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:device:guesses:{ip}")
}

/// Claimed while a personal access token's `last_used_at` is fresh enough.
pub fn pat_touched(tenant_id: Uuid, token_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:pat:{token_id}:touched")
}

/// Fixed-window rate-limit counter for one bucket (see `services::rate_limit`).
pub fn rate_limit(bucket: &str) -> String {
    format!("{PREFIX}:rl:{bucket}")
}

/// Union of the CORS origins of a tenant's active clients (the CORS layer's
/// allow list); evicted with every client change.
pub fn client_origins(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:client_origins")
}

/// Every IP rule of a tenant (tenant-wide and per client), evicted on any rule change.
pub fn ip_rules(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:ip_rules")
}

/// A resource server by identifier (the token endpoint's audience lookup).
pub fn resource_server(tenant_id: Uuid, identifier: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:rs:{identifier}")
}

/// Permission names a set of roles holds on a resource server, under the
/// roles version (any grant, role or permission change moves it).
pub fn resource_server_permissions(
    tenant_id: Uuid,
    version: &str,
    rs_id: Uuid,
    roles_key: &str,
) -> String {
    format!("{PREFIX}:t:{tenant_id}:rsperms:{version}:{rs_id}:{roles_key}")
}

/// A user's groups (direct or effective) under the roles version, which
/// every membership change bumps.
pub fn user_groups(tenant_id: Uuid, version: &str, user_id: Uuid, effective: bool) -> String {
    let kind = if effective { "eff" } else { "direct" };
    format!("{PREFIX}:t:{tenant_id}:groups:{version}:{kind}:user:{user_id}")
}

/// Tenant document keyed by its custom domain (the request host).
pub fn tenant_by_host(host: &str) -> String {
    format!("{PREFIX}:tenant:host:{host}")
}
