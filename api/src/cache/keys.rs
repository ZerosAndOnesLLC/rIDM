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

/// Effective roles of a user in one organization context (`None` = unscoped
/// grants only), under the tenant's roles version.
pub fn effective_roles(
    tenant_id: Uuid,
    version: &str,
    user_id: Uuid,
    org_id: Option<Uuid>,
) -> String {
    match org_id {
        Some(org) => format!("{PREFIX}:t:{tenant_id}:roles:{version}:user:{user_id}:org:{org}"),
        None => format!("{PREFIX}:t:{tenant_id}:roles:{version}:user:{user_id}"),
    }
}

/// Effective roles of a user ignoring org scoping (every grant counts).
pub fn effective_roles_anywhere(tenant_id: Uuid, version: &str, user_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:roles:{version}:user:{user_id}:org:any")
}

/// Admin permissions of a user, derived from effective roles (same version
/// token). The organization the caller acts in is part of the key: a grant
/// scoped to one organization must not be served to a session in another.
pub fn admin_permissions(
    tenant_id: Uuid,
    version: &str,
    user_id: Uuid,
    org: Option<String>,
) -> String {
    match org {
        Some(org) => {
            format!("{PREFIX}:t:{tenant_id}:admin_perms:{version}:user:{user_id}:org:{org}")
        }
        None => format!("{PREFIX}:t:{tenant_id}:admin_perms:{version}:user:{user_id}"),
    }
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

/// A tenant's published keys parsed for verification, under the keys
/// version (L1 only).
pub fn verification_keys(tenant_id: Uuid, version: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:verify_keys:{version}")
}

/// The key signing a tenant's tokens for one algorithm, under the keys
/// version (L1 only: it carries the encrypted private half).
pub fn active_signing_key(tenant_id: Uuid, alg: &str, version: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:active_key:{alg}:{version}")
}

/// A user row (L1 only: it carries the password hash).
pub fn user(tenant_id: Uuid, user_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:user:{user_id}")
}

/// Parsed signing key material (L1 only; never written to Redis).
pub fn signing_key_material(key_id: Uuid) -> String {
    format!("{PREFIX}:signing_key:{key_id}:material")
}

/// The tenant's SAML signing keys (public views).
pub fn saml_keys(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:saml:keys")
}

/// A SAML signing key's decrypted signer (L1 only).
pub fn saml_key_material(key_id: Uuid) -> String {
    format!("{PREFIX}:saml_key:{key_id}:material")
}

/// A SAML service provider by its client's row id.
pub fn saml_sp(tenant_id: Uuid, client_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:saml:sp:{client_id}")
}

/// A SAML service provider by entity ID. Entity IDs are URLs of any
/// length, so the key holds their SHA-256.
pub fn saml_sp_by_entity(tenant_id: Uuid, entity_id: &str) -> String {
    use sha2::Digest as _;
    let h = sha2::Sha256::digest(entity_id.as_bytes());
    format!("{PREFIX}:t:{tenant_id}:saml:entity:{}", hex::encode(h))
}

/// Denylisted access-token `jti` (instant revocation before expiry).
pub fn jti_denied(tenant_id: Uuid, jti: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:jti:{jti}")
}

/// The tenant of an opaque access token, by the SHA-256 of the token. Not
/// tenant-scoped: the admin and account APIs learn the tenant from the entry
/// (tokens issued by earlier releases kept their claims here).
pub fn opaque_access_token(token_hash: &str) -> String {
    format!("{PREFIX}:at:{token_hash}")
}

/// The claims of an opaque access token, in its tenant's region; the
/// deployment-wide [`opaque_access_token`] entry then only names the tenant.
pub fn opaque_access_token_claims(tenant_id: Uuid, token_hash: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:at:{token_hash}")
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

/// A one-time ticket that opens an impersonated session in the browser that
/// presents it.
pub fn impersonation_ticket(tenant_id: Uuid, ticket_hash: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:impersonate:{ticket_hash}")
}

/// The browser's own session an impersonated session replaced, put back
/// when the impersonation ends.
pub fn impersonation_restore(tenant_id: Uuid, session_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:session:{session_id}:restore")
}

/// An upstream provider's JWK set.
pub fn idp_jwks(tenant_id: Uuid, idp_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:idp:{idp_id}:jwks")
}

/// The enabled providers of a tenant, for the login page.
pub fn identity_providers(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:idps")
}

/// The ids of a tenant's enabled LDAP directories, for the password step.
/// Every identity provider of a tenant with its details, for the sign-in
/// paths (L1 only: the rows carry encrypted secrets).
pub fn identity_providers_full(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:idps:full")
}

pub fn ldap_directories(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:idps:ldap")
}

/// A tenant's enabled Kerberos providers, for the login page's Negotiate
/// step.
pub fn kerberos_realms(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:idps:kerberos")
}

/// A Kerberos authenticator already accepted (the replay cache), by the
/// hash of its ciphertext.
pub fn kerberos_replay(tenant_id: Uuid, hash: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:krb:replay:{hash}")
}

/// A pending device authorization (RFC 8628), by the device code's hash.
pub fn device_code(tenant_id: Uuid, device_hash: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:device:{device_hash}")
}

/// A live backchannel authentication request (CIBA), by the hash of its
/// `auth_req_id`.
pub fn ciba_request(tenant_id: Uuid, auth_req_hash: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:ciba:{auth_req_hash}")
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
/// A personal access token's record by the hash of the token (the token
/// names no tenant, so this is deployment-wide; evicted on revocation).
pub fn pat_by_hash(token_hash: &[u8]) -> String {
    format!("{PREFIX}:pat:{}", hex::encode(token_hash))
}

pub fn pat_touched(tenant_id: Uuid, token_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:pat:{token_id}:touched")
}

/// Fixed-window rate-limit counter for one deployment-wide bucket (see
/// `services::rate_limit`).
pub fn rate_limit(bucket: &str) -> String {
    format!("{PREFIX}:rl:{bucket}")
}

/// A tenant's own rate-limit counter: under the tenant's prefix, so it lives
/// in the tenant's region with the addresses it counts.
pub fn tenant_rate_limit(tenant_id: Uuid, bucket: &str) -> String {
    format!("{PREFIX}:t:{tenant_id}:rl:{bucket}")
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

/// The tenant's certificate authorities for `tls_client_auth` clients.
pub fn mtls_trust_anchors(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:mtls_trust_anchors")
}

/// The client-certificate verifier built from a tenant's trust anchors (L1
/// only; evicted with the anchors).
pub fn mtls_verifier(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:mtls_verifier")
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

/// Organizations a user belongs to, under the roles version (membership
/// changes bump it, as org-scoped role grants hang off the same graph).
pub fn user_organizations(tenant_id: Uuid, version: &str, user_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:orgs:{version}:user:{user_id}")
}

/// Tenant document keyed by its custom domain (the request host).
pub fn tenant_by_host(host: &str) -> String {
    format!("{PREFIX}:tenant:host:{host}")
}

/// A tenant's message template overrides (evicted by every change to one).
pub fn message_templates(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:message_templates")
}

/// Version token of one user's memberships and direct grants: moved by a
/// change to what that user alone holds, where the tenant's roles version
/// would orphan every user's cached access.
pub fn user_access_version(tenant_id: Uuid, user_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:user:{user_id}:access_version")
}

/// One organization (evicted by every change to it).
pub fn organization(tenant_id: Uuid, org_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:org:{org_id}")
}

/// The e-mail domains at which a verified address joins an organization on
/// sign-in (evicted by every change to an organization or a domain).
pub fn org_auto_join_domains(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:org_auto_join")
}

/// A tenant's dashboard statistics over `days` (cached a minute).
pub fn tenant_stats(tenant_id: Uuid, days: u32) -> String {
    format!("{PREFIX}:t:{tenant_id}:stats:{days}")
}

/// A tenant's user counts for the dashboard (cached ten minutes).
pub fn tenant_user_counts(tenant_id: Uuid) -> String {
    format!("{PREFIX}:t:{tenant_id}:stats:users")
}
