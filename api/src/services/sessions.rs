//! Browser SSO sessions: server-side in Redis (fast path), referenced by an
//! HttpOnly cookie, mirrored to Postgres for listing, revocation and audit.
//! One session per tenant per browser. Tenant policy sets idle and absolute
//! timeouts and the number of concurrent sessions a user may hold.

use std::time::Duration;

use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use redis::AsyncCommands as _;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::AppResult;
use crate::models::{SessionPolicy, Tenant};
use crate::repos;
use crate::services::refresh_tokens;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SsoSession {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub auth_time: DateTime<Utc>,
    /// Authentication methods used (`pwd`, `otp`, `hwk`, `mfa`, ...).
    pub amr: Vec<String>,
    pub acr: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    /// Trusted device this session was opened from, if any.
    #[serde(default)]
    pub device_id: Option<Uuid>,
    /// Organization this session acts in; the source of the `org_id` claim.
    #[serde(default)]
    pub org_id: Option<Uuid>,
    /// The administrator who opened this session as the user
    /// (impersonation); the source of the `act` claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonator: Option<Impersonator>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    /// Absolute end of life.
    pub expires_at: DateTime<Utc>,
    /// Sliding end of life.
    pub idle_expires_at: DateTime<Utc>,
}

/// The administrator behind an impersonated session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Impersonator {
    pub user_id: Uuid,
    /// The administrator's own tenant (`master` for a global administrator).
    pub tenant_id: Uuid,
    pub username: String,
}

impl SsoSession {
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.expires_at > now && self.idle_expires_at > now
    }
}

/// Cookie name, one per tenant so tenants on one host never share a cookie.
///
/// With `COOKIE_SECURE` the name carries the `__Host-` prefix, which browsers
/// accept only with `Secure`, `Path=/` and no `Domain`: the cookie is pinned
/// to the exact host that set it. The path cannot separate tenants (a
/// `__Host-` cookie must have `Path=/`, and a custom domain serves the tenant
/// without the `/t/{slug}` prefix), so the slug is in the name instead; slugs
/// are `[a-z0-9-]`, all valid cookie-name characters. Plain-http development
/// cannot set `Secure`, so it drops the prefix.
pub fn cookie_name(state: &AppState, slug: &str) -> String {
    tenant_cookie_name(state.config.cookie_secure, "ridm_session", slug)
}

/// `{base}_{slug}`, with the `__Host-` prefix when `secure`.
pub(crate) fn tenant_cookie_name(secure: bool, base: &str, slug: &str) -> String {
    if secure {
        format!("__Host-{base}_{slug}")
    } else {
        format!("{base}_{slug}")
    }
}

/// A `Set-Cookie` value for a host-only, whole-host (`Path=/`), HttpOnly,
/// `SameSite=Lax` cookie; `Secure` when `secure`. Never a `Domain`, which a
/// `__Host-` cookie must not carry.
pub(crate) fn cookie_header(secure: bool, name: &str, value: &str, max_age: i64) -> String {
    let mut v = format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}");
    if secure {
        v.push_str("; Secure");
    }
    v
}

pub fn set_cookie_header(state: &AppState, tenant: &Tenant, session: &SsoSession) -> String {
    let max_age = (session.expires_at - Utc::now()).num_seconds().max(0);
    cookie_header(
        state.config.cookie_secure,
        &cookie_name(state, &tenant.slug),
        &session.id.to_string(),
        max_age,
    )
}

pub fn clear_cookie_header(state: &AppState, tenant: &Tenant) -> String {
    cookie_header(
        state.config.cookie_secure,
        &cookie_name(state, &tenant.slug),
        "",
        0,
    )
}

/// The tenant's session id from the request's `Cookie` header, if present
/// and well formed.
pub fn session_id_from_headers(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
) -> Option<Uuid> {
    let name = cookie_name(state, &tenant.slug);
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|line| line.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .and_then(|(_, v)| Uuid::parse_str(v.trim()).ok())
}

pub struct NewSession<'a> {
    pub user_id: Uuid,
    pub amr: Vec<String>,
    pub acr: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub policy: &'a SessionPolicy,
}

/// Open a session. When the tenant caps concurrent sessions, the user's
/// oldest live sessions are ended first so the cap holds after this one;
/// they end through [`crate::services::logout::end_session`], so their
/// refresh tokens go and their relying parties hear of it (back-channel).
pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    req: NewSession<'_>,
) -> AppResult<SsoSession> {
    let max = usize::try_from(req.policy.max_concurrent).unwrap_or(usize::MAX);
    if max > 0 {
        let live = list_live_for_user(state, tenant_id, req.user_id).await?;
        let excess = (live.len() + 1).saturating_sub(max);
        if excess > 0 {
            let tenant = crate::services::tenants::get(state, tenant_id).await?;
            for old in live.iter().take(excess) {
                crate::services::logout::end_session(state, &tenant, old.id).await?;
            }
        }
    }

    let now = Utc::now();
    let session = SsoSession {
        id: Uuid::now_v7(),
        tenant_id,
        user_id: req.user_id,
        auth_time: now,
        amr: req.amr,
        acr: req.acr,
        ip: req.ip,
        user_agent: req.user_agent,
        device_id: None,
        org_id: None,
        impersonator: None,
        created_at: now,
        last_seen_at: now,
        expires_at: now + chrono::Duration::seconds(req.policy.absolute_timeout_secs as i64),
        idle_expires_at: now + chrono::Duration::seconds(req.policy.idle_timeout_secs as i64),
    };

    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    repos::sessions::insert(&mut *tx, &session, None).await?;
    tx.commit().await?;
    store(state, &session).await?;
    track(state, &session).await?;

    state.events.publish(Event::new(
        Some(tenant_id),
        Actor::User { id: req.user_id },
        EventKind::SessionCreated {
            session_id: session.id,
            user_id: req.user_id,
        },
    ));
    metrics::counter!("ridm_sessions_created_total").increment(1);
    Ok(session)
}

pub struct NewImpersonatedSession<'a> {
    pub user_id: Uuid,
    pub impersonator: Impersonator,
    pub reason: &'a str,
    pub lifetime: chrono::Duration,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

/// Open a session as the user on behalf of an administrator. It lives for
/// `lifetime` at most (never past the tenant's absolute timeout), does not
/// count against the user's concurrent-session cap — opening it never signs
/// the user out anywhere — and carries no authentication method: nothing the
/// user proved went into it.
pub async fn create_impersonated(
    state: &AppState,
    tenant: &Tenant,
    req: NewImpersonatedSession<'_>,
) -> AppResult<SsoSession> {
    let policy = &tenant.settings.session;
    let now = Utc::now();
    let expires_at = now
        + req.lifetime.min(chrono::Duration::seconds(
            policy.absolute_timeout_secs as i64,
        ));
    let session = SsoSession {
        id: Uuid::now_v7(),
        tenant_id: tenant.id,
        user_id: req.user_id,
        auth_time: now,
        amr: vec![],
        acr: None,
        ip: req.ip,
        user_agent: req.user_agent,
        device_id: None,
        org_id: None,
        impersonator: Some(req.impersonator),
        created_at: now,
        last_seen_at: now,
        expires_at,
        idle_expires_at: (now + chrono::Duration::seconds(policy.idle_timeout_secs as i64))
            .min(expires_at),
    };
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    repos::sessions::insert(&mut *tx, &session, None).await?;
    if let Some(imp) = &session.impersonator {
        repos::sessions::set_impersonation(&mut *tx, tenant.id, session.id, imp, req.reason)
            .await?;
    }
    tx.commit().await?;
    store(state, &session).await?;
    track(state, &session).await?;
    metrics::counter!("ridm_sessions_created_total").increment(1);
    Ok(session)
}

async fn store(state: &AppState, session: &SsoSession) -> AppResult<()> {
    // Millisecond precision so a short policy window is never rounded away.
    let ttl_ms = (session.expires_at.min(session.idle_expires_at) - Utc::now()).num_milliseconds();
    if ttl_ms <= 0 {
        return Ok(());
    }
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .pset_ex(
            keys::sso_session(session.tenant_id, session.id),
            serde_json::to_string(session)?,
            ttl_ms as u64,
        )
        .await?;
    Ok(())
}

/// Add the session to its user's live-session set. The set outlives its
/// members (absolute timeout) and is pruned on read.
async fn track(state: &AppState, session: &SsoSession) -> AppResult<()> {
    let key = keys::user_sessions(session.tenant_id, session.user_id);
    let ttl = (session.expires_at - Utc::now()).num_seconds().max(60);
    let mut conn = state.redis.get().await?;
    let _: () = conn.sadd(&key, session.id.to_string()).await?;
    // Never shorten the set's life below a member's remaining lifetime.
    let current: i64 = conn.ttl(&key).await?;
    if current < ttl {
        let _: () = conn.expire(&key, ttl).await?;
    }
    Ok(())
}

async fn untrack(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    session_id: Uuid,
) -> AppResult<()> {
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .srem(
            keys::user_sessions(tenant_id, user_id),
            session_id.to_string(),
        )
        .await?;
    Ok(())
}

/// Load a live session. Touches the idle timer (`policy` supplies the window).
pub async fn get(
    state: &AppState,
    tenant_id: Uuid,
    session_id: Uuid,
    policy: &SessionPolicy,
) -> AppResult<Option<SsoSession>> {
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = conn.get(keys::sso_session(tenant_id, session_id)).await?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let mut session: SsoSession = match serde_json::from_str(&raw) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let now = Utc::now();
    if !session.is_live(now) {
        return Ok(None);
    }
    // Slide the idle window at most once a minute to keep writes cheap.
    if (now - session.last_seen_at).num_seconds() >= 60 {
        session.last_seen_at = now;
        session.idle_expires_at = (now
            + chrono::Duration::seconds(policy.idle_timeout_secs as i64))
        .min(session.expires_at);
        store(state, &session).await?;
        mirror_touch(state, &session).await?;
    }
    Ok(Some(session))
}

/// Session for the current request, from the cookie.
pub async fn from_request(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
) -> AppResult<Option<SsoSession>> {
    let Some(id) = session_id_from_headers(state, tenant, headers) else {
        return Ok(None);
    };
    let session = get(state, tenant.id, id, &tenant.settings.session).await?;
    // What this request goes on to do, it does for the administrator.
    if let Some(imp) = session.as_ref().and_then(|s| s.impersonator.as_ref()) {
        ridm_core::events::acting::set(imp.user_id);
    }
    Ok(session)
}

async fn mirror_touch(state: &AppState, session: &SsoSession) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, session.tenant_id).await?;
    repos::sessions::touch(&mut *tx, session).await?;
    tx.commit().await?;
    Ok(())
}

/// Record a fresh authentication on an existing session (step-up, re-login).
pub async fn refresh_auth(
    state: &AppState,
    session: &mut SsoSession,
    amr: Vec<String>,
    acr: Option<String>,
) -> AppResult<()> {
    session.auth_time = Utc::now();
    session.amr = amr;
    session.acr = acr;
    store(state, session).await?;
    mirror_touch(state, session).await
}

/// Record the organization this session acts in. Tokens issued through the
/// session carry it as `org_id`.
pub async fn bind_organization(
    state: &AppState,
    session: &mut SsoSession,
    org_id: Uuid,
) -> AppResult<()> {
    if session.org_id == Some(org_id) {
        return Ok(());
    }
    session.org_id = Some(org_id);
    store(state, session).await?;
    let mut tx = db::tenant_tx(&state.db, session.tenant_id).await?;
    repos::sessions::set_organization(&mut *tx, session.tenant_id, session.id, org_id).await?;
    tx.commit().await?;
    Ok(())
}

/// Attach the trusted device the browser presented (or just registered).
pub async fn bind_device(
    state: &AppState,
    session: &mut SsoSession,
    device_id: Uuid,
) -> AppResult<()> {
    session.device_id = Some(device_id);
    store(state, session).await?;
    let mut tx = db::tenant_tx(&state.db, session.tenant_id).await?;
    repos::sessions::set_device(&mut *tx, session.tenant_id, session.id, device_id).await?;
    tx.commit().await?;
    Ok(())
}

/// End one session and the refresh tokens issued in it (offline ones
/// included: they belong to the sign-in that was just ended). Returns whether
/// the session was live. Relying parties are told by
/// [`crate::services::logout::end_session`], which callers outside this
/// module use.
pub async fn revoke(state: &AppState, tenant_id: Uuid, session_id: Uuid) -> AppResult<bool> {
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = conn.get(keys::sso_session(tenant_id, session_id)).await?;
    let removed: i64 = conn.del(keys::sso_session(tenant_id, session_id)).await?;
    drop(conn);
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    repos::sessions::mark_revoked(&mut *tx, tenant_id, session_id).await?;
    tx.commit().await?;
    let ended = raw.and_then(|raw| serde_json::from_str::<SsoSession>(&raw).ok());
    let owner = ended.as_ref().map(|s| s.user_id);
    if let Some(s) = ended.as_ref().filter(|_| removed > 0) {
        crate::services::impersonation::announce_end(state, s);
    }
    if let Some(user_id) = owner {
        untrack(state, tenant_id, user_id, session_id).await?;
        state.events.publish(Event::new(
            Some(tenant_id),
            Actor::User { id: user_id },
            EventKind::SessionRevoked {
                session_id,
                user_id,
            },
        ));
    }
    let actor = owner.map_or(Actor::System, |id| Actor::User { id });
    refresh_tokens::revoke_for_session(state, tenant_id, actor, session_id).await?;
    Ok(removed > 0)
}

/// Live sessions of a user, oldest first. Prunes ids whose session expired.
pub async fn list_live_for_user(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<SsoSession>> {
    let set_key = keys::user_sessions(tenant_id, user_id);
    let mut conn = state.redis.get().await?;
    let ids: Vec<String> = conn.smembers(&set_key).await?;
    if ids.is_empty() {
        return Ok(vec![]);
    }
    let session_keys: Vec<String> = ids
        .iter()
        .filter_map(|id| Uuid::parse_str(id).ok())
        .map(|id| keys::sso_session(tenant_id, id))
        .collect();
    let raws: Vec<Option<String>> = redis::cmd("MGET")
        .arg(&session_keys)
        .query_async(&mut conn)
        .await?;
    let now = Utc::now();
    let mut live = Vec::with_capacity(raws.len());
    let mut stale: Vec<String> = vec![];
    for (id, raw) in ids.iter().zip(raws) {
        match raw.and_then(|r| serde_json::from_str::<SsoSession>(&r).ok()) {
            Some(s) if s.is_live(now) && s.user_id == user_id => live.push(s),
            _ => stale.push(id.clone()),
        }
    }
    if !stale.is_empty() {
        let _: () = conn.srem(&set_key, stale).await?;
    }
    live.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    Ok(live)
}

/// Redis TTL helper for callers that need the remaining lifetime.
pub fn remaining(session: &SsoSession) -> Duration {
    let secs = (session.expires_at.min(session.idle_expires_at) - Utc::now())
        .num_seconds()
        .max(0);
    Duration::from_secs(secs as u64)
}

/// Remember that `client_id` (public id) took part in this session.
pub async fn add_client(state: &AppState, session: &SsoSession, client_id: &str) -> AppResult<()> {
    let key = keys::session_clients(session.tenant_id, session.id);
    let mut conn = state.redis.get().await?;
    let _: () = conn.sadd(&key, client_id).await?;
    let ttl = remaining(session).as_secs().max(60);
    let _: () = conn.expire(&key, ttl as i64).await?;
    Ok(())
}

pub async fn clients_of(
    state: &AppState,
    tenant_id: Uuid,
    session_id: Uuid,
) -> AppResult<Vec<String>> {
    let mut conn = state.redis.get().await?;
    Ok(conn
        .smembers(keys::session_clients(tenant_id, session_id))
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_cookies_meet_the_host_prefix_rules() {
        let name = tenant_cookie_name(true, "ridm_session", "acme");
        assert_eq!(name, "__Host-ridm_session_acme");
        let v = cookie_header(true, &name, "abc", 3600);
        assert!(v.starts_with("__Host-ridm_session_acme=abc;"), "{v}");
        // Browsers drop a `__Host-` cookie unless it is Secure, has Path=/
        // and carries no Domain.
        let attrs: Vec<&str> = v.split(';').map(str::trim).skip(1).collect();
        assert!(attrs.contains(&"Path=/"), "{v}");
        assert!(attrs.contains(&"Secure"), "{v}");
        assert!(attrs.contains(&"HttpOnly"), "{v}");
        assert!(
            !attrs
                .iter()
                .any(|a| a.to_ascii_lowercase().starts_with("domain")),
            "{v}"
        );
        assert_eq!(attrs.iter().filter(|a| a.starts_with("Path=")).count(), 1);
    }

    #[test]
    fn plain_http_cookies_drop_the_prefix_but_stay_per_tenant() {
        let a = tenant_cookie_name(false, "ridm_device", "acme");
        let b = tenant_cookie_name(false, "ridm_device", "globex");
        assert_eq!(a, "ridm_device_acme");
        assert_ne!(a, b);
        let v = cookie_header(false, &a, "", 0);
        assert_eq!(
            v,
            "ridm_device_acme=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
        );
    }
}
