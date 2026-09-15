//! Browser SSO sessions: server-side in Redis, referenced by an HttpOnly
//! cookie. One session per tenant per browser.

use std::time::Duration;

use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use redis::AsyncCommands as _;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cache::keys;
use crate::error::AppResult;
use crate::models::{SessionPolicy, Tenant};
use crate::state::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    /// Absolute end of life.
    pub expires_at: DateTime<Utc>,
    /// Sliding end of life.
    pub idle_expires_at: DateTime<Utc>,
}

impl SsoSession {
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.expires_at > now && self.idle_expires_at > now
    }
}

/// Cookie name. `__Host-` requires `Secure`, which plain-http dev cannot set.
pub fn cookie_name(state: &AppState) -> &'static str {
    if state.config.cookie_secure {
        "__Host-ridm_session"
    } else {
        "ridm_session"
    }
}

/// Session cookies are scoped to the tenant path so tenants never share one.
pub fn cookie_path(tenant: &Tenant) -> String {
    format!("/t/{}", tenant.slug)
}

pub fn set_cookie_header(state: &AppState, tenant: &Tenant, session: &SsoSession) -> String {
    let max_age = (session.expires_at - Utc::now()).num_seconds().max(0);
    let mut v = format!(
        "{}={}; Path={}; HttpOnly; SameSite=Lax; Max-Age={max_age}",
        cookie_name(state),
        session.id,
        cookie_path(tenant)
    );
    if state.config.cookie_secure {
        v.push_str("; Secure");
    }
    v
}

pub fn clear_cookie_header(state: &AppState, tenant: &Tenant) -> String {
    let mut v = format!(
        "{}=; Path={}; HttpOnly; SameSite=Lax; Max-Age=0",
        cookie_name(state),
        cookie_path(tenant)
    );
    if state.config.cookie_secure {
        v.push_str("; Secure");
    }
    v
}

/// Session id from the request's `Cookie` header, if present and well formed.
pub fn session_id_from_headers(state: &AppState, headers: &HeaderMap) -> Option<Uuid> {
    let name = cookie_name(state);
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

pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    req: NewSession<'_>,
) -> AppResult<SsoSession> {
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
        created_at: now,
        last_seen_at: now,
        expires_at: now + chrono::Duration::seconds(req.policy.absolute_timeout_secs as i64),
        idle_expires_at: now + chrono::Duration::seconds(req.policy.idle_timeout_secs as i64),
    };
    store(state, &session).await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        Actor::User { id: req.user_id },
        EventKind::SessionCreated {
            session_id: session.id,
            user_id: req.user_id,
        },
    ));
    Ok(session)
}

async fn store(state: &AppState, session: &SsoSession) -> AppResult<()> {
    let ttl = (session.expires_at.min(session.idle_expires_at) - Utc::now()).num_seconds();
    if ttl <= 0 {
        return Ok(());
    }
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(
            keys::sso_session(session.tenant_id, session.id),
            serde_json::to_string(session)?,
            ttl as u64,
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
    }
    Ok(Some(session))
}

/// Session for the current request, from the cookie.
pub async fn from_request(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
) -> AppResult<Option<SsoSession>> {
    let Some(id) = session_id_from_headers(state, headers) else {
        return Ok(None);
    };
    get(state, tenant.id, id, &tenant.settings.session).await
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
    store(state, session).await
}

pub async fn revoke(state: &AppState, tenant_id: Uuid, session_id: Uuid) -> AppResult<bool> {
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = conn.get(keys::sso_session(tenant_id, session_id)).await?;
    let removed: i64 = conn.del(keys::sso_session(tenant_id, session_id)).await?;
    if let Some(raw) = raw
        && let Ok(s) = serde_json::from_str::<SsoSession>(&raw)
    {
        state.events.publish(Event::new(
            Some(tenant_id),
            Actor::User { id: s.user_id },
            EventKind::SessionRevoked {
                session_id,
                user_id: s.user_id,
            },
        ));
    }
    Ok(removed > 0)
}

/// Redis TTL helper for callers that need the remaining lifetime.
pub fn remaining(session: &SsoSession) -> Duration {
    let secs = (session.expires_at.min(session.idle_expires_at) - Utc::now())
        .num_seconds()
        .max(0);
    Duration::from_secs(secs as u64)
}
