//! "Remember this device": a long-lived cookie whose secret is stored hashed;
//! a trusted device may skip the second factor (Phase 7).

use axum::http::HeaderMap;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::db;
use crate::error::AppResult;
use crate::models::{Tenant, TrustedDevice};
use crate::repos;
use crate::services::sessions;
use crate::state::AppState;

fn hash(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

/// Cookie name, one per tenant, `__Host-`-prefixed when cookies are secure:
/// the same rules as [`crate::services::sessions::cookie_name`].
pub fn cookie_name(state: &AppState, slug: &str) -> String {
    sessions::tenant_cookie_name(state.config.cookie_secure, "ridm_device", slug)
}

pub fn set_cookie_header(state: &AppState, tenant: &Tenant, secret: &str, days: u32) -> String {
    sessions::cookie_header(
        state.config.cookie_secure,
        &cookie_name(state, &tenant.slug),
        secret,
        i64::from(days) * 86_400,
    )
}

pub fn clear_cookie_header(state: &AppState, tenant: &Tenant) -> String {
    sessions::cookie_header(
        state.config.cookie_secure,
        &cookie_name(state, &tenant.slug),
        "",
        0,
    )
}

pub fn secret_from_headers(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
) -> Option<String> {
    let name = cookie_name(state, &tenant.slug);
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|line| line.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim().to_string())
        .filter(|v| !v.is_empty() && v.len() <= 128)
}

/// Register the current browser as trusted; returns the device and the cookie secret.
pub async fn trust(
    state: &AppState,
    tenant: &Tenant,
    user_id: Uuid,
    name: Option<&str>,
    user_agent: Option<&str>,
    ip: Option<&str>,
) -> AppResult<(TrustedDevice, String)> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let secret = URL_SAFE_NO_PAD.encode(bytes);
    let days = tenant.settings.session.remember_device_days.max(1);
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    let device = repos::trusted_devices::insert(
        &mut *tx,
        tenant.id,
        Uuid::now_v7(),
        user_id,
        &hash(&secret),
        name,
        user_agent,
        ip,
        Utc::now() + Duration::days(i64::from(days)),
    )
    .await?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tenant.id),
        Actor::User { id: user_id },
        EventKind::TrustedDeviceAdded {
            user_id,
            device_id: device.id,
        },
    ));
    Ok((device, secret))
}

/// Is the request's device cookie a live trusted device of `user_id`?
pub async fn is_trusted(
    state: &AppState,
    tenant: &Tenant,
    user_id: Uuid,
    headers: &HeaderMap,
    ip: Option<&str>,
) -> AppResult<Option<TrustedDevice>> {
    let Some(secret) = secret_from_headers(state, tenant, headers) else {
        return Ok(None);
    };
    verify_secret(state, tenant, user_id, &secret, ip).await
}

/// Resolve a cookie secret to a live trusted device of `user_id`, touching
/// its last-seen time and IP.
pub async fn verify_secret(
    state: &AppState,
    tenant: &Tenant,
    user_id: Uuid,
    secret: &str,
    ip: Option<&str>,
) -> AppResult<Option<TrustedDevice>> {
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    let device = repos::trusted_devices::find_by_hash(&mut *tx, tenant.id, &hash(secret))
        .await?
        .filter(|d| d.user_id == user_id && d.is_live(Utc::now()));
    if let Some(d) = &device {
        repos::trusted_devices::touch(&mut *tx, tenant.id, d.id, ip).await?;
    }
    tx.commit().await?;
    Ok(device)
}

pub async fn list(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<TrustedDevice>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::trusted_devices::list_for_user(&mut *tx, tenant_id, user_id).await?;
    tx.commit().await?;
    Ok(rows)
}

pub async fn revoke(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    user_id: Uuid,
    device_id: Uuid,
) -> AppResult<bool> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::trusted_devices::revoke(&mut *tx, tenant_id, user_id, device_id).await?;
    tx.commit().await?;
    if ok {
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::TrustedDeviceRevoked { user_id, device_id },
        ));
    }
    Ok(ok)
}

pub async fn revoke_all(state: &AppState, tenant_id: Uuid, user_id: Uuid) -> AppResult<u64> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let n = repos::trusted_devices::revoke_all(&mut *tx, tenant_id, user_id).await?;
    tx.commit().await?;
    Ok(n)
}
