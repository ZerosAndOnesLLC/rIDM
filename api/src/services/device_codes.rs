//! Device authorization grant (RFC 8628): the codes an input-constrained
//! device polls with while the user approves the request on another
//! device.
//!
//! A pending code lives in Valkey with everything the token endpoint must
//! check; the user code (eight letters from an alphabet without look-alikes,
//! shown as `XXXX-XXXX`) points at it. Approval or denial rewrites the
//! record in place; the device's next poll takes it (once). Guesses at user
//! codes are rate-limited per address, and polling faster than the interval
//! earns `slow_down` and a longer interval. Every code leaves an audit row.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use redis::AsyncCommands as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::middleware::TenantCtx;
use crate::models::Client;
use crate::repos;
use crate::services::sessions::SsoSession;
use crate::state::AppState;

/// How long the user has to approve.
pub const DEVICE_CODE_TTL_SECS: u64 = 10 * 60;
/// Seconds between polls the device must respect.
pub const INTERVAL_SECS: u64 = 5;
/// Added to the interval on every `slow_down`.
const SLOW_DOWN_STEP_SECS: u64 = 5;
/// Letters that are hard to confuse with one another or with digits.
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
const USER_CODE_LEN: usize = 8;
/// Wrong user codes one address may try per window.
const GUESS_LIMIT: i64 = 10;
const GUESS_WINDOW_SECS: u64 = 10 * 60;

/// The user said yes: the session that did, and the scopes they granted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub auth_time: DateTime<Utc>,
    pub amr: Vec<String>,
    pub acr: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Status {
    Pending,
    Approved(Approval),
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// The audit row.
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: Uuid,
    pub client_public_id: String,
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
    pub user_code: String,
    pub interval_secs: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: Status,
    pub last_poll_at: Option<DateTime<Utc>>,
}

impl DeviceRecord {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

/// The device authorization response (RFC 8628 §3.2).
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

fn hash(code: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code.as_bytes()))
}

fn random_user_code() -> String {
    let letters: String = (0..USER_CODE_LEN)
        .map(|_| USER_CODE_ALPHABET[rand::random_range(0..USER_CODE_ALPHABET.len())] as char)
        .collect();
    format!("{}-{}", &letters[..4], &letters[4..])
}

/// `bcdf-ghjk`, `BCDF GHJK` or `BCDFGHJK` → `BCDF-GHJK`; `None` when it
/// cannot be a user code.
pub fn normalize_user_code(raw: &str) -> Option<String> {
    let letters: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if letters.len() != USER_CODE_LEN || !letters.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)) {
        return None;
    }
    Some(format!("{}-{}", &letters[..4], &letters[4..]))
}

async fn store(state: &AppState, key: &str, rec: &DeviceRecord, keep_ttl: bool) -> AppResult<()> {
    let mut conn = state.redis.get().await?;
    let raw = serde_json::to_string(rec)?;
    if keep_ttl {
        let _: () = redis::cmd("SET")
            .arg(key)
            .arg(raw)
            .arg("KEEPTTL")
            .query_async(&mut conn)
            .await?;
    } else {
        let _: () = conn.set_ex(key, raw, DEVICE_CODE_TTL_SECS).await?;
    }
    Ok(())
}

async fn load(state: &AppState, key: &str) -> AppResult<Option<DeviceRecord>> {
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = conn.get(key).await?;
    Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
}

/// Mint a device code and its user code for `client`.
pub async fn issue(
    state: &AppState,
    tenant: &TenantCtx,
    client: &Client,
    scopes: Vec<String>,
    audiences: Vec<String>,
) -> AppResult<DeviceAuthorization> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let device_code = URL_SAFE_NO_PAD.encode(bytes);
    let device_hash = hash(&device_code);
    let mut conn = state.redis.get().await?;
    // A user code in use by another pending request is never handed out twice.
    let mut user_code = random_user_code();
    for _ in 0..8 {
        let claimed: Option<String> = redis::cmd("SET")
            .arg(keys::device_user_code(tenant.id(), &user_code))
            .arg(&device_hash)
            .arg("NX")
            .arg("EX")
            .arg(DEVICE_CODE_TTL_SECS)
            .query_async(&mut conn)
            .await?;
        if claimed.is_some() {
            break;
        }
        user_code = random_user_code();
    }
    drop(conn);
    let now = Utc::now();
    let rec = DeviceRecord {
        id: Uuid::now_v7(),
        tenant_id: tenant.id(),
        client_id: client.id,
        client_public_id: client.client_id.clone(),
        scopes: scopes.clone(),
        audiences,
        user_code: user_code.clone(),
        interval_secs: INTERVAL_SECS,
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(DEVICE_CODE_TTL_SECS as i64),
        status: Status::Pending,
        last_poll_at: None,
    };
    store(
        state,
        &keys::device_code(tenant.id(), &device_hash),
        &rec,
        false,
    )
    .await?;
    let mut tx = db::tenant_tx(&state.db, tenant.id()).await?;
    repos::device_codes::insert(
        &mut *tx,
        tenant.id(),
        rec.id,
        client.id,
        &user_code,
        &scopes,
    )
    .await?;
    tx.commit().await?;
    let verification_uri = state.config.ui_page("device", &[("tenant", tenant.slug())]);
    let verification_uri_complete = state.config.ui_page(
        "device",
        &[("tenant", tenant.slug()), ("user_code", &user_code)],
    );
    Ok(DeviceAuthorization {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in: DEVICE_CODE_TTL_SECS,
        interval: INTERVAL_SECS,
    })
}

/// The pending request behind a user code, for the approval page. Wrong
/// guesses count against the address; an unknown, decided or expired code
/// is `None`.
pub async fn find_by_user_code(
    state: &AppState,
    tenant_id: Uuid,
    raw: &str,
    ip: Option<&str>,
) -> AppResult<Option<(String, DeviceRecord)>> {
    let guess_key = keys::device_guesses(tenant_id, ip.unwrap_or("unknown"));
    let mut conn = state.redis.get().await?;
    let guesses: i64 = conn.incr(&guess_key, 1).await?;
    if guesses == 1 {
        let _: () = conn.expire(&guess_key, GUESS_WINDOW_SECS as i64).await?;
    }
    if guesses > GUESS_LIMIT {
        return Err(AppError::RateLimited {
            retry_after_secs: GUESS_WINDOW_SECS,
        });
    }
    let Some(code) = normalize_user_code(raw) else {
        return Ok(None);
    };
    let device_hash: Option<String> = conn.get(keys::device_user_code(tenant_id, &code)).await?;
    drop(conn);
    let Some(device_hash) = device_hash else {
        return Ok(None);
    };
    let rec = load(state, &keys::device_code(tenant_id, &device_hash)).await?;
    Ok(rec
        .filter(|r| matches!(r.status, Status::Pending) && !r.is_expired(Utc::now()))
        .map(|r| (device_hash, r)))
}

/// The user approved the request from `session` with `scopes`.
pub async fn approve(
    state: &AppState,
    tenant_id: Uuid,
    device_hash: &str,
    session: &SsoSession,
    scopes: &[String],
) -> AppResult<DeviceRecord> {
    let key = keys::device_code(tenant_id, device_hash);
    let mut rec = load(state, &key)
        .await?
        .filter(|r| matches!(r.status, Status::Pending) && !r.is_expired(Utc::now()))
        .ok_or(AppError::NotFound("device code"))?;
    rec.status = Status::Approved(Approval {
        user_id: session.user_id,
        session_id: session.id,
        auth_time: session.auth_time,
        amr: session.amr.clone(),
        acr: session.acr.clone(),
        scopes: scopes.to_vec(),
    });
    store(state, &key, &rec, true).await?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    repos::device_codes::decide(
        &mut *tx,
        tenant_id,
        rec.id,
        "approved",
        Some(session.user_id),
    )
    .await?;
    tx.commit().await?;
    Ok(rec)
}

/// The user denied the request (or cancelled the sign-in).
pub async fn deny(state: &AppState, tenant_id: Uuid, device_hash: &str) -> AppResult<()> {
    let key = keys::device_code(tenant_id, device_hash);
    let Some(mut rec) = load(state, &key)
        .await?
        .filter(|r| matches!(r.status, Status::Pending))
    else {
        return Ok(());
    };
    rec.status = Status::Denied;
    store(state, &key, &rec, true).await?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    repos::device_codes::decide(&mut *tx, tenant_id, rec.id, "denied", None).await?;
    tx.commit().await?;
    Ok(())
}

/// What the token endpoint tells the device.
pub enum Poll {
    /// Tokens follow; the code is spent.
    Approved(Box<DeviceRecord>, Approval),
    Pending,
    /// Polled before the interval passed; the interval grew.
    SlowDown,
    Denied,
    Expired,
}

/// One poll by `client_id` with `device_code`. `None` is a code that does
/// not exist (or belongs to another client).
pub async fn poll(
    state: &AppState,
    tenant_id: Uuid,
    client_id: Uuid,
    device_code: &str,
) -> AppResult<Option<Poll>> {
    if device_code.is_empty() || device_code.len() > 128 {
        return Ok(None);
    }
    let device_hash = hash(device_code);
    let key = keys::device_code(tenant_id, &device_hash);
    let Some(mut rec) = load(state, &key).await? else {
        return Ok(None);
    };
    if rec.client_id != client_id {
        return Ok(None);
    }
    let now = Utc::now();
    let mut conn = state.redis.get().await?;
    let user_key = |rec: &DeviceRecord| keys::device_user_code(tenant_id, &rec.user_code);
    if rec.is_expired(now) {
        let _: () = conn.del(&[key.clone(), user_key(&rec)]).await?;
        return Ok(Some(Poll::Expired));
    }
    if let Some(last) = rec.last_poll_at
        && (now - last).num_seconds() < rec.interval_secs as i64
    {
        rec.interval_secs += SLOW_DOWN_STEP_SECS;
        rec.last_poll_at = Some(now);
        drop(conn);
        store(state, &key, &rec, true).await?;
        return Ok(Some(Poll::SlowDown));
    }
    match rec.status.clone() {
        Status::Pending => {
            rec.last_poll_at = Some(now);
            drop(conn);
            store(state, &key, &rec, true).await?;
            Ok(Some(Poll::Pending))
        }
        Status::Denied => {
            let _: () = conn.del(&[key.clone(), user_key(&rec)]).await?;
            Ok(Some(Poll::Denied))
        }
        Status::Approved(a) => {
            // Spent by the first poll that sees the approval.
            let taken: Option<String> = redis::cmd("GETDEL")
                .arg(&key)
                .query_async(&mut conn)
                .await?;
            if taken.is_none() {
                return Ok(None);
            }
            let _: () = conn.del(user_key(&rec)).await?;
            drop(conn);
            let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
            repos::device_codes::consume(&mut *tx, tenant_id, rec.id).await?;
            tx.commit().await?;
            Ok(Some(Poll::Approved(Box::new(rec), a)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_codes_normalize_and_reject_strangers() {
        assert_eq!(
            normalize_user_code("bcdf-ghjk").as_deref(),
            Some("BCDF-GHJK")
        );
        assert_eq!(
            normalize_user_code(" BCDF GHJK ").as_deref(),
            Some("BCDF-GHJK")
        );
        assert_eq!(
            normalize_user_code("BCDFGHJK").as_deref(),
            Some("BCDF-GHJK")
        );
        assert!(normalize_user_code("BCDF-GHJ").is_none(), "too short");
        assert!(
            normalize_user_code("ABCD-EFGH").is_none(),
            "letters outside the alphabet"
        );
        assert!(
            normalize_user_code("BCDF-GH1K").is_none(),
            "digits are never used"
        );
    }

    #[test]
    fn generated_user_codes_are_well_formed() {
        for _ in 0..50 {
            let c = random_user_code();
            assert_eq!(normalize_user_code(&c).as_deref(), Some(c.as_str()));
        }
    }
}
