//! Client-initiated backchannel authentication (OpenID CIBA Core 1.0): a
//! client that already knows who the user is asks rIDM to have them sign in
//! on their own device, then collects the tokens without ever seeing a
//! browser.
//!
//! A request lives in Valkey under the hash of its `auth_req_id`, with what
//! the token endpoint must check (and, for `ping` clients, the notification
//! token and the id itself, which the ping carries). The user is told by
//! email or text and answers on the account console's approvals page, which
//! finds the request through its `ciba_requests` row; the row is also the
//! audit trail. Approval or denial rewrites the Valkey record in place; the
//! client's next token request takes it (once). Polling faster than the
//! interval earns `slow_down` and a longer interval, exactly as the device
//! grant does.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use redis::AsyncCommands as _;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{BackchannelDeliveryMode, Client, Tenant, User};
use crate::repos;
use crate::repos::ciba_requests::{NewRequest, PendingRequest};
use crate::services::notifications;
use crate::state::AppState;
use crate::util::outbound;

/// Lifetime of a request the client did not ask otherwise for.
pub const DEFAULT_EXPIRY_SECS: u64 = 10 * 60;
/// Bounds of `requested_expiry`.
pub const MIN_EXPIRY_SECS: u64 = 30;
pub const MAX_EXPIRY_SECS: u64 = 30 * 60;
/// Seconds between polls the client must respect.
pub const INTERVAL_SECS: u64 = 5;
const SLOW_DOWN_STEP_SECS: u64 = 5;
/// Requests that may wait on one user at once; more would let a client
/// flood their inbox.
pub const MAX_PENDING_PER_USER: i64 = 5;
/// Longest `binding_message`, in characters.
pub const BINDING_MESSAGE_MAX_CHARS: usize = 64;
/// Longest `client_notification_token`.
pub const NOTIFICATION_TOKEN_MAX_LEN: usize = 1024;

/// The user said yes, from the sign-in session behind their account token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub auth_time: DateTime<Utc>,
    pub amr: Vec<String>,
    pub acr: Option<String>,
    /// Organization the approving session acts in.
    pub org_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Status {
    Pending,
    Approved(Approval),
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CibaRecord {
    /// The `ciba_requests` row.
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
    pub mode: BackchannelDeliveryMode,
    /// Ping mode only: the id the ping names, and the bearer token the
    /// client gave for its notification endpoint.
    pub auth_req_id: Option<String>,
    pub notification_token: Option<String>,
    pub interval_secs: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: Status,
    pub last_poll_at: Option<DateTime<Utc>>,
}

impl CibaRecord {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

/// The authentication request acknowledgement (CIBA Core §7.3).
#[derive(Debug, Clone, Serialize)]
pub struct Acknowledgement {
    pub auth_req_id: String,
    pub expires_in: u64,
    pub interval: u64,
}

/// What the client asked for, validated.
pub struct Start<'a> {
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
    pub binding_message: Option<String>,
    pub acr_values: Vec<String>,
    pub notification_token: Option<String>,
    pub expiry_secs: u64,
    pub ip: Option<&'a str>,
}

fn hash(auth_req_id: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(auth_req_id.as_bytes()))
}

/// A binding message is shown on two screens and put in an email or a
/// text, so it stays short and plain: letters, digits, spaces and a little
/// punctuation, never anything a mail client would turn into a link.
pub fn valid_binding_message(m: &str) -> bool {
    let n = m.chars().count();
    (1..=BINDING_MESSAGE_MAX_CHARS).contains(&n)
        && m.trim() == m
        && m.chars()
            .all(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | ':' | '#'))
}

async fn store(state: &AppState, key: &str, rec: &CibaRecord, ttl: Option<u64>) -> AppResult<()> {
    let mut conn = state.redis.get().await?;
    let raw = serde_json::to_string(rec)?;
    match ttl {
        Some(secs) => {
            let _: () = conn.set_ex(key, raw, secs).await?;
        }
        None => {
            let _: () = redis::cmd("SET")
                .arg(key)
                .arg(raw)
                .arg("KEEPTTL")
                .query_async(&mut conn)
                .await?;
        }
    }
    Ok(())
}

async fn load(state: &AppState, key: &str) -> AppResult<Option<CibaRecord>> {
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = conn.get(key).await?;
    Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
}

/// Requests waiting on `user_id` right now.
pub async fn pending_count(state: &AppState, tenant_id: Uuid, user_id: Uuid) -> AppResult<i64> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let n = repos::ciba_requests::count_pending(&mut *tx, tenant_id, user_id).await?;
    tx.commit().await?;
    Ok(n)
}

/// Open a request for `user` on behalf of `client` and tell the user.
pub async fn start(
    state: &AppState,
    tenant: &Tenant,
    client: &Client,
    user: &User,
    req: Start<'_>,
) -> AppResult<Acknowledgement> {
    let mode = client
        .backchannel_token_delivery_mode
        .ok_or_else(|| AppError::Internal("CIBA client without a delivery mode".into()))?;
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let auth_req_id = URL_SAFE_NO_PAD.encode(bytes);
    let auth_req_hash = hash(&auth_req_id);
    let now = Utc::now();
    let expires_at = now + chrono::Duration::seconds(req.expiry_secs as i64);
    let ping = mode == BackchannelDeliveryMode::Ping;
    let rec = CibaRecord {
        id: Uuid::now_v7(),
        tenant_id: tenant.id,
        client_id: client.id,
        user_id: user.id,
        scopes: req.scopes.clone(),
        audiences: req.audiences,
        mode,
        auth_req_id: ping.then(|| auth_req_id.clone()),
        notification_token: if ping { req.notification_token } else { None },
        interval_secs: INTERVAL_SECS,
        issued_at: now,
        expires_at,
        status: Status::Pending,
        last_poll_at: None,
    };
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    repos::ciba_requests::insert(
        &mut *tx,
        &NewRequest {
            id: rec.id,
            tenant_id: tenant.id,
            client_id: client.id,
            user_id: user.id,
            auth_req_hash: &auth_req_hash,
            scopes: &req.scopes,
            binding_message: req.binding_message.as_deref(),
            acr_values: &req.acr_values,
            delivery_mode: mode.as_str(),
            expires_at,
        },
    )
    .await?;
    tx.commit().await?;
    store(
        state,
        &keys::ciba_request(tenant.id, &auth_req_hash),
        &rec,
        Some(req.expiry_secs),
    )
    .await?;
    state.events.publish(
        Event::new(
            Some(tenant.id),
            Actor::Client { id: client.id },
            EventKind::BackchannelRequested {
                request_id: rec.id,
                client_id: client.id,
                user_id: user.id,
                scopes: req.scopes,
                binding_message: req.binding_message.clone(),
            },
        )
        .with_request(req.ip.map(str::to_string), None),
    );
    let link = state.ui_page(
        tenant,
        "account/approvals",
        &[("tenant", &tenant.slug), ("request", &rec.id.to_string())],
    );
    notifications::backchannel_request(
        state,
        tenant,
        user,
        &client.name,
        req.binding_message.as_deref(),
        &link,
        req.expiry_secs.div_ceil(60),
    )
    .await;
    Ok(Acknowledgement {
        auth_req_id,
        expires_in: req.expiry_secs,
        interval: INTERVAL_SECS,
    })
}

/// What is waiting on the user, for their account console.
pub async fn list_pending(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<PendingRequest>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::ciba_requests::list_pending(&mut *tx, tenant_id, user_id).await?;
    tx.commit().await?;
    Ok(rows)
}

/// The user's answer to request `id`: `Some(approval)` approves it, `None`
/// denies it. Only a pending, unexpired request of this user can be
/// answered, and only once. A `ping` client is then told. An approval
/// returns the client (row id) and the scopes it now holds.
pub async fn decide(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    id: Uuid,
    approval: Option<Approval>,
) -> AppResult<Option<(Uuid, Vec<String>)>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let hash = repos::ciba_requests::pending_hash_for_update(&mut *tx, tenant_id, user_id, id)
        .await?
        .ok_or(AppError::NotFound("backchannel request"))?;
    let key = keys::ciba_request(tenant_id, &hash);
    let mut rec = load(state, &key)
        .await?
        .filter(|r| {
            r.user_id == user_id && matches!(r.status, Status::Pending) && !r.is_expired(Utc::now())
        })
        .ok_or(AppError::NotFound("backchannel request"))?;
    let approved = approval.is_some();
    rec.status = match approval {
        Some(a) => Status::Approved(a),
        None => Status::Denied,
    };
    repos::ciba_requests::decide(
        &mut *tx,
        tenant_id,
        id,
        if approved { "approved" } else { "denied" },
    )
    .await?;
    store(state, &key, &rec, None).await?;
    tx.commit().await?;
    if approved {
        state.events.publish(Event::new(
            Some(tenant_id),
            Actor::User { id: user_id },
            EventKind::AuthorizationGranted {
                user_id,
                client_id: rec.client_id,
                scopes: rec.scopes.clone(),
            },
        ));
    } else {
        state.events.publish(Event::new(
            Some(tenant_id),
            Actor::User { id: user_id },
            EventKind::BackchannelDenied {
                request_id: rec.id,
                client_id: rec.client_id,
                user_id,
            },
        ));
    }
    let granted = approved.then(|| (rec.client_id, rec.scopes.clone()));
    if rec.mode == BackchannelDeliveryMode::Ping {
        let state = state.clone();
        tokio::spawn(async move { ping(&state, &rec).await });
    }
    Ok(granted)
}

/// Tell a `ping` client its request was decided (CIBA Core §10.2): a POST
/// of `{"auth_req_id": …}` with the client's notification token as the
/// bearer. Tried three times; a client that never hears can still poll.
async fn ping(state: &AppState, rec: &CibaRecord) {
    let (Some(auth_req_id), Some(token)) = (&rec.auth_req_id, &rec.notification_token) else {
        return;
    };
    let client = match crate::services::clients::get(state, rec.tenant_id, rec.client_id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(client = %rec.client_id, error = %e, "CIBA ping skipped: client lookup failed");
            return;
        }
    };
    let Some(uri) = client.backchannel_client_notification_endpoint.clone() else {
        return;
    };
    // The client chose this URL: public addresses only (SSRF).
    if let Err(e) = outbound::check_url(&uri) {
        tracing::warn!(client = %client.client_id, error = %e, "CIBA ping refused");
        return;
    }
    let http = match outbound::client_builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, "CIBA ping: no HTTP client");
            return;
        }
    };
    let body = serde_json::json!({ "auth_req_id": auth_req_id });
    for (attempt, wait) in [0u64, 1, 4].into_iter().enumerate() {
        if wait > 0 {
            tokio::time::sleep(Duration::from_secs(wait)).await;
        }
        match http.post(&uri).bearer_auth(token).json(&body).send().await {
            Ok(res) if res.status().is_success() => {
                tracing::info!(client = %client.client_id, "CIBA ping delivered");
                return;
            }
            Ok(res) => {
                tracing::warn!(client = %client.client_id, attempt, status = %res.status(), "CIBA ping refused by the client");
            }
            Err(e) => {
                tracing::warn!(client = %client.client_id, attempt, error = %outbound::describe(&e), "CIBA ping failed");
            }
        }
    }
}

/// What the token endpoint tells the client.
pub enum Poll {
    /// Tokens follow; the request is spent.
    Approved(Box<CibaRecord>, Approval),
    Pending,
    /// Asked before the interval passed; the interval grew.
    SlowDown,
    Denied,
    Expired,
}

/// One token request by `client_id` with `auth_req_id`. `None` is a request
/// that does not exist (or belongs to another client).
pub async fn poll(
    state: &AppState,
    tenant_id: Uuid,
    client_id: Uuid,
    auth_req_id: &str,
) -> AppResult<Option<Poll>> {
    if auth_req_id.is_empty() || auth_req_id.len() > 128 {
        return Ok(None);
    }
    let key = keys::ciba_request(tenant_id, &hash(auth_req_id));
    let Some(mut rec) = load(state, &key).await? else {
        return Ok(None);
    };
    if rec.client_id != client_id {
        return Ok(None);
    }
    let now = Utc::now();
    let mut conn = state.redis.get().await?;
    if rec.is_expired(now) {
        let _: () = conn.del(&key).await?;
        return Ok(Some(Poll::Expired));
    }
    match rec.status.clone() {
        Status::Pending => {
            // Only an undecided request can be asked too often: a decided
            // one is handed over at once, which is what a pinged client
            // expects.
            let too_soon = rec
                .last_poll_at
                .is_some_and(|last| (now - last).num_seconds() < rec.interval_secs as i64);
            if too_soon {
                rec.interval_secs += SLOW_DOWN_STEP_SECS;
            }
            rec.last_poll_at = Some(now);
            drop(conn);
            store(state, &key, &rec, None).await?;
            Ok(Some(if too_soon {
                Poll::SlowDown
            } else {
                Poll::Pending
            }))
        }
        Status::Denied => {
            let _: () = conn.del(&key).await?;
            Ok(Some(Poll::Denied))
        }
        Status::Approved(a) => {
            // Spent by the first request that sees the approval.
            let taken: Option<String> = redis::cmd("GETDEL")
                .arg(&key)
                .query_async(&mut conn)
                .await?;
            if taken.is_none() {
                return Ok(None);
            }
            drop(conn);
            let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
            repos::ciba_requests::consume(&mut *tx, tenant_id, rec.id).await?;
            tx.commit().await?;
            Ok(Some(Poll::Approved(Box::new(rec), a)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_messages_stay_short_and_plain() {
        assert!(valid_binding_message("K7 R2"));
        assert!(valid_binding_message("Überweisung #4711"));
        assert!(valid_binding_message("Order 12.50: ok"));
        assert!(!valid_binding_message(""));
        assert!(!valid_binding_message(" padded"));
        assert!(!valid_binding_message("line\nbreak"));
        assert!(!valid_binding_message("https://evil.example/x"));
        assert!(!valid_binding_message("<b>bold</b>"));
        assert!(!valid_binding_message(
            &"x".repeat(BINDING_MESSAGE_MAX_CHARS + 1)
        ));
        assert!(valid_binding_message(
            &"x".repeat(BINDING_MESSAGE_MAX_CHARS)
        ));
    }
}
