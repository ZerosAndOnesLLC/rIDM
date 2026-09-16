//! Outbound webhooks: configuration with an encrypted HMAC secret, a
//! dispatcher that turns bus events into queued deliveries and sends them
//! at once, and a delivery pass (also run by the `webhook_delivery` job for
//! retries) with concurrent attempts, backoff and dead-lettering. Every
//! delivery carries `X-RIDM-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret,
//! "<t>.<body>")>`; a dead letter raises `webhook.delivery_dead`.

use std::sync::LazyLock;
use std::time::Duration as StdDuration;

use futures::StreamExt as _;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use hmac::{Hmac, KeyInit as _, Mac as _};
use redis::AsyncCommands as _;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use ridm_core::providers::Encrypted;
use serde::Serialize;
use sha2::Sha256;
use tokio::sync::broadcast::error::RecvError;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cache::keys as cache_keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{DeliveryStatus, NewWebhook, Webhook, WebhookDelivery, WebhookUpdate};
use crate::repos;
use crate::state::AppState;

const LIST_CACHE_TTL: StdDuration = StdDuration::from_secs(60);
const SECRET_PREFIX: &str = "whsec_";
const DEFAULT_MAX_ATTEMPTS: i32 = 8;
const REQUEST_TIMEOUT: StdDuration = StdDuration::from_secs(10);
const SNIPPET_BYTES: usize = 512;
/// Deliveries attempted at the same time within one pass.
const CONCURRENCY: usize = 8;
/// Deliveries one prompt pass (right after an event) takes on.
const PROMPT_BATCH: i64 = 50;
/// Lock that keeps one prompt pass per tenant in flight at a time.
const PROMPT_LOCK_SECS: u64 = 15;

/// One connection pool for every delivery.
static HTTP: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("rIDM-Webhooks/1")
        .build()
        .expect("reqwest client")
});

fn aad(tenant_id: Uuid, id: Uuid) -> Vec<u8> {
    format!("webhooks:{tenant_id}:{id}").into_bytes()
}

fn random_secret() -> Zeroizing<String> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    Zeroizing::new(format!("{SECRET_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

async fn encrypt_secret(
    state: &AppState,
    tenant_id: Uuid,
    id: Uuid,
    secret: &str,
) -> AppResult<Encrypted> {
    state
        .key_encryptor
        .encrypt(secret.as_bytes(), &aad(tenant_id, id))
        .await
        .map_err(|e| AppError::Internal(format!("webhook secret encrypt: {e}")))
}

async fn decrypt_secret(state: &AppState, w: &Webhook) -> AppResult<Zeroizing<String>> {
    let enc =
        Encrypted::from_bytes(&w.secret_enc).map_err(|e| AppError::Internal(e.to_string()))?;
    let plain = state
        .key_encryptor
        .decrypt(&enc, &aad(w.tenant_id, w.id))
        .await
        .map_err(|e| AppError::Internal(format!("webhook secret decrypt: {e}")))?;
    Ok(Zeroizing::new(String::from_utf8_lossy(&plain).into_owned()))
}

/// Literal addresses that must never be a webhook target: this server's
/// own network (SSRF). Loopback stays allowed for plain-http development.
fn is_private_literal(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || (ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]))
                || ip.octets()[0] == 0
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            ip.is_unspecified()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_private() || v4.is_link_local() || v4.is_loopback())
        }
        Err(_) => false,
    }
}

fn validate_url(raw: &str) -> AppResult<()> {
    let u = url::Url::parse(raw)
        .map_err(|_| AppError::BadRequest(format!("url: `{raw}` is not a valid URL")))?;
    if is_private_literal(u.host_str().unwrap_or_default()) {
        return Err(AppError::BadRequest(
            "url: private, link-local and unspecified addresses are not allowed".into(),
        ));
    }
    match u.scheme() {
        "https" => Ok(()),
        "http"
            if matches!(
                u.host_str().unwrap_or_default(),
                "localhost" | "127.0.0.1" | "[::1]"
            ) =>
        {
            Ok(())
        }
        "http" => Err(AppError::BadRequest(
            "url: plain http is only allowed for loopback addresses".into(),
        )),
        other => Err(AppError::BadRequest(format!(
            "url: scheme `{other}` is not allowed"
        ))),
    }
}

fn validate_events(events: &[String]) -> AppResult<Vec<String>> {
    if events.is_empty() {
        return Err(AppError::BadRequest(
            "events must name at least one event, prefix (`user.*`) or `*`".into(),
        ));
    }
    let mut out = Vec::with_capacity(events.len());
    for e in events {
        let e = e.trim();
        let ok = e == "*"
            || (!e.is_empty()
                && e.len() <= 64
                && e.chars().all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.' || c == '*'
                })
                && e.matches('*').count() <= 1
                && (!e.contains('*') || e.ends_with('*')));
        if !ok {
            return Err(AppError::BadRequest(format!(
                "events: `{e}` is not an event name, prefix or `*`"
            )));
        }
        if !out.iter().any(|x| x == e) {
            out.push(e.to_string());
        }
    }
    Ok(out)
}

fn validate_headers(h: &serde_json::Value) -> AppResult<()> {
    let Some(obj) = h.as_object() else {
        return Err(AppError::BadRequest("headers must be an object".into()));
    };
    for (k, v) in obj {
        if axum::http::HeaderName::from_bytes(k.as_bytes()).is_err() {
            return Err(AppError::BadRequest(format!(
                "headers: `{k}` is not a header name"
            )));
        }
        if k.eq_ignore_ascii_case("host") || k.to_ascii_lowercase().starts_with("x-ridm-") {
            return Err(AppError::BadRequest(format!("headers: `{k}` is reserved")));
        }
        match v.as_str() {
            Some(s) if axum::http::HeaderValue::from_str(s).is_ok() => {}
            _ => {
                return Err(AppError::BadRequest(format!(
                    "headers: `{k}` must be a string header value"
                )));
            }
        }
    }
    Ok(())
}

fn validate_max_attempts(n: i32) -> AppResult<()> {
    if (1..=20).contains(&n) {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "max_attempts must be between 1 and 20".into(),
        ))
    }
}

/// A created or rotated webhook with its secret, shown exactly once.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct WebhookWithSecret {
    #[serde(flatten)]
    pub webhook: Webhook,
    pub secret: String,
}

pub async fn list(state: &AppState, tenant_id: Uuid) -> AppResult<Vec<Webhook>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::webhooks::list(&mut *tx, tenant_id).await?;
    tx.commit().await?;
    Ok(rows)
}

/// Enabled webhooks of a tenant, cached briefly for the dispatcher.
async fn enabled_cached(state: &AppState, tenant_id: Uuid) -> AppResult<Vec<Webhook>> {
    let db = state.db.clone();
    let rows = state
        .cache
        .get_or_load(
            &cache_keys::webhooks(tenant_id),
            LIST_CACHE_TTL,
            || async move {
                let mut tx = db::tenant_tx(&db, tenant_id).await?;
                let rows = repos::webhooks::list(&mut *tx, tenant_id).await?;
                tx.commit().await?;
                Ok(Some(
                    rows.into_iter().filter(|w| w.enabled).collect::<Vec<_>>(),
                ))
            },
        )
        .await?;
    Ok(rows.map(|r| r.as_ref().clone()).unwrap_or_default())
}

pub async fn get(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<Webhook> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let w = repos::webhooks::find_by_id(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    w.ok_or(AppError::NotFound("webhook"))
}

pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    input: NewWebhook,
) -> AppResult<WebhookWithSecret> {
    let name = input.name.trim().to_string();
    if name.is_empty() || name.len() > 255 {
        return Err(AppError::BadRequest("name must be 1-255 characters".into()));
    }
    validate_url(&input.url)?;
    let events = validate_events(&input.events)?;
    let headers = input.headers.unwrap_or_else(|| serde_json::json!({}));
    validate_headers(&headers)?;
    let max_attempts = input.max_attempts.unwrap_or(DEFAULT_MAX_ATTEMPTS);
    validate_max_attempts(max_attempts)?;
    let id = Uuid::now_v7();
    let secret = random_secret();
    let enc = encrypt_secret(state, tenant_id, id, &secret).await?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let w = repos::webhooks::insert(
        &mut *tx,
        tenant_id,
        id,
        &name,
        input.url.trim(),
        &enc.to_bytes(),
        enc.key_version as i32,
        &events,
        input.enabled.unwrap_or(true),
        &headers,
        max_attempts,
    )
    .await?;
    tx.commit().await?;
    state
        .cache
        .invalidate(&[cache_keys::webhooks(tenant_id)])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::WebhookCreated { webhook_id: id },
    ));
    Ok(WebhookWithSecret {
        webhook: w,
        secret: secret.to_string(),
    })
}

pub async fn update(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
    mut patch: WebhookUpdate,
) -> AppResult<Webhook> {
    if patch.is_empty() {
        return get(state, tenant_id, id).await;
    }
    if let Some(n) = &patch.name {
        let n = n.trim().to_string();
        if n.is_empty() || n.len() > 255 {
            return Err(AppError::BadRequest("name must be 1-255 characters".into()));
        }
        patch.name = Some(n);
    }
    if let Some(u) = &patch.url {
        validate_url(u)?;
        patch.url = Some(u.trim().to_string());
    }
    if let Some(e) = &patch.events {
        patch.events = Some(validate_events(e)?);
    }
    if let Some(h) = &patch.headers {
        validate_headers(h)?;
    }
    if let Some(m) = patch.max_attempts {
        validate_max_attempts(m)?;
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let w = repos::webhooks::update(&mut *tx, tenant_id, id, &patch)
        .await?
        .ok_or(AppError::NotFound("webhook"))?;
    tx.commit().await?;
    state
        .cache
        .invalidate(&[cache_keys::webhooks(tenant_id)])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::WebhookUpdated { webhook_id: id },
    ));
    Ok(w)
}

pub async fn delete(state: &AppState, tenant_id: Uuid, actor: Actor, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::webhooks::delete(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    if !ok {
        return Err(AppError::NotFound("webhook"));
    }
    state
        .cache
        .invalidate(&[cache_keys::webhooks(tenant_id)])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::WebhookDeleted { webhook_id: id },
    ));
    Ok(())
}

/// New signing secret, shown once. Deliveries after this call use it.
pub async fn rotate_secret(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> AppResult<WebhookWithSecret> {
    get(state, tenant_id, id).await?;
    let secret = random_secret();
    let enc = encrypt_secret(state, tenant_id, id, &secret).await?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    repos::webhooks::set_secret(
        &mut *tx,
        tenant_id,
        id,
        &enc.to_bytes(),
        enc.key_version as i32,
    )
    .await?;
    let w = repos::webhooks::find_by_id(&mut *tx, tenant_id, id)
        .await?
        .ok_or(AppError::NotFound("webhook"))?;
    tx.commit().await?;
    state
        .cache
        .invalidate(&[cache_keys::webhooks(tenant_id)])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::WebhookSecretRotated { webhook_id: id },
    ));
    Ok(WebhookWithSecret {
        webhook: w,
        secret: secret.to_string(),
    })
}

// --- dispatch ----------------------------------------------------------------

/// Queue a delivery of `event` to every enabled webhook of its tenant that
/// wants it. Global events (no tenant) are not delivered.
pub async fn dispatch(state: &AppState, event: &Event) -> AppResult<usize> {
    let Some(tenant_id) = event.tenant_id else {
        return Ok(0);
    };
    let name = event.name();
    // A dead letter's own event never becomes a delivery: a failing endpoint
    // would otherwise breed one new delivery per death, forever.
    if name == "webhook.delivery_dead" {
        return Ok(0);
    }
    // Deliveries of our own configuration changes would loop on themselves only
    // in the sense of noise; they are still events and are delivered.
    let targets: Vec<Webhook> = enabled_cached(state, tenant_id)
        .await?
        .into_iter()
        .filter(|w| w.wants(name))
        .collect();
    if targets.is_empty() {
        return Ok(0);
    }
    let payload = serde_json::to_value(event)?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    for w in &targets {
        repos::webhooks::enqueue(
            &mut *tx,
            tenant_id,
            Uuid::now_v7(),
            w.id,
            event.id,
            name,
            &payload,
            w.max_attempts,
        )
        .await?;
    }
    tx.commit().await?;
    // Send now rather than at the job's next tick; retries stay with the job.
    let prompt = state.clone();
    tokio::spawn(async move {
        if let Err(err) = deliver_promptly(&prompt, tenant_id).await {
            tracing::warn!(%tenant_id, error = %err, "prompt webhook delivery failed");
        }
    });
    Ok(targets.len())
}

/// One prompt delivery pass per tenant at a time (a short Valkey lock);
/// when a pass is already running it will pick the new rows up itself.
async fn deliver_promptly(state: &AppState, tenant_id: Uuid) -> AppResult<()> {
    let key = format!("{}:t:{tenant_id}:webhooks:prompt", cache_keys::PREFIX);
    let mut conn = state.redis.get().await?;
    let mine: bool = redis::cmd("SET")
        .arg(&key)
        .arg(1u8)
        .arg("NX")
        .arg("EX")
        .arg(PROMPT_LOCK_SECS)
        .query_async(&mut *conn)
        .await?;
    if !mine {
        return Ok(());
    }
    // Rows the current pass may have committed after this one's claim are
    // few; drain until a pass finds nothing so none waits for the job.
    loop {
        let (delivered, failed) = deliver_due(state, tenant_id, PROMPT_BATCH).await?;
        if delivered + failed == 0 {
            break;
        }
    }
    let _: () = conn.del(&key).await.unwrap_or(());
    Ok(())
}

/// Subscribe to the event bus and queue deliveries; the delivery job sends them.
pub fn spawn_dispatcher(state: AppState) -> tokio::task::JoinHandle<()> {
    let mut rx = state.events.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(envelope) => {
                    if let Err(err) = dispatch(&state, &envelope.event).await {
                        tracing::error!(event = envelope.event.name(), error = %err, "webhook dispatch failed");
                    }
                }
                Err(RecvError::Lagged(n)) => {
                    tracing::warn!(
                        skipped = n,
                        "webhooks: event bus lagged, deliveries skipped"
                    );
                }
                Err(RecvError::Closed) => break,
            }
        }
    })
}

// --- delivery ----------------------------------------------------------------

/// `t=<unix>,v1=<hex>` over `"<t>.<body>"`.
pub fn sign(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!(
        "t={timestamp},v1={}",
        hex::encode(mac.finalize().into_bytes())
    )
}

/// Backoff after `attempt` failures: 30s, 2m, 10m, 30m, 2h, then 6h.
pub fn backoff(attempt: i32) -> Duration {
    match attempt {
        0 | 1 => Duration::seconds(30),
        2 => Duration::minutes(2),
        3 => Duration::minutes(10),
        4 => Duration::minutes(30),
        5 => Duration::hours(2),
        _ => Duration::hours(6),
    }
}

/// Outcome of one HTTP attempt.
pub struct Attempt {
    pub status: Option<i32>,
    pub snippet: Option<String>,
    pub error: Option<String>,
    pub retryable: bool,
}

async fn attempt(state: &AppState, w: &Webhook, delivery: &WebhookDelivery) -> AppResult<Attempt> {
    let secret = decrypt_secret(state, w).await?;
    let body = serde_json::to_vec(&serde_json::json!({
        "delivery_id": delivery.id,
        "attempt": delivery.attempts + 1,
        "event": delivery.payload,
    }))?;
    let ts = Utc::now().timestamp();
    let mut req = HTTP
        .post(&w.url)
        .header("content-type", "application/json")
        .header("x-ridm-event", &delivery.event_name)
        .header("x-ridm-timestamp", ts.to_string())
        .header("x-ridm-delivery", delivery.id.to_string())
        .header("x-ridm-webhook", w.id.to_string())
        .header("x-ridm-signature", sign(&secret, ts, &body));
    if let Some(h) = w.headers.as_object() {
        for (k, v) in h {
            if let Some(s) = v.as_str() {
                req = req.header(k, s);
            }
        }
    }
    let res = match req.body(body).send().await {
        Ok(r) => r,
        Err(e) => {
            return Ok(Attempt {
                status: None,
                snippet: None,
                error: Some(format!("request failed: {e}")),
                retryable: true,
            });
        }
    };
    let status = res.status();
    let snippet = res
        .bytes()
        .await
        .ok()
        .map(|b| String::from_utf8_lossy(&b[..b.len().min(SNIPPET_BYTES)]).into_owned());
    if status.is_success() {
        return Ok(Attempt {
            status: Some(status.as_u16().into()),
            snippet,
            error: None,
            retryable: false,
        });
    }
    let retryable = status.is_server_error() || matches!(status.as_u16(), 408 | 425 | 429);
    Ok(Attempt {
        status: Some(status.as_u16().into()),
        snippet,
        error: Some(format!("endpoint returned {status}")),
        retryable,
    })
}

/// Deliver due deliveries of one tenant, several at a time. Returns
/// (delivered, failed); a failure that is dead raises `webhook.delivery_dead`.
pub async fn deliver_due(
    state: &AppState,
    tenant_id: Uuid,
    limit: i64,
) -> AppResult<(usize, usize)> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    repos::webhooks::requeue_stale(&mut *tx, tenant_id, Utc::now() - Duration::minutes(10)).await?;
    let claimed = repos::webhooks::claim_due(&mut *tx, tenant_id, limit).await?;
    tx.commit().await?;
    let outcomes: Vec<AppResult<bool>> = futures::stream::iter(claimed)
        .map(|d| deliver_one(state, tenant_id, d))
        .buffer_unordered(CONCURRENCY)
        .collect()
        .await;
    let mut delivered = 0;
    let mut failed = 0;
    for o in outcomes {
        match o? {
            true => delivered += 1,
            false => failed += 1,
        }
    }
    Ok((delivered, failed))
}

/// One claimed delivery: attempt, record, dead-letter. `Ok(true)` when delivered.
async fn deliver_one(state: &AppState, tenant_id: Uuid, d: WebhookDelivery) -> AppResult<bool> {
    let webhook = get(state, tenant_id, d.webhook_id).await;
    let outcome = match &webhook {
        Ok(w) if w.enabled => attempt(state, w, &d).await?,
        Ok(_) => Attempt {
            status: None,
            snippet: None,
            error: Some("webhook is disabled".into()),
            retryable: false,
        },
        // The webhook vanished under the queue (cascade takes the rows too).
        Err(_) => return Ok(false),
    };
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let result = match outcome.error {
        None => {
            repos::webhooks::mark_delivered(
                &mut *tx,
                tenant_id,
                d.id,
                outcome.status.unwrap_or(200),
                outcome.snippet.as_deref(),
            )
            .await?;
            metrics::counter!("ridm_webhook_deliveries_total", "outcome" => "delivered")
                .increment(1);
            Ok(true)
        }
        Some(err) => {
            let attempts = d.attempts + 1;
            let dead = !outcome.retryable || attempts >= d.max_attempts;
            repos::webhooks::mark_failed(
                &mut *tx,
                tenant_id,
                d.id,
                outcome.status,
                &err,
                outcome.snippet.as_deref(),
                Utc::now() + backoff(attempts),
                dead,
            )
            .await?;
            metrics::counter!(
                "ridm_webhook_deliveries_total",
                "outcome" => if dead { "dead" } else { "retry" }
            )
            .increment(1);
            if dead {
                tracing::warn!(%tenant_id, webhook = %d.webhook_id, delivery = %d.id, event = %d.event_name, error = %err, "webhook delivery dead-lettered");
                state.events.publish(Event::new(
                    Some(tenant_id),
                    Actor::System,
                    EventKind::WebhookDeliveryDead {
                        webhook_id: d.webhook_id,
                        delivery_id: d.id,
                        event_name: d.event_name.clone(),
                    },
                ));
            }
            Ok(false)
        }
    };
    tx.commit().await?;
    result
}

/// Put every dead delivery of a webhook back on the queue and send now.
pub async fn redeliver_dead(state: &AppState, tenant_id: Uuid, webhook_id: Uuid) -> AppResult<u64> {
    get(state, tenant_id, webhook_id).await?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let n = repos::webhooks::requeue_dead(&mut *tx, tenant_id, webhook_id).await?;
    tx.commit().await?;
    if n > 0 {
        deliver_due(state, tenant_id, i64::try_from(n).unwrap_or(i64::MAX)).await?;
    }
    Ok(n)
}

pub async fn list_deliveries(
    state: &AppState,
    tenant_id: Uuid,
    webhook_id: Uuid,
    status: Option<DeliveryStatus>,
    limit: i64,
) -> AppResult<Vec<WebhookDelivery>> {
    get(state, tenant_id, webhook_id).await?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::webhooks::list_deliveries(
        &mut *tx,
        tenant_id,
        webhook_id,
        status,
        limit.clamp(1, 500),
    )
    .await?;
    tx.commit().await?;
    Ok(rows)
}

pub async fn get_delivery(
    state: &AppState,
    tenant_id: Uuid,
    webhook_id: Uuid,
    id: Uuid,
) -> AppResult<WebhookDelivery> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let d = repos::webhooks::find_delivery(&mut *tx, tenant_id, webhook_id, id).await?;
    tx.commit().await?;
    d.ok_or(AppError::NotFound("delivery"))
}

/// Requeue a delivery and try it right away.
pub async fn redeliver(
    state: &AppState,
    tenant_id: Uuid,
    webhook_id: Uuid,
    id: Uuid,
) -> AppResult<WebhookDelivery> {
    get_delivery(state, tenant_id, webhook_id, id).await?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::webhooks::requeue(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    if !ok {
        return Err(AppError::BadRequest(
            "only delivered, failed or dead deliveries can be redelivered".into(),
        ));
    }
    deliver_due(state, tenant_id, 50).await?;
    get_delivery(state, tenant_id, webhook_id, id).await
}

/// Queue a synthetic `webhook.test` event for one webhook and deliver it now.
pub async fn test(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    webhook_id: Uuid,
) -> AppResult<WebhookDelivery> {
    let w = get(state, tenant_id, webhook_id).await?;
    let event = Event::new(
        Some(tenant_id),
        actor,
        EventKind::WebhookTest { webhook_id: w.id },
    );
    let payload = serde_json::to_value(&event)?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let d = repos::webhooks::enqueue(
        &mut *tx,
        tenant_id,
        Uuid::now_v7(),
        w.id,
        event.id,
        event.name(),
        &payload,
        1,
    )
    .await?;
    tx.commit().await?;
    deliver_due(state, tenant_id, 50).await?;
    get_delivery(state, tenant_id, webhook_id, d.id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_patterns() {
        let mut w = Webhook {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            name: "w".into(),
            url: "https://x".into(),
            secret_enc: vec![],
            key_version: 1,
            events: vec!["user.created".into(), "client.*".into()],
            enabled: true,
            headers: serde_json::json!({}),
            max_attempts: 8,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(w.wants("user.created"));
        assert!(!w.wants("user.updated"));
        assert!(w.wants("client.secret_rotated"));
        w.events = vec!["*".into()];
        assert!(w.wants("anything.at_all"));
        assert!(validate_events(&["user.*".into(), "*".into()]).is_ok());
        assert!(validate_events(&["User.Created".into()]).is_err());
        assert!(validate_events(&["*.created".into()]).is_err());
        assert!(validate_events(&[]).is_err());
    }

    #[test]
    fn private_targets_are_refused() {
        assert!(validate_url("https://10.1.2.3/hook").is_err());
        assert!(validate_url("https://192.168.0.9/hook").is_err());
        assert!(validate_url("https://169.254.169.254/latest").is_err());
        assert!(validate_url("https://100.64.0.1/").is_err());
        assert!(validate_url("https://[fd00::1]/").is_err());
        assert!(validate_url("https://[::ffff:10.0.0.1]/").is_err());
        assert!(
            validate_url("http://127.0.0.1:9/hook").is_ok(),
            "loopback for dev"
        );
        assert!(validate_url("https://hooks.example.com/x").is_ok());
        assert!(validate_url("http://hooks.example.com/x").is_err());
    }

    #[test]
    fn signature_is_deterministic_and_keyed() {
        let a = sign("s1", 1_700_000_000, b"{}");
        assert!(a.starts_with("t=1700000000,v1="));
        assert_eq!(a, sign("s1", 1_700_000_000, b"{}"));
        assert_ne!(a, sign("s2", 1_700_000_000, b"{}"));
        assert_ne!(a, sign("s1", 1_700_000_001, b"{}"));
    }
}
