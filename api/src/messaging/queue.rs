//! Outbound queue: render, enqueue, deliver with retries and dead-lettering.

use chrono::{Duration, Utc};
use ridm_core::providers::{EmailAddress, EmailMessage, ProviderError, SmsMessage};
use serde_json::Value;
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::messaging::templates;
use crate::models::{MessageChannel, MessageStatus, OutboundMessage, Tenant};
use crate::repos;
use crate::state::AppState;

pub const DEFAULT_MAX_ATTEMPTS: i32 = 6;
const BATCH: i64 = 50;

/// Backoff after `attempt` failures: 1m, 5m, 30m, 2h, 6h, then 12h.
pub fn backoff(attempt: i32) -> Duration {
    match attempt {
        0 | 1 => Duration::minutes(1),
        2 => Duration::minutes(5),
        3 => Duration::minutes(30),
        4 => Duration::hours(2),
        5 => Duration::hours(6),
        _ => Duration::hours(12),
    }
}

pub struct Outgoing<'a> {
    pub channel: MessageChannel,
    pub event: &'a str,
    pub recipient: &'a str,
    pub locale: Option<&'a str>,
    /// Template variables (`user`, `link`, `code`, ...). `tenant` is added automatically.
    pub vars: Value,
}

/// Render and queue a message, then try to deliver it immediately.
pub async fn send(
    state: &AppState,
    tenant: &Tenant,
    out: Outgoing<'_>,
) -> AppResult<OutboundMessage> {
    let mut vars = out.vars;
    if !vars.is_object() {
        vars = Value::Object(Default::default());
    }
    vars["tenant"] = super::vars::tenant(tenant);
    let locale = out.locale.unwrap_or(&tenant.settings.locale.default);
    let template = templates::resolve(
        state,
        tenant.id,
        &tenant.settings.locale.default,
        out.channel,
        out.event,
        locale,
    )
    .await?;
    let rendered = templates::render(&template, &vars)?;
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    let msg = repos::messages::enqueue(
        &mut *tx,
        tenant.id,
        Uuid::now_v7(),
        out.channel,
        out.event,
        out.recipient,
        rendered.subject.as_deref(),
        &rendered.body_text,
        rendered.body_html.as_deref(),
        &Value::Object(Default::default()),
        DEFAULT_MAX_ATTEMPTS,
    )
    .await?;
    tx.commit().await?;
    // Fast path: deliver now; the job retries anything that fails.
    let _ = deliver_due(state, tenant.id, BATCH).await;
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    let latest = repos::messages::find(&mut *tx, tenant.id, msg.id)
        .await?
        .unwrap_or(msg);
    tx.commit().await?;
    Ok(latest)
}

/// Deliver due messages of a tenant. Returns `(sent, failed)`.
pub async fn deliver_due(
    state: &AppState,
    tenant_id: Uuid,
    limit: i64,
) -> AppResult<(usize, usize)> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    repos::messages::requeue_stale(&mut *tx, tenant_id, Utc::now() - Duration::minutes(10)).await?;
    let claimed = repos::messages::claim_due(&mut *tx, tenant_id, limit).await?;
    tx.commit().await?;
    if claimed.is_empty() {
        return Ok((0, 0));
    }
    let email = state.senders.email(state, tenant_id).await?;
    let sms = state.senders.sms(state, tenant_id).await?;
    let mut sent = 0;
    let mut failed = 0;
    for msg in claimed {
        let result: Result<(), ProviderError> = match msg.channel {
            MessageChannel::Email => match &email {
                Some(s) => {
                    s.send(&EmailMessage {
                        to: vec![EmailAddress::new(&msg.recipient)],
                        from: None,
                        reply_to: None,
                        subject: msg.subject.clone().unwrap_or_default(),
                        text: msg.body_text.clone(),
                        html: msg.body_html.clone(),
                        headers: vec![],
                    })
                    .await
                }
                None => Err(ProviderError::Configuration(
                    "no email sender configured".into(),
                )),
            },
            MessageChannel::Sms => match &sms {
                Some(s) => {
                    s.send(&SmsMessage {
                        to: msg.recipient.clone(),
                        body: msg.body_text.clone(),
                    })
                    .await
                }
                None => Err(ProviderError::Configuration(
                    "no sms sender configured".into(),
                )),
            },
        };
        let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
        match result {
            Ok(()) => {
                repos::messages::mark_sent(&mut *tx, tenant_id, msg.id).await?;
                sent += 1;
            }
            Err(err) => {
                let attempts = msg.attempts + 1;
                // Permanent rejections and exhausted budgets are dead-lettered.
                let dead = !err.is_retryable() || attempts >= msg.max_attempts;
                let next = Utc::now() + backoff(attempts);
                repos::messages::mark_failed(
                    &mut *tx,
                    tenant_id,
                    msg.id,
                    &err.to_string(),
                    next,
                    dead,
                )
                .await?;
                failed += 1;
                if dead {
                    tracing::warn!(message = %msg.id, event = %msg.event, error = %err, "message dead-lettered");
                }
            }
        }
        tx.commit().await?;
    }
    Ok((sent, failed))
}

/// Put a dead message back in the queue (admin redeliver).
pub async fn redeliver(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let msg = repos::messages::find(&mut *tx, tenant_id, id)
        .await?
        .ok_or(AppError::NotFound("message"))?;
    if msg.status != MessageStatus::Dead {
        return Err(AppError::BadRequest(
            "only dead messages can be redelivered".into(),
        ));
    }
    sqlx::query(
        "UPDATE outbound_messages SET status = 'queued', attempts = 0, next_attempt_at = now(), last_error = NULL \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn recent(
    state: &AppState,
    tenant_id: Uuid,
    status: Option<MessageStatus>,
    limit: i64,
) -> AppResult<Vec<OutboundMessage>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows =
        repos::messages::list_recent(&mut *tx, tenant_id, status, limit.clamp(1, 500)).await?;
    tx.commit().await?;
    Ok(rows)
}
