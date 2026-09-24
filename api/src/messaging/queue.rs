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

/// Render and queue a message, and send it in the background: the request
/// that asked for it does not wait on the mail server. What fails is retried
/// by the delivery job; the returned row is the queued message.
pub async fn send(
    state: &AppState,
    tenant: &Tenant,
    out: Outgoing<'_>,
) -> AppResult<OutboundMessage> {
    let mut vars = out.vars;
    if !vars.is_object() {
        vars = Value::Object(Default::default());
    }
    vars["tenant"] = super::vars::tenant(tenant, &super::vars::sign_in_host(state, tenant));
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
    // Only this message: the backlog, and retries, are the job's.
    let background = state.clone();
    let (tenant_id, id) = (tenant.id, msg.id);
    state.background.spawn(async move {
        if let Err(e) = deliver_one(&background, tenant_id, id).await {
            tracing::warn!(error = %e, message = %id, "immediate message delivery failed; the job will retry");
        }
    });
    Ok(msg)
}

/// Deliver one queued message now, if it is still waiting.
async fn deliver_one(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let claimed = repos::messages::claim_one(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    let Some(msg) = claimed else {
        // Taken by the delivery job in the meantime.
        return Ok(());
    };
    let senders = Senders::of(state, tenant_id, std::slice::from_ref(&msg)).await?;
    deliver_claimed(state, tenant_id, &senders, msg).await?;
    Ok(())
}

/// Messages sent at the same time within one delivery pass.
const CONCURRENCY: usize = 8;

/// Deliver due messages of a tenant, several at a time. Returns
/// `(sent, failed)`. Messages a crashed node left in `sending` are the
/// delivery job's to requeue.
pub async fn deliver_due(
    state: &AppState,
    tenant_id: Uuid,
    limit: i64,
) -> AppResult<(usize, usize)> {
    use futures::StreamExt as _;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let claimed = repos::messages::claim_due(&mut *tx, tenant_id, limit).await?;
    tx.commit().await?;
    if claimed.is_empty() {
        return Ok((0, 0));
    }
    let senders = Senders::of(state, tenant_id, &claimed).await?;
    let senders = &senders;
    let outcomes: Vec<AppResult<bool>> = futures::stream::iter(claimed)
        .map(|msg| deliver_claimed(state, tenant_id, senders, msg))
        .buffer_unordered(CONCURRENCY)
        .collect()
        .await;
    let mut sent = 0;
    let mut failed = 0;
    for outcome in outcomes {
        match outcome? {
            true => sent += 1,
            false => failed += 1,
        }
    }
    Ok((sent, failed))
}

/// The tenant's senders for the channels some messages need.
struct Senders {
    email: Option<std::sync::Arc<dyn ridm_core::providers::EmailSender>>,
    sms: Option<std::sync::Arc<dyn ridm_core::providers::SmsSender>>,
}

impl Senders {
    async fn of(state: &AppState, tenant_id: Uuid, msgs: &[OutboundMessage]) -> AppResult<Self> {
        let email = if msgs.iter().any(|m| m.channel == MessageChannel::Email) {
            state.senders.email(state, tenant_id).await?
        } else {
            None
        };
        let sms = if msgs.iter().any(|m| m.channel == MessageChannel::Sms) {
            state.senders.sms(state, tenant_id).await?
        } else {
            None
        };
        Ok(Self { email, sms })
    }
}

/// Send one claimed message and record the outcome. `Ok(true)` when sent.
async fn deliver_claimed(
    state: &AppState,
    tenant_id: Uuid,
    senders: &Senders,
    msg: OutboundMessage,
) -> AppResult<bool> {
    let result: Result<(), ProviderError> = match msg.channel {
        MessageChannel::Email => match &senders.email {
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
        MessageChannel::Sms => match &senders.sms {
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
    let sent = match result {
        Ok(()) => {
            repos::messages::mark_sent(&mut *tx, tenant_id, msg.id).await?;
            true
        }
        Err(err) => {
            let attempts = msg.attempts + 1;
            // Permanent rejections and exhausted budgets are dead-lettered.
            let dead = !err.is_retryable() || attempts >= msg.max_attempts;
            let next = Utc::now() + backoff(attempts);
            repos::messages::mark_failed(&mut *tx, tenant_id, msg.id, &err.to_string(), next, dead)
                .await?;
            if dead {
                tracing::warn!(message = %msg.id, event = %msg.event, error = %err, "message dead-lettered");
            }
            false
        }
    };
    tx.commit().await?;
    Ok(sent)
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
    limit: Option<u32>,
) -> AppResult<Vec<OutboundMessage>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::messages::list_recent(
        &mut *tx,
        tenant_id,
        status,
        crate::util::cursor::page_size(limit),
    )
    .await?;
    tx.commit().await?;
    Ok(rows)
}
