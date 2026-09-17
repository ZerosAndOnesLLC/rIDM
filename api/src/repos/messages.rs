//! Message templates and the outbound queue (run inside a tenant tx).

use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{MessageChannel, MessageStatus, MessageTemplate, OutboundMessage};

const TEMPLATE_COLUMNS: &str =
    "id, tenant_id, channel, event, locale, subject, body_text, body_html, created_at, updated_at";
const MESSAGE_COLUMNS: &str = "id, tenant_id, channel, event, recipient, subject, body_text, body_html, headers, \
    status, attempts, max_attempts, next_attempt_at, last_error, created_at, sent_at";

pub async fn list_templates<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
) -> Result<Vec<MessageTemplate>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(TEMPLATE_COLUMNS)
        .push(" FROM message_templates WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" ORDER BY channel, event, locale");
    qb.build_query_as::<MessageTemplate>().fetch_all(exec).await
}

pub async fn find_template<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    channel: MessageChannel,
    event: &str,
    locale: &str,
) -> Result<Option<MessageTemplate>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(TEMPLATE_COLUMNS)
        .push(" FROM message_templates WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND channel = ")
        .push_bind(channel)
        .push(" AND event = ")
        .push_bind(event)
        .push(" AND locale = ")
        .push_bind(locale);
    qb.build_query_as::<MessageTemplate>()
        .fetch_optional(exec)
        .await
}

#[allow(clippy::too_many_arguments)]
pub async fn upsert_template<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    channel: MessageChannel,
    event: &str,
    locale: &str,
    subject: Option<&str>,
    body_text: &str,
    body_html: Option<&str>,
) -> Result<MessageTemplate, sqlx::Error> {
    sqlx::query_as::<_, MessageTemplate>(
        "INSERT INTO message_templates (tenant_id, channel, event, locale, subject, body_text, body_html) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (tenant_id, channel, event, locale) DO UPDATE SET subject = EXCLUDED.subject, \
            body_text = EXCLUDED.body_text, body_html = EXCLUDED.body_html, updated_at = now() \
         RETURNING id, tenant_id, channel, event, locale, subject, body_text, body_html, created_at, updated_at",
    )
    .bind(tenant_id)
    .bind(channel)
    .bind(event)
    .bind(locale)
    .bind(subject)
    .bind(body_text)
    .bind(body_html)
    .fetch_one(exec)
    .await
}

pub async fn delete_template<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("DELETE FROM message_templates WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}

#[allow(clippy::too_many_arguments)]
pub async fn enqueue<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    channel: MessageChannel,
    event: &str,
    recipient: &str,
    subject: Option<&str>,
    body_text: &str,
    body_html: Option<&str>,
    headers: &serde_json::Value,
    max_attempts: i32,
) -> Result<OutboundMessage, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO outbound_messages (id, tenant_id, channel, event, recipient, subject, body_text, \
         body_html, headers, max_attempts) VALUES (",
    );
    let mut s = qb.separated(", ");
    s.push_bind(id)
        .push_bind(tenant_id)
        .push_bind(channel)
        .push_bind(event)
        .push_bind(recipient)
        .push_bind(subject)
        .push_bind(body_text)
        .push_bind(body_html)
        .push_bind(headers.clone())
        .push_bind(max_attempts);
    qb.push(") RETURNING ").push(MESSAGE_COLUMNS);
    qb.build_query_as::<OutboundMessage>().fetch_one(exec).await
}

/// Messages still to be sent, across tenants (bypass transaction; a gauge).
pub async fn count_queued<'e>(exec: impl PgExecutor<'e>) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM outbound_messages WHERE status IN ('queued', 'sending')",
    )
    .fetch_one(exec)
    .await
}

/// Tenants with a message due right now (bypass transaction; the job visits only these).
pub async fn tenants_with_due<'e>(exec: impl PgExecutor<'e>) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT DISTINCT tenant_id FROM outbound_messages \
         WHERE status IN ('queued', 'sending') AND next_attempt_at <= now()",
    )
    .fetch_all(exec)
    .await
}

/// Claim due messages for delivery (marks them `sending`).
pub async fn claim_due<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    limit: i64,
) -> Result<Vec<OutboundMessage>, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "UPDATE outbound_messages SET status = 'sending' WHERE id IN ( \
            SELECT id FROM outbound_messages WHERE tenant_id = ",
    );
    qb.push_bind(tenant_id)
        .push(" AND status = 'queued' AND next_attempt_at <= now() ORDER BY next_attempt_at LIMIT ")
        .push_bind(limit)
        .push(" FOR UPDATE SKIP LOCKED) AND tenant_id = ")
        .push_bind(tenant_id)
        .push(" RETURNING ")
        .push(MESSAGE_COLUMNS);
    qb.build_query_as::<OutboundMessage>().fetch_all(exec).await
}

/// Messages stuck in `sending` (crashed worker) older than `stale_before` go back to queued.
pub async fn requeue_stale<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    stale_before: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE outbound_messages SET status = 'queued' WHERE tenant_id = $1 AND status = 'sending' AND next_attempt_at < $2",
    )
    .bind(tenant_id)
    .bind(stale_before)
    .execute(exec)
    .await?
    .rows_affected())
}

pub async fn mark_sent<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE outbound_messages SET status = 'sent', sent_at = now(), attempts = attempts + 1, last_error = NULL \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(exec)
    .await?;
    Ok(())
}

pub async fn mark_failed<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    error: &str,
    next_attempt_at: DateTime<Utc>,
    dead: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE outbound_messages SET status = $5, attempts = attempts + 1, last_error = $3, next_attempt_at = $4 \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(error)
    .bind(next_attempt_at)
    .bind(if dead { MessageStatus::Dead } else { MessageStatus::Queued })
    .execute(exec)
    .await?;
    Ok(())
}

pub async fn find<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<OutboundMessage>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(MESSAGE_COLUMNS)
        .push(" FROM outbound_messages WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id);
    qb.build_query_as::<OutboundMessage>()
        .fetch_optional(exec)
        .await
}

pub async fn list_recent<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    status: Option<MessageStatus>,
    limit: i64,
) -> Result<Vec<OutboundMessage>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(MESSAGE_COLUMNS)
        .push(" FROM outbound_messages WHERE tenant_id = ")
        .push_bind(tenant_id);
    if let Some(s) = status {
        qb.push(" AND status = ").push_bind(s);
    }
    qb.push(" ORDER BY created_at DESC LIMIT ").push_bind(limit);
    qb.build_query_as::<OutboundMessage>().fetch_all(exec).await
}

pub async fn purge_sent<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    older_than: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM outbound_messages WHERE tenant_id = $1 AND status IN ('sent', 'dead') AND created_at < $2")
        .bind(tenant_id)
        .bind(older_than)
        .execute(exec)
        .await?
        .rows_affected())
}
