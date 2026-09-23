//! Webhooks and their deliveries (tenant-bound transactions).

use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{DeliveryStatus, Webhook, WebhookDelivery, WebhookUpdate};

const COLUMNS: &str = "id, tenant_id, name, url, secret_enc, key_version, events, enabled, headers, \
    max_attempts, created_at, updated_at";
const DELIVERY_COLUMNS: &str = "id, tenant_id, webhook_id, event_id, event_name, payload, status, \
    attempts, max_attempts, next_attempt_at, last_status, last_error, response_snippet, created_at, \
    delivered_at";

pub async fn list<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
) -> Result<Vec<Webhook>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM webhooks WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" ORDER BY created_at, id");
    qb.build_query_as::<Webhook>().fetch_all(exec).await
}

pub async fn find_by_id<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<Webhook>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(COLUMNS)
        .push(" FROM webhooks WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id);
    qb.build_query_as::<Webhook>().fetch_optional(exec).await
}

#[allow(clippy::too_many_arguments)]
pub async fn insert<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    name: &str,
    url: &str,
    secret_enc: &[u8],
    key_version: i32,
    events: &[String],
    enabled: bool,
    headers: &serde_json::Value,
    max_attempts: i32,
) -> Result<Webhook, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "INSERT INTO webhooks (id, tenant_id, name, url, secret_enc, key_version, events, enabled, \
         headers, max_attempts) VALUES (",
    );
    let mut s = qb.separated(", ");
    s.push_bind(id)
        .push_bind(tenant_id)
        .push_bind(name)
        .push_bind(url)
        .push_bind(secret_enc)
        .push_bind(key_version)
        .push_bind(events)
        .push_bind(enabled)
        .push_bind(headers)
        .push_bind(max_attempts);
    qb.push(") RETURNING ").push(COLUMNS);
    qb.build_query_as::<Webhook>().fetch_one(exec).await
}

pub async fn update<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    patch: &WebhookUpdate,
) -> Result<Option<Webhook>, sqlx::Error> {
    let mut qb = QueryBuilder::new("UPDATE webhooks SET updated_at = now()");
    if let Some(n) = &patch.name {
        qb.push(", name = ").push_bind(n);
    }
    if let Some(u) = &patch.url {
        qb.push(", url = ").push_bind(u);
    }
    if let Some(e) = &patch.events {
        qb.push(", events = ").push_bind(e);
    }
    if let Some(en) = patch.enabled {
        qb.push(", enabled = ").push_bind(en);
    }
    if let Some(h) = &patch.headers {
        qb.push(", headers = ").push_bind(h);
    }
    if let Some(m) = patch.max_attempts {
        qb.push(", max_attempts = ").push_bind(m);
    }
    qb.push(" WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id)
        .push(" RETURNING ")
        .push(COLUMNS);
    qb.build_query_as::<Webhook>().fetch_optional(exec).await
}

pub async fn set_secret<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    secret_enc: &[u8],
    key_version: i32,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE webhooks SET secret_enc = $3, key_version = $4, updated_at = now() \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(secret_enc)
    .bind(key_version)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn delete<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("DELETE FROM webhooks WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(exec)
        .await?;
    Ok(res.rows_affected() > 0)
}

// --- deliveries --------------------------------------------------------------

/// A delivery to queue.
pub struct NewDelivery<'a> {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub event_id: Uuid,
    pub event_name: &'a str,
    pub payload: serde_json::Value,
    pub max_attempts: i32,
}

/// Rows per statement: 7 binds a row stays well under Postgres' 65,535.
const ENQUEUE_CHUNK: usize = 1_000;

/// Queue deliveries of one tenant with as few statements as their number
/// allows.
pub async fn enqueue_many(
    conn: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    rows: &[NewDelivery<'_>],
) -> Result<(), sqlx::Error> {
    for chunk in rows.chunks(ENQUEUE_CHUNK) {
        let mut qb = QueryBuilder::new(
            "INSERT INTO webhook_deliveries (id, tenant_id, webhook_id, event_id, event_name, payload, \
             max_attempts) ",
        );
        qb.push_values(chunk, |mut b, d| {
            b.push_bind(d.id)
                .push_bind(tenant_id)
                .push_bind(d.webhook_id)
                .push_bind(d.event_id)
                .push_bind(d.event_name)
                .push_bind(&d.payload)
                .push_bind(d.max_attempts);
        });
        qb.build().execute(&mut *conn).await?;
    }
    Ok(())
}

/// Claim one delivery, if it is waiting to be sent.
pub async fn claim_one<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<WebhookDelivery>, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "UPDATE webhook_deliveries SET status = 'sending', next_attempt_at = now() WHERE tenant_id = ",
    );
    qb.push_bind(tenant_id)
        .push(" AND id = ")
        .push_bind(id)
        .push(" AND status IN ('pending', 'failed') RETURNING ")
        .push(DELIVERY_COLUMNS);
    qb.build_query_as::<WebhookDelivery>()
        .fetch_optional(exec)
        .await
}

/// Claim due deliveries (pending or retrying) for this tenant. A claim
/// stamps `next_attempt_at`, so a row is only taken for stuck once it has
/// been `sending` for a while, however long it waited to be claimed.
pub async fn claim_due<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    limit: i64,
) -> Result<Vec<WebhookDelivery>, sqlx::Error> {
    let mut qb = QueryBuilder::new(
        "UPDATE webhook_deliveries SET status = 'sending', next_attempt_at = now() WHERE id IN ( \
            SELECT id FROM webhook_deliveries WHERE tenant_id = ",
    );
    qb.push_bind(tenant_id)
        .push(" AND status IN ('pending', 'failed') AND next_attempt_at <= now() ORDER BY next_attempt_at LIMIT ")
        .push_bind(limit)
        .push(" FOR UPDATE SKIP LOCKED) AND tenant_id = ")
        .push_bind(tenant_id)
        .push(" RETURNING ")
        .push(DELIVERY_COLUMNS);
    qb.build_query_as::<WebhookDelivery>().fetch_all(exec).await
}

/// Deliveries still to be sent, across tenants (bypass transaction; a gauge).
pub async fn count_pending<'e>(exec: impl PgExecutor<'e>) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM webhook_deliveries WHERE status IN ('pending', 'failed', 'sending')",
    )
    .fetch_one(exec)
    .await
}

/// Tenants that have a delivery due right now (run in a bypass transaction:
/// the job visits only these instead of every tenant). Reads the live-rows
/// index.
pub async fn tenants_with_due<'e>(exec: impl PgExecutor<'e>) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT DISTINCT tenant_id FROM webhook_deliveries \
         WHERE status IN ('pending', 'failed') AND next_attempt_at <= now()",
    )
    .fetch_all(exec)
    .await
}

/// Deliveries stuck in `sending` (a node crashed or stopped mid-attempt) go
/// back to the queue, across tenants (bypass transaction; the delivery job
/// runs it before looking for due work). Reads the live-rows index.
pub async fn requeue_stale_all<'e>(
    exec: impl PgExecutor<'e>,
    stale_before: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE webhook_deliveries SET status = 'failed', next_attempt_at = now() \
         WHERE status = 'sending' AND next_attempt_at < $1",
    )
    .bind(stale_before)
    .execute(exec)
    .await?
    .rows_affected())
}

pub async fn mark_delivered<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    status_code: i32,
    snippet: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE webhook_deliveries SET status = 'delivered', attempts = attempts + 1, \
         last_status = $3, last_error = NULL, response_snippet = $4, delivered_at = now() \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(status_code)
    .bind(snippet)
    .execute(exec)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn mark_failed<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
    status_code: Option<i32>,
    error: &str,
    snippet: Option<&str>,
    next_attempt_at: DateTime<Utc>,
    dead: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE webhook_deliveries SET status = $7, attempts = attempts + 1, last_status = $3, \
         last_error = $4, response_snippet = $5, next_attempt_at = $6 \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(status_code)
    .bind(error)
    .bind(snippet)
    .bind(next_attempt_at)
    .bind(if dead { "dead" } else { "failed" })
    .execute(exec)
    .await?;
    Ok(())
}

pub async fn find_delivery<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    webhook_id: Uuid,
    id: Uuid,
) -> Result<Option<WebhookDelivery>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(DELIVERY_COLUMNS)
        .push(" FROM webhook_deliveries WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND webhook_id = ")
        .push_bind(webhook_id)
        .push(" AND id = ")
        .push_bind(id);
    qb.build_query_as::<WebhookDelivery>()
        .fetch_optional(exec)
        .await
}

pub async fn list_deliveries<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    webhook_id: Uuid,
    status: Option<DeliveryStatus>,
    limit: i64,
) -> Result<Vec<WebhookDelivery>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(DELIVERY_COLUMNS)
        .push(" FROM webhook_deliveries WHERE tenant_id = ")
        .push_bind(tenant_id)
        .push(" AND webhook_id = ")
        .push_bind(webhook_id);
    if let Some(s) = status {
        qb.push(" AND status = ").push_bind(s);
    }
    qb.push(" ORDER BY created_at DESC, id DESC LIMIT ")
        .push_bind(limit);
    qb.build_query_as::<WebhookDelivery>().fetch_all(exec).await
}

/// Requeue one delivery (dead or failed) for an immediate attempt.
/// Every dead delivery of one webhook back to the queue.
pub async fn requeue_dead<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    webhook_id: Uuid,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE webhook_deliveries SET status = 'pending', attempts = 0, next_attempt_at = now(), \
         last_error = NULL WHERE tenant_id = $1 AND webhook_id = $2 AND status = 'dead'",
    )
    .bind(tenant_id)
    .bind(webhook_id)
    .execute(exec)
    .await?
    .rows_affected())
}

pub async fn requeue<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE webhook_deliveries SET status = 'pending', attempts = 0, next_attempt_at = now(), \
         last_error = NULL WHERE tenant_id = $1 AND id = $2 AND status IN ('dead', 'failed', 'delivered')",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(exec)
    .await?;
    Ok(res.rows_affected() > 0)
}
