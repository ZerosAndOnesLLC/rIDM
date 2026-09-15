//! Audit log: every domain event is appended to a per-tenant hash chain
//! (`hash = SHA-256(prev_hash || canonical row)`), so a row changed or
//! removed inside the retained window breaks verification. Global events
//! (no tenant) form their own chain.

use chrono::{DateTime, Duration, Utc};
use futures::stream::{self, Stream};
use ridm_core::events::{Actor, Event};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use tokio::sync::broadcast::error::RecvError;
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{AuditEvent, AuditFilter};
use crate::repos;
use crate::state::AppState;
use crate::util::cursor::{Cursor, Page, page_size};

const EXPORT_PAGE: i64 = 500;
const PURGE_BATCH: i64 = 5_000;

/// Payload keys that name the entity an event is about, in priority order.
const SUBJECT_KEYS: [&str; 10] = [
    "user_id",
    "client_id",
    "role_id",
    "group_id",
    "invitation_id",
    "key_id",
    "mapper_id",
    "resource_server_id",
    "scope_id",
    "session_id",
];

fn actor_parts(actor: &Actor) -> (&'static str, Option<Uuid>) {
    match actor {
        Actor::User { id } => ("user", Some(*id)),
        Actor::Client { id } => ("client", Some(*id)),
        Actor::Admin { id } => ("admin", Some(*id)),
        Actor::System => ("system", None),
    }
}

fn subject_of(payload: &Value) -> Option<Uuid> {
    let obj = payload.as_object()?;
    SUBJECT_KEYS
        .iter()
        .find_map(|k| obj.get(*k).and_then(Value::as_str))
        .and_then(|s| Uuid::parse_str(s).ok())
}

/// The bytes the chain hash covers. Field order is fixed; the payload is
/// serialized with sorted keys (serde_json's default map), so the same row
/// always hashes the same way.
fn canonical(row: &AuditEvent) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        row.id,
        repos::audit::chain_id(row.tenant_id),
        row.seq,
        row.occurred_at
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        row.name,
        row.actor_type,
        row.actor_id.map(|u| u.to_string()).unwrap_or_default(),
        row.subject_id.map(|u| u.to_string()).unwrap_or_default(),
        row.ip.clone().unwrap_or_default(),
        row.user_agent.clone().unwrap_or_default(),
        row.payload,
    )
    .into_bytes()
}

fn hash_of(prev: Option<&[u8]>, row: &AuditEvent) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(prev.unwrap_or(&[]));
    h.update(canonical(row));
    h.finalize().to_vec()
}

/// Append one event to its chain.
pub async fn record(state: &AppState, event: &Event) -> AppResult<AuditEvent> {
    let (actor_type, actor_id) = actor_parts(&event.actor);
    let payload = serde_json::to_value(&event.kind)?;
    let chain = repos::audit::chain_id(event.tenant_id);
    let mut tx = db::bypass_tx(&state.db).await?;
    repos::audit::lock_chain(&mut *tx, chain).await?;
    let head = repos::audit::chain_head(&mut *tx, chain).await?;
    let (seq, prev_hash) = match head {
        Some((seq, hash)) => (seq + 1, Some(hash)),
        None => (1, None),
    };
    let mut row = AuditEvent {
        id: event.id,
        tenant_id: event.tenant_id,
        seq,
        occurred_at: event.occurred_at,
        recorded_at: Utc::now(),
        name: event.name().to_string(),
        actor_type: actor_type.to_string(),
        actor_id,
        subject_id: subject_of(&payload),
        ip: event.ip.clone(),
        user_agent: event.user_agent.clone(),
        payload,
        prev_hash,
        hash: vec![],
    };
    row.hash = hash_of(row.prev_hash.as_deref(), &row);
    repos::audit::insert(&mut *tx, &row).await?;
    tx.commit().await?;
    Ok(row)
}

/// Subscribe to the event bus and append everything that comes through.
/// Lagging (the bus dropped events under load) is logged: the audit log is
/// best-effort append, never a reason to fail the action itself.
pub fn spawn_writer(state: AppState) -> tokio::task::JoinHandle<()> {
    let mut rx = state.events.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(envelope) => {
                    if let Err(err) = record(&state, &envelope.event).await {
                        tracing::error!(
                            event = envelope.event.name(),
                            error = %err,
                            "audit: could not record event"
                        );
                    }
                }
                Err(RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "audit: event bus lagged, events not recorded");
                }
                Err(RecvError::Closed) => break,
            }
        }
    })
}

/// Newest first. `tenant_id = None` reads the global chain.
pub async fn list(
    state: &AppState,
    tenant_id: Option<Uuid>,
    filter: &AuditFilter,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> AppResult<Page<AuditEvent>> {
    let before = cursor.map(Cursor::decode).transpose()?;
    let limit = page_size(limit);
    let rows = match tenant_id {
        Some(t) => {
            let mut tx = db::tenant_tx(&state.db, t).await?;
            let rows = repos::audit::list(&mut *tx, Some(t), filter, before, limit).await?;
            tx.commit().await?;
            rows
        }
        None => {
            let mut tx = db::bypass_tx(&state.db).await?;
            let rows = repos::audit::list(&mut *tx, None, filter, before, limit).await?;
            tx.commit().await?;
            rows
        }
    };
    Ok(Page::from_rows(rows, limit, |r| Cursor {
        created_at: r.occurred_at,
        id: r.id,
    }))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Verification {
    /// Rows checked, oldest retained first.
    pub checked: u64,
    pub valid: bool,
    pub first_seq: Option<i64>,
    pub last_seq: Option<i64>,
    /// Chain position of the first row whose hash or link does not match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_at_seq: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Walk the chain from the oldest retained row and recompute every hash.
/// The oldest row's `prev_hash` may point at a purged row; from there on
/// every link must match.
pub async fn verify(state: &AppState, tenant_id: Option<Uuid>) -> AppResult<Verification> {
    let chain = repos::audit::chain_id(tenant_id);
    let mut out = Verification {
        checked: 0,
        valid: true,
        first_seq: None,
        last_seq: None,
        broken_at_seq: None,
        reason: None,
    };
    let mut after = None;
    let mut prev: Option<(i64, Vec<u8>)> = None;
    loop {
        let mut tx = db::bypass_tx(&state.db).await?;
        let rows =
            repos::audit::chain_page(&mut *tx, chain, &AuditFilter::default(), after, EXPORT_PAGE)
                .await?;
        tx.commit().await?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            out.checked += 1;
            if out.first_seq.is_none() {
                out.first_seq = Some(row.seq);
            }
            out.last_seq = Some(row.seq);
            let problem = match &prev {
                Some((seq, hash)) if row.seq != seq + 1 => {
                    Some(format!("gap in chain after seq {seq}"))
                }
                Some((_, hash)) if row.prev_hash.as_deref() != Some(hash.as_slice()) => {
                    Some("prev_hash does not link to the previous row".into())
                }
                _ if hash_of(row.prev_hash.as_deref(), row) != row.hash => {
                    Some("row hash does not match its contents".into())
                }
                _ => None,
            };
            if let Some(reason) = problem {
                out.valid = false;
                out.broken_at_seq = Some(row.seq);
                out.reason = Some(reason);
                return Ok(out);
            }
            prev = Some((row.seq, row.hash.clone()));
        }
        after = rows.last().map(|r| r.seq);
        if (rows.len() as i64) < EXPORT_PAGE {
            break;
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Json,
    Csv,
}

const CSV_HEADER: [&str; 12] = [
    "seq",
    "id",
    "occurred_at",
    "name",
    "actor_type",
    "actor_id",
    "subject_id",
    "ip",
    "user_agent",
    "payload",
    "prev_hash",
    "hash",
];

fn csv_chunk(rows: &[AuditEvent], with_header: bool) -> AppResult<Vec<u8>> {
    let mut w = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(Vec::new());
    let io = |e: csv::Error| AppError::Internal(format!("csv: {e}"));
    if with_header {
        w.write_record(CSV_HEADER).map_err(io)?;
    }
    for r in rows {
        w.write_record([
            r.seq.to_string(),
            r.id.to_string(),
            r.occurred_at.to_rfc3339(),
            r.name.clone(),
            r.actor_type.clone(),
            r.actor_id.map(|u| u.to_string()).unwrap_or_default(),
            r.subject_id.map(|u| u.to_string()).unwrap_or_default(),
            r.ip.clone().unwrap_or_default(),
            r.user_agent.clone().unwrap_or_default(),
            r.payload.to_string(),
            r.prev_hash.as_ref().map(hex::encode).unwrap_or_default(),
            hex::encode(&r.hash),
        ])
        .map_err(io)?;
    }
    w.into_inner()
        .map_err(|e| AppError::Internal(format!("csv: {e}")))
}

/// Stream a chain oldest-first as JSON or CSV, honouring the filter.
pub fn export(
    state: AppState,
    tenant_id: Option<Uuid>,
    filter: AuditFilter,
    format: ExportFormat,
) -> impl Stream<Item = AppResult<Vec<u8>>> {
    let chain = repos::audit::chain_id(tenant_id);
    enum Step {
        Page(Option<i64>, bool),
        Done,
    }
    stream::try_unfold(Step::Page(None, true), move |step| {
        let state = state.clone();
        let filter = filter.clone();
        async move {
            let (after, first) = match step {
                Step::Page(a, first) => (a, first),
                Step::Done => return Ok(None),
            };
            let rows = {
                let mut tx = db::bypass_tx(&state.db).await?;
                let rows =
                    repos::audit::chain_page(&mut *tx, chain, &filter, after, EXPORT_PAGE).await?;
                tx.commit().await?;
                rows
            };
            let last = (rows.len() as i64) < EXPORT_PAGE;
            let mut chunk = match format {
                ExportFormat::Json => {
                    let mut out = Vec::new();
                    if first {
                        out.push(b'[');
                    }
                    for (i, r) in rows.iter().enumerate() {
                        if !first || i > 0 {
                            out.push(b',');
                        }
                        serde_json::to_writer(&mut out, r)?;
                    }
                    out
                }
                ExportFormat::Csv => csv_chunk(&rows, first)?,
            };
            if last && format == ExportFormat::Json {
                chunk.extend_from_slice(b"]\n");
            }
            let next = if last {
                Step::Done
            } else {
                Step::Page(rows.last().map(|r| r.seq), false)
            };
            Ok(Some((chunk, next)))
        }
    })
}

/// Drop the expired prefix of a chain: every row up to the newest one older
/// than `retention_days` (0 keeps everything). Deleting a prefix rather than
/// individual old rows keeps the surviving chain contiguous and verifiable.
pub async fn purge(
    state: &AppState,
    tenant_id: Option<Uuid>,
    retention_days: u32,
) -> AppResult<u64> {
    if retention_days == 0 {
        return Ok(0);
    }
    let cutoff: DateTime<Utc> = Utc::now() - Duration::days(i64::from(retention_days));
    let chain = repos::audit::chain_id(tenant_id);
    let up_to = {
        let mut tx = db::bypass_tx(&state.db).await?;
        let head = repos::audit::expired_head(&mut *tx, chain, cutoff).await?;
        tx.commit().await?;
        head
    };
    let Some(up_to) = up_to else {
        return Ok(0);
    };
    let mut total = 0;
    loop {
        let mut tx = db::bypass_tx(&state.db).await?;
        let n = repos::audit::purge_prefix(&mut *tx, chain, up_to, PURGE_BATCH).await?;
        tx.commit().await?;
        total += n;
        if (n as i64) < PURGE_BATCH {
            break;
        }
    }
    Ok(total)
}

/// Make sure the monthly partitions for the coming months exist.
pub async fn ensure_partitions(state: &AppState) -> AppResult<i32> {
    let mut tx = db::bypass_tx(&state.db).await?;
    let n = repos::audit::ensure_partitions(&mut *tx, 2).await?;
    tx.commit().await?;
    Ok(n)
}
