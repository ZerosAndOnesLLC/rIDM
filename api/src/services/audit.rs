//! Audit log: every domain event is appended to a per-tenant hash chain
//! (`hash = SHA-256(prev_hash || canonical row)`), so a row changed or
//! removed inside the retained window breaks verification. Global events
//! (no tenant) form their own chain.

use chrono::{DateTime, Duration, Utc};
use futures::stream::{self, Stream};
use ridm_core::audit_chain::{self, CanonicalRow, Verifier};
use ridm_core::events::Envelope;
use ridm_core::events::{Actor, Event, EventSink as _};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
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
const SUBJECT_KEYS: [&str; 11] = [
    "user_id",
    "client_id",
    "role_id",
    "group_id",
    "org_id",
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

/// The fields of a row its hash covers ([`ridm_core::audit_chain`] holds the
/// algorithm, so an export can be checked without this server).
pub fn canonical_view(row: &AuditEvent) -> CanonicalRow<'_> {
    CanonicalRow {
        id: row.id,
        tenant_id: row.tenant_id,
        seq: row.seq,
        occurred_at: row.occurred_at,
        name: &row.name,
        actor_type: &row.actor_type,
        actor_id: row.actor_id,
        subject_id: row.subject_id,
        impersonator_id: row.impersonator_id,
        ip: row.ip.as_deref(),
        user_agent: row.user_agent.as_deref(),
        payload: &row.payload,
    }
}

fn hash_of(prev: Option<&[u8]>, row: &AuditEvent) -> Vec<u8> {
    audit_chain::hash(prev, &canonical_view(row))
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
        impersonator_id: event.impersonator,
        ip: event.ip.clone(),
        user_agent: event.user_agent.clone(),
        payload,
        prev_hash,
        hash: vec![],
    };
    row.hash = hash_of(row.prev_hash.as_deref(), &row);
    repos::audit::insert(&mut *tx, &row).await?;
    repos::audit_chains::advance_head(&mut *tx, chain, row.tenant_id, row.seq, &row.hash).await?;
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
                Ok(envelope) => match record(&state, &envelope.event).await {
                    Ok(_) => {
                        metrics::counter!("ridm_audit_events_total").increment(1);
                    }
                    Err(err) => {
                        tracing::error!(
                            event = envelope.event.name(),
                            error = %err,
                            "audit: could not record event"
                        );
                    }
                },
                Err(RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "audit: event bus lagged, events not recorded");
                }
                Err(RecvError::Closed) => break,
            }
        }
    })
}

/// The audit trail of a one-shot command (`ridm-api bootstrap`,
/// `ridm-api rotate-master-key`, `ridm bootstrap`). A server records through
/// [`spawn_writer`]; a command exits as soon as it has acted, before a
/// background task would get to the events, so it subscribes before acting
/// and writes what was published before it exits. The export sink ships
/// the rows later, from the database, like any others.
pub struct CommandRecorder {
    rx: broadcast::Receiver<Envelope>,
}

impl CommandRecorder {
    pub fn start(state: &AppState) -> Self {
        Self {
            rx: state.events.subscribe(),
        }
    }

    /// Record every event published since [`CommandRecorder::start`].
    /// Returns how many could not be recorded (each is also logged).
    pub async fn flush(mut self, state: &AppState) -> usize {
        let mut failed = 0;
        loop {
            match self.rx.try_recv() {
                Ok(envelope) => {
                    if let Err(err) = record(state, &envelope.event).await {
                        failed += 1;
                        tracing::error!(
                            event = envelope.event.name(),
                            error = %err,
                            "audit: could not record event"
                        );
                    }
                }
                Err(TryRecvError::Lagged(n)) => {
                    failed += n as usize;
                    tracing::warn!(skipped = n, "audit: event bus lagged, events not recorded");
                }
                Err(TryRecvError::Empty | TryRecvError::Closed) => return failed,
            }
        }
    }
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
            let mut tx = db::read_tx(&state.db_read, t).await?;
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
    /// Hash of the newest row checked (lowercase hex): keep it, and a later
    /// `ridm audit verify --head` proves an export still ends where it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_hash: Option<String>,
    /// Chain position of the first row whose hash or link does not match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_at_seq: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The daily verification job's progress on this chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduled: Option<ScheduledVerification>,
}

/// What the `audit_verify` job last established about a chain.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ScheduledVerification {
    /// The chain is intact up to here.
    pub verified_seq: Option<i64>,
    pub verified_at: Option<DateTime<Utc>>,
    /// Where the job found the chain broken, while it stays broken.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_at_seq: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_reason: Option<String>,
}

/// Where a walk ended.
struct Walk {
    verifier: Verifier,
    broken: Option<audit_chain::Break>,
}

/// Walk `chain` oldest first from after `from` (a row already known good),
/// or from its oldest retained row.
async fn walk(state: &AppState, chain: Uuid, from: Option<(i64, Vec<u8>)>) -> AppResult<Walk> {
    let (mut verifier, mut after) = match from {
        Some((seq, hash)) => (Verifier::after(chain, seq, hash), Some(seq)),
        None => (Verifier::new(), None),
    };
    loop {
        let mut tx = db::bypass_tx(&state.db).await?;
        let rows =
            repos::audit::chain_page(&mut *tx, chain, &AuditFilter::default(), after, EXPORT_PAGE)
                .await?;
        tx.commit().await?;
        for row in &rows {
            if let Err(b) =
                verifier.check(&canonical_view(row), row.prev_hash.as_deref(), &row.hash)
            {
                return Ok(Walk {
                    verifier,
                    broken: Some(b),
                });
            }
        }
        after = rows.last().map(|r| r.seq);
        if (rows.len() as i64) < EXPORT_PAGE {
            return Ok(Walk {
                verifier,
                broken: None,
            });
        }
    }
}

/// Walk the chain from the oldest retained row and recompute every hash.
/// The oldest row's `prev_hash` may point at a purged row; from there on
/// every link must match.
pub async fn verify(state: &AppState, tenant_id: Option<Uuid>) -> AppResult<Verification> {
    let chain = repos::audit::chain_id(tenant_id);
    let w = walk(state, chain, None).await?;
    let mut tx = db::bypass_tx(&state.db).await?;
    let known = repos::audit_chains::state(&mut *tx, chain).await?;
    tx.commit().await?;
    let v = &w.verifier;
    Ok(Verification {
        checked: v.checked,
        valid: w.broken.is_none(),
        first_seq: v.first_seq.or(w.broken.as_ref().map(|b| b.seq)),
        last_seq: v.last_seq,
        last_hash: v.last_hash.as_ref().map(hex::encode),
        broken_at_seq: w.broken.as_ref().map(|b| b.seq),
        reason: w.broken.map(|b| b.reason),
        scheduled: known.map(|k| ScheduledVerification {
            verified_seq: k.verified_seq,
            verified_at: k.verified_at,
            broken_at_seq: k.broken_at_seq,
            broken_reason: k.broken_reason,
        }),
    })
}

/// One pass of the `audit_verify` job: walk every chain that grew since it
/// was last found intact, from that checkpoint on. A break is recorded on
/// the chain, logged, counted and — the first time it is seen at that row —
/// published as `audit.chain_broken`, which lands in the broken chain itself
/// and reaches the tenant's webhooks. Returns the rows checked.
///
/// Rows at or before a checkpoint are not rehashed on every pass (that is
/// what keeps the job cheap on a large log); the checkpoint row itself is,
/// so a rewrite that reaches it is caught, and the verify endpoint and
/// `ridm audit verify` always walk the whole retained chain.
pub async fn verify_pending(state: &AppState) -> AppResult<u64> {
    const PAGE: i64 = 200;
    let mut checked = 0;
    let mut after = None;
    loop {
        let mut tx = db::bypass_tx(&state.db).await?;
        let chains = repos::audit_chains::unverified(&mut *tx, after, PAGE).await?;
        tx.commit().await?;
        for c in &chains {
            checked += verify_one(state, c).await?.checked;
        }
        after = chains.last().map(|c| c.chain_id);
        if (chains.len() as i64) < PAGE {
            break;
        }
    }
    let mut tx = db::bypass_tx(&state.db).await?;
    let broken = repos::audit_chains::broken_count(&mut *tx).await?;
    tx.commit().await?;
    metrics::gauge!("ridm_audit_chains_broken").set(broken as f64);
    Ok(checked)
}

/// What one scheduled check of a chain found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainCheck {
    pub checked: u64,
    /// Where the chain is broken, when it is.
    pub broken_at_seq: Option<i64>,
}

/// The scheduled check of one chain (`None`: the global chain), from its
/// last verified checkpoint on.
pub async fn verify_chain(state: &AppState, tenant_id: Option<Uuid>) -> AppResult<ChainCheck> {
    let chain = repos::audit::chain_id(tenant_id);
    let mut tx = db::bypass_tx(&state.db).await?;
    let known = repos::audit_chains::verification_of(&mut *tx, chain).await?;
    tx.commit().await?;
    match known {
        Some(c) => verify_one(state, &c).await,
        None => Ok(ChainCheck {
            checked: 0,
            broken_at_seq: None,
        }),
    }
}

async fn verify_one(
    state: &AppState,
    c: &repos::audit_chains::Unverified,
) -> AppResult<ChainCheck> {
    // Start at the checkpoint row itself when it is still retained, so its
    // hash is checked against the one recorded for it.
    let from = match (c.verified_seq, &c.verified_hash, c.broken_at_seq) {
        (Some(seq), Some(hash), None) => checkpoint_intact(state, c.chain_id, seq, hash).await?,
        _ => None,
    };
    let w = match from {
        Some(Err(b)) => Walk {
            verifier: Verifier::new(),
            broken: Some(b),
        },
        Some(Ok(start)) => walk(state, c.chain_id, Some(start)).await?,
        None => walk(state, c.chain_id, None).await?,
    };
    let checked = w.verifier.checked;
    let mut tx = db::bypass_tx(&state.db).await?;
    let Some(b) = w.broken else {
        if let (Some(seq), Some(hash)) = (w.verifier.last_seq, &w.verifier.last_hash) {
            repos::audit_chains::set_verified(&mut *tx, c.chain_id, seq, hash).await?;
        }
        tx.commit().await?;
        return Ok(ChainCheck {
            checked,
            broken_at_seq: None,
        });
    };
    let new = repos::audit_chains::set_broken(&mut *tx, c.chain_id, b.seq, &b.reason).await?;
    tx.commit().await?;
    tracing::error!(chain = %c.chain_id, seq = b.seq, reason = %b.reason, "audit chain does not verify");
    if new {
        metrics::counter!("ridm_audit_chain_breaks_total").increment(1);
        state.events.publish(Event::new(
            c.tenant_id,
            Actor::System,
            ridm_core::events::EventKind::AuditChainBroken {
                seq: b.seq,
                reason: b.reason,
            },
        ));
    }
    Ok(ChainCheck {
        checked,
        broken_at_seq: Some(b.seq),
    })
}

/// `Some(Ok(checkpoint))` when the checkpoint row is retained and still
/// hashes to what was recorded for it, `Some(Err(..))` when it does not, and
/// `None` when retention has purged it (the walk then starts at the oldest
/// row).
async fn checkpoint_intact(
    state: &AppState,
    chain: Uuid,
    seq: i64,
    hash: &[u8],
) -> AppResult<Option<Result<(i64, Vec<u8>), audit_chain::Break>>> {
    let mut tx = db::bypass_tx(&state.db).await?;
    let rows = repos::audit::chain_page(&mut *tx, chain, &AuditFilter::default(), Some(seq - 1), 1)
        .await?;
    tx.commit().await?;
    let Some(row) = rows.into_iter().next().filter(|r| r.seq == seq) else {
        return Ok(None);
    };
    if row.hash != hash || hash_of(row.prev_hash.as_deref(), &row) != row.hash {
        return Ok(Some(Err(audit_chain::Break {
            seq,
            reason: "the last verified row has changed since it was verified".into(),
        })));
    }
    Ok(Some(Ok((seq, row.hash))))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Json,
    Csv,
}

/// New columns go at the end, so a reader written for an older export keeps
/// finding every column where it was.
const CSV_HEADER: [&str; 13] = [
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
    "impersonator_id",
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
            r.impersonator_id.map(|u| u.to_string()).unwrap_or_default(),
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
