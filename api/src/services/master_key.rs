//! Master key rotation: re-encrypt every `*_enc` column under the current key
//! generation. Runs online: each row is decrypted with the generation recorded
//! on it and rewritten with an optimistic `key_version` check, so concurrent
//! writers and other rotation runs never clobber each other.

use std::collections::BTreeMap;

use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use ridm_core::providers::Encrypted;
use serde::Serialize;
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

const BATCH: i64 = 200;

/// Tables holding envelope-encrypted columns.
const TABLES: &[EncryptedTable] = &[
    EncryptedTable {
        table: "signing_keys",
        column: "private_key_enc",
        aad_prefix: "signing_keys",
        id_column: "id",
        id_type: "uuid",
    },
    EncryptedTable {
        table: "credentials",
        column: "data_enc",
        aad_prefix: "credentials",
        id_column: "id",
        id_type: "uuid",
    },
    EncryptedTable {
        table: "tenant_provider_settings",
        column: "config_enc",
        aad_prefix: "provider_settings",
        id_column: "kind",
        id_type: "text",
    },
    EncryptedTable {
        table: "identity_providers",
        column: "client_secret_enc",
        aad_prefix: "identity_providers",
        id_column: "id",
        id_type: "uuid",
    },
    EncryptedTable {
        table: "webhooks",
        column: "secret_enc",
        aad_prefix: "webhooks",
        id_column: "id",
        id_type: "uuid",
    },
    EncryptedTable {
        table: "saml_signing_keys",
        column: "private_key_enc",
        aad_prefix: "saml_signing_keys",
        id_column: "id",
        id_type: "uuid",
    },
];

struct EncryptedTable {
    table: &'static str,
    column: &'static str,
    aad_prefix: &'static str,
    /// Row identifier column (uuid `id`, or a text key for keyed tables).
    id_column: &'static str,
    /// Its type, for casting the text form back.
    id_type: &'static str,
}

impl EncryptedTable {
    fn aad(&self, tenant_id: Uuid, id: &str) -> Vec<u8> {
        format!("{}:{tenant_id}:{id}", self.aad_prefix).into_bytes()
    }
}

#[derive(Debug, Default, Serialize, utoipa::ToSchema)]
pub struct RotationReport {
    pub target_version: u32,
    /// Rows re-encrypted per table.
    pub rewritten: BTreeMap<String, u64>,
    /// Rows that could not be re-encrypted (unknown generation, corrupt blob).
    pub failed: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct StatusReport {
    pub current_version: u32,
    pub known_versions: Vec<u32>,
    /// Every generation: from the environment (`env`) or wrapped by a key
    /// custody backend, and whether this node holds it.
    pub generations: Vec<crate::key_custody::generations::GenerationInfo>,
    /// The backend new generations are wrapped by (`KEY_WRAPPER`), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_wrapper: Option<String>,
    /// table → (key_version → rows)
    pub rows_by_version: BTreeMap<String, BTreeMap<i32, i64>>,
}

impl StatusReport {
    pub fn pending(&self) -> i64 {
        let current = self.current_version as i32;
        self.rows_by_version
            .values()
            .flat_map(|m| m.iter())
            .filter(|(v, _)| **v != current)
            .map(|(_, n)| *n)
            .sum()
    }
}

/// Count rows per key generation for every encrypted table, summed over
/// every database (home and regions).
pub async fn status(state: &AppState) -> AppResult<StatusReport> {
    let mut rows_by_version: BTreeMap<String, BTreeMap<i32, i64>> = BTreeMap::new();
    for database in state.db.all() {
        let mut tx = db::bypass_tx(&database.primary).await?;
        for t in TABLES {
            // Table names are compile-time constants from TABLES, never user input.
            let sql = format!(
                "SELECT key_version, count(*) FROM {} GROUP BY key_version ORDER BY key_version",
                t.table
            );
            let rows: Vec<(i32, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .fetch_all(&mut *tx)
                .await?;
            let counts = rows_by_version.entry(t.table.to_string()).or_default();
            for (version, n) in rows {
                *counts.entry(version).or_default() += n;
            }
        }
        tx.commit().await?;
    }
    let known = match state.key_encryptor.as_ref().known_versions_hint() {
        Some(v) => v,
        None => vec![state.key_encryptor.current_version()],
    };
    let generations = state
        .master_keys
        .describe()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(StatusReport {
        current_version: state.key_encryptor.current_version(),
        known_versions: known,
        generations,
        key_wrapper: state.master_keys.primary_backend().map(str::to_string),
        rows_by_version,
    })
}

/// Have the key custody backend wrap a new generation and make it current
/// (`rotate-master-key --new-generation`); [`rotate_all`] then moves every
/// row onto it.
pub async fn new_generation(state: &AppState) -> AppResult<u32> {
    let version = state
        .master_keys
        .new_generation()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    state.events.publish(Event::new(
        None,
        Actor::System,
        EventKind::MasterKeyGenerationCreated {
            version,
            backend: state
                .master_keys
                .primary_backend()
                .unwrap_or_default()
                .to_string(),
        },
    ));
    Ok(version)
}

/// The highest generation any stored secret is under. A new generation must
/// be above it: numbering one below would shadow rows still under an older
/// key (a node started with `KEY_WRAPPER` but without the `MASTER_KEY` those
/// rows were written with). One aggregate per table, run only when a
/// generation is created, in every database.
pub async fn highest_version_in_use(db: &crate::db::Db) -> Result<u32, sqlx::Error> {
    // Table names are compile-time constants from TABLES.
    let sql = TABLES
        .iter()
        .map(|t| format!("SELECT max(key_version) AS v FROM {}", t.table))
        .collect::<Vec<_>>()
        .join(" UNION ALL ");
    let sql = format!("SELECT max(v) FROM ({sql}) AS versions");
    let mut highest = 0;
    for database in db.all() {
        let mut tx = db::bypass_tx(&database.primary).await?;
        let found: Option<i32> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql.clone()))
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        highest = highest.max(found.unwrap_or(0));
    }
    Ok(highest.max(0) as u32)
}

/// Re-encrypt everything not yet under the current generation.
pub async fn rotate_all(state: &AppState) -> AppResult<RotationReport> {
    // Adopt a generation another process created since this node started.
    state
        .master_keys
        .refresh()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let target = state.key_encryptor.current_version();
    let mut report = RotationReport {
        target_version: target,
        ..Default::default()
    };
    for database in state.db.all() {
        for t in TABLES {
            let (ok, failed) = rotate_table(state, &database.primary, t, target).await?;
            *report.rewritten.entry(t.table.to_string()).or_default() += ok;
            *report.failed.entry(t.table.to_string()).or_default() += failed;
        }
    }
    let total: u64 = report.rewritten.values().sum();
    if total > 0 {
        state.events.publish(Event::new(
            None,
            Actor::System,
            EventKind::MasterKeyRotated {
                new_version: target,
            },
        ));
    }
    tracing::info!(
        target,
        rewritten = total,
        "master key rotation pass complete"
    );
    Ok(report)
}

/// Rows re-encrypted at the same time within a batch (a key custody
/// backend may be a network round trip per row).
const REENCRYPT_CONCURRENCY: usize = 8;

/// Move every row of `t` in this database onto generation `target`, one
/// older generation at a time, in `(tenant_id, id)` order from a cursor: each
/// batch is one index range read and one update, and a row that fails is
/// passed over by the cursor (and counted) rather than read again.
async fn rotate_table(
    state: &AppState,
    pool: &sqlx::PgPool,
    t: &EncryptedTable,
    target: u32,
) -> AppResult<(u64, u64)> {
    use futures::StreamExt as _;
    let mut ok = 0u64;
    let mut failed = 0u64;
    // The generations in use besides the target, one index probe each (a
    // loose index scan over `key_version`), not a scan of the table.
    let versions: Vec<i32> = {
        let sql = format!(
            "WITH RECURSIVE v AS ( \
               SELECT min(key_version) AS k FROM {table} \
               UNION ALL \
               SELECT (SELECT min(key_version) FROM {table} WHERE key_version > v.k) FROM v WHERE v.k IS NOT NULL) \
             SELECT k FROM v WHERE k IS NOT NULL AND k <> $1",
            table = t.table
        );
        let mut tx = db::bypass_tx(pool).await?;
        let versions = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(target as i32)
            .fetch_all(&mut *tx)
            .await?;
        tx.commit().await?;
        versions
    };
    for version in versions {
        let mut after: Option<(Uuid, String)> = None;
        loop {
            let mut sql = format!(
                "SELECT {id}::text, tenant_id, {col} FROM {table} WHERE key_version = $1",
                id = t.id_column,
                col = t.column,
                table = t.table
            );
            if after.is_some() {
                sql.push_str(&format!(
                    " AND (tenant_id, {id}) > ($3, $4::{ty})",
                    id = t.id_column,
                    ty = t.id_type
                ));
            }
            sql.push_str(&format!(" ORDER BY tenant_id, {} LIMIT $2", t.id_column));
            let mut tx = db::bypass_tx(pool).await?;
            let mut query = sqlx::query_as::<_, (String, Uuid, Vec<u8>)>(sqlx::AssertSqlSafe(sql))
                .bind(version)
                .bind(BATCH);
            if let Some((tenant_id, id)) = &after {
                query = query.bind(*tenant_id).bind(id.clone());
            }
            let rows = query.fetch_all(&mut *tx).await?;
            tx.commit().await?;
            let Some((last_id, last_tenant, _)) = rows.last() else {
                break;
            };
            after = Some((*last_tenant, last_id.clone()));
            let full = rows.len() as i64 == BATCH;
            let outcomes: Vec<(String, Uuid, AppResult<Vec<u8>>)> = futures::stream::iter(rows)
                .map(|(id, tenant_id, blob)| async move {
                    let fresh = reencrypt(state, t, tenant_id, &id, &blob).await;
                    (id, tenant_id, fresh)
                })
                .buffer_unordered(REENCRYPT_CONCURRENCY)
                .collect()
                .await;
            let (mut ids, mut tenants, mut blobs) = (vec![], vec![], vec![]);
            for (id, tenant_id, fresh) in outcomes {
                match fresh {
                    Ok(blob) => {
                        ids.push(id);
                        tenants.push(tenant_id);
                        blobs.push(blob);
                    }
                    Err(err) => {
                        tracing::error!(table = t.table, %id, %tenant_id, error = %err, "re-encryption failed");
                        failed += 1;
                    }
                }
            }
            if !ids.is_empty() {
                // Only rows still on the generation they were read under: one
                // rewritten meanwhile (by a writer or another rotation run) is
                // left as it is.
                let sql = format!(
                    "UPDATE {table} AS t SET {col} = u.blob, key_version = $4 \
                     FROM unnest($1::text[], $2::uuid[], $3::bytea[]) AS u(id, tenant_id, blob) \
                     WHERE t.{idc} = u.id::{ty} AND t.tenant_id = u.tenant_id AND t.key_version = $5",
                    table = t.table,
                    col = t.column,
                    idc = t.id_column,
                    ty = t.id_type
                );
                let mut tx = db::bypass_tx(pool).await?;
                let n = sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(&ids)
                    .bind(&tenants)
                    .bind(&blobs)
                    .bind(target as i32)
                    .bind(version)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
                tx.commit().await?;
                ok += n;
            }
            if !full {
                break;
            }
        }
    }
    Ok((ok, failed))
}

/// What [`check`] found.
#[derive(Debug, Default)]
pub struct CheckReport {
    /// Sampled signing keys that decrypted.
    pub signing_keys_ok: usize,
    pub failures: Vec<CheckFailure>,
}

/// A stored secret the configured master keys could not decrypt.
#[derive(Debug)]
pub struct CheckFailure {
    pub table: &'static str,
    pub key_version: i32,
    pub error: String,
}

/// Decrypt a sample of stored secrets with the configured keys, to catch a
/// wrong `MASTER_KEY` (or a generation missing from `MASTER_KEY_PREVIOUS`)
/// at start-up rather than at the first sign-in. That is the classic mistake
/// after a restore: the server starts and reports ready, then fails every
/// token request, and generates new signing keys under the wrong key for
/// tenants that had none. One signing key per generation is tried (the table
/// is small: a few keys per tenant), and the first row of every other
/// encrypted table, which reads no further than one row whatever its size.
/// Every database is sampled: a region restored with the wrong key fails
/// the same way.
pub async fn check(state: &AppState) -> AppResult<CheckReport> {
    let mut samples: Vec<Sample> = vec![];
    for database in state.db.all() {
        match sample(&database.primary, &mut samples).await {
            Ok(()) => {}
            // A region that is down is checked when a node next starts.
            Err(err) if !database.is_home() => {
                tracing::error!(region = %database.name, error = %err, "master key check skipped a region");
            }
            Err(err) => return Err(err),
        }
    }
    let mut report = CheckReport::default();
    for (t, id, tenant_id, blob, key_version) in samples {
        match decrypt_row(state, t, tenant_id, &id, &blob).await {
            Ok(_) if t.table == "signing_keys" => report.signing_keys_ok += 1,
            Ok(_) => {}
            Err(err) => report.failures.push(CheckFailure {
                table: t.table,
                key_version,
                error: err.to_string(),
            }),
        }
    }
    Ok(report)
}

type Sample = (&'static EncryptedTable, String, Uuid, Vec<u8>, i32);

/// [`check`]'s rows from one database.
async fn sample(pool: &sqlx::PgPool, samples: &mut Vec<Sample>) -> AppResult<()> {
    let mut tx = db::bypass_tx(pool).await?;
    for t in TABLES {
        // Table and column names are compile-time constants from TABLES.
        let sql = if t.table == "signing_keys" {
            format!(
                "SELECT DISTINCT ON (key_version) {id}::text, tenant_id, {col}, key_version \
                 FROM {table} ORDER BY key_version",
                id = t.id_column,
                col = t.column,
                table = t.table
            )
        } else {
            format!(
                "SELECT {id}::text, tenant_id, {col}, key_version FROM {table} LIMIT 1",
                id = t.id_column,
                col = t.column,
                table = t.table
            )
        };
        let rows: Vec<(String, Uuid, Vec<u8>, i32)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .fetch_all(&mut *tx)
            .await?;
        samples.extend(
            rows.into_iter()
                .map(|(id, tenant, blob, version)| (t, id, tenant, blob, version)),
        );
    }
    tx.commit().await?;
    Ok(())
}

async fn decrypt_row(
    state: &AppState,
    t: &EncryptedTable,
    tenant_id: Uuid,
    id: &str,
    blob: &[u8],
) -> AppResult<zeroize::Zeroizing<Vec<u8>>> {
    let aad = t.aad(tenant_id, id);
    let encrypted = Encrypted::from_bytes(blob).map_err(|e| AppError::Internal(e.to_string()))?;
    state
        .key_encryptor
        .decrypt(&encrypted, &aad)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))
}

async fn reencrypt(
    state: &AppState,
    t: &EncryptedTable,
    tenant_id: Uuid,
    id: &str,
    blob: &[u8],
) -> AppResult<Vec<u8>> {
    let aad = t.aad(tenant_id, id);
    let plaintext = decrypt_row(state, t, tenant_id, id, blob).await?;
    let fresh = state
        .key_encryptor
        .encrypt(&plaintext, &aad)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(fresh.to_bytes())
}
