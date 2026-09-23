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
    },
    EncryptedTable {
        table: "credentials",
        column: "data_enc",
        aad_prefix: "credentials",
        id_column: "id",
    },
    EncryptedTable {
        table: "tenant_provider_settings",
        column: "config_enc",
        aad_prefix: "provider_settings",
        id_column: "kind",
    },
    EncryptedTable {
        table: "identity_providers",
        column: "client_secret_enc",
        aad_prefix: "identity_providers",
        id_column: "id",
    },
    EncryptedTable {
        table: "webhooks",
        column: "secret_enc",
        aad_prefix: "webhooks",
        id_column: "id",
    },
    EncryptedTable {
        table: "saml_signing_keys",
        column: "private_key_enc",
        aad_prefix: "saml_signing_keys",
        id_column: "id",
    },
];

struct EncryptedTable {
    table: &'static str,
    column: &'static str,
    aad_prefix: &'static str,
    /// Row identifier column (uuid `id`, or a text key for keyed tables).
    id_column: &'static str,
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

/// Count rows per key generation for every encrypted table.
pub async fn status(state: &AppState) -> AppResult<StatusReport> {
    let mut tx = db::bypass_tx(&state.db).await?;
    let mut rows_by_version = BTreeMap::new();
    for t in TABLES {
        // Table names are compile-time constants from TABLES, never user input.
        let sql = format!(
            "SELECT key_version, count(*) FROM {} GROUP BY key_version ORDER BY key_version",
            t.table
        );
        let rows: Vec<(i32, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .fetch_all(&mut *tx)
            .await?;
        rows_by_version.insert(t.table.to_string(), rows.into_iter().collect());
    }
    tx.commit().await?;
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
/// generation is created.
pub async fn highest_version_in_use(db: &crate::db::Db) -> Result<u32, sqlx::Error> {
    // Table names are compile-time constants from TABLES.
    let sql = TABLES
        .iter()
        .map(|t| format!("SELECT max(key_version) AS v FROM {}", t.table))
        .collect::<Vec<_>>()
        .join(" UNION ALL ");
    let sql = format!("SELECT max(v) FROM ({sql}) AS versions");
    let mut tx = db::bypass_tx(db).await?;
    let highest: Option<i32> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(highest.unwrap_or(0).max(0) as u32)
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
    for t in TABLES {
        let (ok, failed) = rotate_table(state, t, target).await?;
        report.rewritten.insert(t.table.to_string(), ok);
        report.failed.insert(t.table.to_string(), failed);
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

async fn rotate_table(state: &AppState, t: &EncryptedTable, target: u32) -> AppResult<(u64, u64)> {
    let mut ok = 0u64;
    let mut failed = 0u64;
    let mut skip: Vec<String> = vec![];
    loop {
        // Fetch a batch of rows still on an older generation, skipping ones
        // that already failed in this pass so we cannot loop forever.
        let sql = format!(
            "SELECT {id}::text, tenant_id, {col}, key_version FROM {table} \
             WHERE key_version <> $1 AND NOT ({id}::text = ANY($2)) ORDER BY tenant_id, {id} LIMIT $3",
            id = t.id_column,
            col = t.column,
            table = t.table
        );
        let mut tx = db::bypass_tx(&state.db).await?;
        let rows: Vec<(String, Uuid, Vec<u8>, i32)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(target as i32)
            .bind(&skip)
            .bind(BATCH)
            .fetch_all(&mut *tx)
            .await?;
        tx.commit().await?;
        if rows.is_empty() {
            break;
        }
        for (id, tenant_id, blob, old_version) in rows {
            match reencrypt(state, t, tenant_id, &id, &blob).await {
                Ok(new_blob) => {
                    let sql = format!(
                        "UPDATE {table} SET {col} = $1, key_version = $2 \
                         WHERE {idc}::text = $3 AND tenant_id = $4 AND key_version = $5",
                        col = t.column,
                        table = t.table,
                        idc = t.id_column
                    );
                    let mut tx = db::bypass_tx(&state.db).await?;
                    let n = sqlx::query(sqlx::AssertSqlSafe(sql))
                        .bind(&new_blob)
                        .bind(target as i32)
                        .bind(&id)
                        .bind(tenant_id)
                        .bind(old_version)
                        .execute(&mut *tx)
                        .await?
                        .rows_affected();
                    tx.commit().await?;
                    if n == 1 {
                        ok += 1;
                    } else {
                        // Rewritten concurrently by someone else; nothing to do.
                        skip.push(id);
                    }
                }
                Err(err) => {
                    tracing::error!(table = t.table, %id, %tenant_id, error = %err, "re-encryption failed");
                    failed += 1;
                    skip.push(id);
                }
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
pub async fn check(state: &AppState) -> AppResult<CheckReport> {
    let mut samples: Vec<(&EncryptedTable, String, Uuid, Vec<u8>, i32)> = vec![];
    let mut tx = db::bypass_tx(&state.db).await?;
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
