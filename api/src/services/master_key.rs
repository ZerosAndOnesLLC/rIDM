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
        table: "webhooks",
        column: "secret_enc",
        aad_prefix: "webhooks",
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
    Ok(StatusReport {
        current_version: state.key_encryptor.current_version(),
        known_versions: known,
        rows_by_version,
    })
}

/// Re-encrypt everything not yet under the current generation.
pub async fn rotate_all(state: &AppState) -> AppResult<RotationReport> {
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

async fn reencrypt(
    state: &AppState,
    t: &EncryptedTable,
    tenant_id: Uuid,
    id: &str,
    blob: &[u8],
) -> AppResult<Vec<u8>> {
    let aad = t.aad(tenant_id, id);
    let encrypted = Encrypted::from_bytes(blob).map_err(|e| AppError::Internal(e.to_string()))?;
    let plaintext = state
        .key_encryptor
        .decrypt(&encrypted, &aad)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let fresh = state
        .key_encryptor
        .encrypt(&plaintext, &aad)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(fresh.to_bytes())
}
