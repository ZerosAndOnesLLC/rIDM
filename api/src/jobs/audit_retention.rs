//! Daily audit housekeeping: upcoming partitions and per-tenant retention.

use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use uuid::Uuid;

use crate::db;
use crate::error::AppResult;
use crate::jobs::leader;
use crate::models::MASTER_TENANT_ID;
use crate::repos;
use crate::repos::audit_chains::Oldest;
use crate::services::{audit, tenants};
use crate::state::AppState;

pub const JOB_NAME: &str = "audit_retention";

/// One pass: create partitions, then apply every chain's retention (the
/// global chain follows the master tenant's), dropping whole months where
/// it can and purging rows where a chain's oldest has expired. Returns rows
/// purged.
pub async fn run_once(state: &AppState) -> AppResult<Option<u64>> {
    let Some(lock) = leader::try_acquire(&state.redis, JOB_NAME, Duration::from_secs(1800)).await?
    else {
        return Ok(None);
    };
    let result = process_all(state).await;
    lock.release().await?;
    result.map(Some)
}

/// What the pass needs of one chain: whose it is, where it lives and how
/// long its rows are kept.
struct Governed {
    tenant_id: Option<Uuid>,
    name: String,
    chain: Uuid,
    region: Option<String>,
    relocating: bool,
    retention_days: u32,
}

async fn process_all(state: &AppState) -> AppResult<u64> {
    // A failure here must not cost the purge: rows then land in the default
    // partition, where the purge still reaches them.
    match audit::ensure_partitions(state).await {
        Ok(0) => {}
        Ok(created) => tracing::info!(created, "audit: partitions created"),
        Err(err) => tracing::error!(error = %err, "audit: creating partitions failed"),
    }
    // Every tenant's chain, read a page at a time and kept small.
    let mut governed = vec![];
    let mut cursor = None;
    loop {
        let page = repos::tenants::list(state.db.home(), None, cursor, 200).await?;
        let has_more = page.len() > 200;
        governed.extend(page.iter().take(200).map(|t| Governed {
            tenant_id: Some(t.id),
            name: t.slug.clone(),
            chain: repos::audit::chain_id(Some(t.id)),
            region: t.data_region.clone(),
            relocating: t.relocating,
            retention_days: t.settings.audit.retention_days,
        }));
        if !has_more {
            break;
        }
        cursor = page.get(199).map(|t| crate::util::cursor::Cursor {
            created_at: t.created_at,
            id: t.id,
        });
    }
    let master = tenants::get(state, MASTER_TENANT_ID).await?;
    let global = Governed {
        tenant_id: None,
        name: "(global)".into(),
        chain: repos::audit::chain_id(None),
        region: None,
        relocating: false,
        retention_days: master.settings.audit.retention_days,
    };

    let now = Utc::now();
    let mut purged = 0;
    for database in state.db.all() {
        // A tenant being moved keeps everything until the move is over.
        let here: Vec<&Governed> = governed
            .iter()
            .filter(|g| !g.relocating && g.region.as_deref() == database.region())
            .chain(database.is_home().then_some(&global))
            .collect();

        // Whole months first: a partition older than every retention in its
        // database, holding nothing else, is dropped rather than emptied.
        let retentions: Vec<(Uuid, u32)> =
            here.iter().map(|g| (g.chain, g.retention_days)).collect();
        match audit::drop_expired_partitions(&database.primary, &retentions).await {
            Ok(0) => {}
            Ok(dropped) => {
                tracing::info!(region = %database.name, dropped, "audit: expired partitions dropped")
            }
            Err(err) => {
                tracing::error!(region = %database.name, error = %err, "audit: dropping expired partitions failed")
            }
        }

        // Then rows, only on the chains whose oldest row has expired: one
        // read here instead of a probe of every chain's rows.
        let oldest: HashMap<Uuid, Oldest> = {
            let mut tx = db::bypass_tx(&database.primary).await?;
            let rows = repos::audit_chains::oldest_all(&mut *tx).await?;
            tx.commit().await?;
            rows.into_iter().collect()
        };
        for g in here {
            if g.retention_days == 0 {
                continue;
            }
            let cutoff = now - chrono::Duration::days(i64::from(g.retention_days));
            match oldest.get(&g.chain) {
                // No rows at all.
                None | Some(Oldest::Empty) => continue,
                Some(Oldest::At(at)) if *at >= cutoff => continue,
                Some(Oldest::At(_)) | Some(Oldest::Unknown) => {}
            }
            match audit::purge(state, g.tenant_id, g.retention_days).await {
                Ok(n) => purged += n,
                Err(err) => {
                    tracing::error!(tenant = %g.name, error = %err, "audit purge failed")
                }
            }
        }
    }
    Ok(purged)
}
