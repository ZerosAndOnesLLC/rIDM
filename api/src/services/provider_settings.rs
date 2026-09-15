//! Typed access to encrypted per-tenant provider configuration. Decrypted
//! documents are cached in the in-process L1 only.

use std::sync::Arc;
use std::time::Duration;

use ridm_core::providers::Encrypted;
use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::cache::keys as cache_keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::ProviderKind;
use crate::repos;
use crate::state::AppState;

const L1_TTL: Duration = Duration::from_secs(60);

fn aad(tenant_id: Uuid, kind: ProviderKind) -> Vec<u8> {
    format!("provider_settings:{tenant_id}:{}", kind.as_str()).into_bytes()
}

pub async fn get<T: DeserializeOwned + Clone + Send + Sync + 'static>(
    state: &AppState,
    tenant_id: Uuid,
    kind: ProviderKind,
) -> AppResult<Option<Arc<T>>> {
    let key = cache_keys::provider_settings(tenant_id, kind.as_str());
    if let Some(v) = state.cache.l1().get::<Option<T>>(&key) {
        return Ok(v.as_ref().clone().map(Arc::new));
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let blob = repos::provider_settings::get(&mut *tx, tenant_id, kind.as_str()).await?;
    tx.commit().await?;
    let value: Option<T> = match blob {
        Some(b) => {
            let enc = Encrypted::from_bytes(&b).map_err(|e| AppError::Internal(e.to_string()))?;
            let plain = state
                .key_encryptor
                .decrypt(&enc, &aad(tenant_id, kind))
                .await
                .map_err(|e| AppError::Internal(format!("provider settings decrypt: {e}")))?;
            Some(serde_json::from_slice(&plain)?)
        }
        None => None,
    };
    // L1 caches `Option<T>` so a missing configuration is remembered too.
    state
        .cache
        .l1()
        .insert(key, Arc::new(value.clone()), L1_TTL);
    Ok(value.map(Arc::new))
}

pub async fn set<T: Serialize>(
    state: &AppState,
    tenant_id: Uuid,
    kind: ProviderKind,
    value: &T,
) -> AppResult<()> {
    let plain = serde_json::to_vec(value)?;
    let enc = state
        .key_encryptor
        .encrypt(&plain, &aad(tenant_id, kind))
        .await
        .map_err(|e| AppError::Internal(format!("provider settings encrypt: {e}")))?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    repos::provider_settings::upsert(
        &mut *tx,
        tenant_id,
        kind.as_str(),
        &enc.to_bytes(),
        enc.key_version as i32,
    )
    .await?;
    tx.commit().await?;
    state
        .cache
        .invalidate(&[cache_keys::provider_settings(tenant_id, kind.as_str())])
        .await?;
    Ok(())
}

pub async fn clear(state: &AppState, tenant_id: Uuid, kind: ProviderKind) -> AppResult<bool> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::provider_settings::delete(&mut *tx, tenant_id, kind.as_str()).await?;
    tx.commit().await?;
    state
        .cache
        .invalidate(&[cache_keys::provider_settings(tenant_id, kind.as_str())])
        .await?;
    Ok(ok)
}
