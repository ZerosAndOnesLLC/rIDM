//! Encryption of the material inside a `credentials` row (an authenticator
//! secret, a passkey, recovery-code hashes): JSON under the master key with
//! AAD `credentials:{tenant}:{id}`, the convention master-key rotation
//! re-encrypts.

use ridm_core::providers::Encrypted;
use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::state::AppState;

fn aad(tenant_id: Uuid, id: Uuid) -> Vec<u8> {
    format!("credentials:{tenant_id}:{id}").into_bytes()
}

pub async fn encrypt<T: Serialize>(
    state: &AppState,
    tenant_id: Uuid,
    id: Uuid,
    value: &T,
) -> AppResult<Encrypted> {
    let plain = serde_json::to_vec(value)?;
    state
        .key_encryptor
        .encrypt(&plain, &aad(tenant_id, id))
        .await
        .map_err(|e| AppError::Internal(format!("credential encrypt: {e}")))
}

pub async fn decrypt<T: DeserializeOwned>(
    state: &AppState,
    tenant_id: Uuid,
    id: Uuid,
    blob: &[u8],
) -> AppResult<T> {
    let enc = Encrypted::from_bytes(blob).map_err(|e| AppError::Internal(e.to_string()))?;
    let plain = state
        .key_encryptor
        .decrypt(&enc, &aad(tenant_id, id))
        .await
        .map_err(|e| AppError::Internal(format!("credential decrypt: {e}")))?;
    Ok(serde_json::from_slice(&plain)?)
}
