//! Client public keys for `private_key_jwt` and encrypted ID tokens: inline
//! `jwks` or a `jwks_uri` fetched over HTTPS and cached in Redis.

use std::time::Duration;

use redis::AsyncCommands as _;
use serde_json::Value;

use crate::cache::keys as cache_keys;
use crate::error::{AppError, AppResult};
use crate::models::Client;
use crate::state::AppState;

const JWKS_CACHE_SECS: u64 = 3600;
const MAX_JWKS_BYTES: usize = 256 * 1024;

/// The client's JWK set (`keys` array). `refresh` forces a re-fetch of `jwks_uri`
/// (used once when a `kid` is unknown, so rotated client keys are picked up).
pub async fn jwks(state: &AppState, client: &Client, refresh: bool) -> AppResult<Vec<Value>> {
    if let Some(inline) = &client.jwks {
        return Ok(inline["keys"].as_array().cloned().unwrap_or_default());
    }
    let Some(uri) = &client.jwks_uri else {
        return Ok(vec![]);
    };
    let key = cache_keys::client_jwks(client.tenant_id, client.id);
    if !refresh {
        let mut conn = state.redis.get().await?;
        if let Some(raw) = conn.get::<_, Option<String>>(&key).await?
            && let Ok(v) = serde_json::from_str::<Value>(&raw)
        {
            return Ok(v["keys"].as_array().cloned().unwrap_or_default());
        }
    }
    let doc = fetch(uri).await?;
    let mut conn = state.redis.get().await?;
    let _: () = conn.set_ex(&key, doc.to_string(), JWKS_CACHE_SECS).await?;
    Ok(doc["keys"].as_array().cloned().unwrap_or_default())
}

async fn fetch(uri: &str) -> AppResult<Value> {
    let parsed =
        url::Url::parse(uri).map_err(|_| AppError::BadRequest("invalid jwks_uri".into()))?;
    if parsed.scheme() != "https" {
        return Err(AppError::BadRequest("jwks_uri must use https".into()));
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let res = client
        .get(uri)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|e| AppError::Unavailable(format!("jwks_uri fetch failed: {e}")))?;
    if !res.status().is_success() {
        return Err(AppError::Unavailable(format!(
            "jwks_uri returned {}",
            res.status()
        )));
    }
    let bytes = res
        .bytes()
        .await
        .map_err(|e| AppError::Unavailable(e.to_string()))?;
    if bytes.len() > MAX_JWKS_BYTES {
        return Err(AppError::BadRequest("jwks document too large".into()));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| AppError::BadRequest("jwks_uri did not return JSON".into()))
}
