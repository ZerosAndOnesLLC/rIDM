//! Authorization codes (RFC 6749 §4.1.2): random, single-use, short-lived,
//! stored hashed in Redis together with everything `/token` must check.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cache::keys;
use crate::error::AppResult;
use crate::state::AppState;

pub const CODE_TTL_SECS: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCode {
    pub tenant_id: Uuid,
    /// Internal client id.
    pub client_id: Uuid,
    /// Public client identifier (bound at `/token`).
    pub client_public_id: String,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    /// Resource indicators / audiences granted.
    pub audiences: Vec<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub auth_time: DateTime<Utc>,
    pub amr: Vec<String>,
    pub acr: Option<String>,
    /// Organization the session acts in, so the exchanged tokens name it.
    #[serde(default)]
    pub org_id: Option<Uuid>,
    /// The `claims` request parameter, verbatim (OIDC Core §5.5).
    pub claims: Option<serde_json::Value>,
    pub issued_at: DateTime<Utc>,
}

fn hash(code: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code.as_bytes()))
}

/// Mint and store a code; the returned secret goes to the client exactly once.
pub async fn issue(state: &AppState, record: &AuthCode) -> AppResult<Zeroizing<String>> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let code = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes));
    let mut conn = state.redis.get().await?;
    let _: () = redis::AsyncCommands::set_ex(
        &mut conn,
        keys::auth_code(record.tenant_id, &hash(&code)),
        serde_json::to_string(record)?,
        CODE_TTL_SECS,
    )
    .await?;
    Ok(code)
}

/// Atomically consume a code. `None` if unknown, expired, or already used.
pub async fn consume(state: &AppState, tenant_id: Uuid, code: &str) -> AppResult<Option<AuthCode>> {
    if code.is_empty() || code.len() > 128 {
        return Ok(None);
    }
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = redis::cmd("GETDEL")
        .arg(keys::auth_code(tenant_id, &hash(code)))
        .query_async(&mut conn)
        .await?;
    Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
}
