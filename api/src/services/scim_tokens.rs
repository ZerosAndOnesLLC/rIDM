//! Bearer tokens for the SCIM provisioning API: `rscim_` + 256 random bits,
//! stored as a SHA-256 hash, shown once, optionally expiring, revocable.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{CreatedScimToken, NewScimToken, ScimToken, ScimTokens, Tenant};
use crate::repos;
use crate::state::AppState;

pub const PREFIX: &str = "rscim_";
const MAX_DAYS: u32 = 3650;
const TOUCH_INTERVAL_SECS: u64 = 60;

pub fn looks_like(token: &str) -> bool {
    token.starts_with(PREFIX)
}

fn hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// `{PUBLIC_URL}/scim/v2/{slug}`.
pub fn base_url(state: &AppState, slug: &str) -> String {
    format!(
        "{}/scim/v2/{slug}",
        state.config.public_url.as_str().trim_end_matches('/')
    )
}

pub async fn list(state: &AppState, tenant: &Tenant) -> AppResult<ScimTokens> {
    let mut tx = db::read_tx(&state.db, tenant.id).await?;
    let tokens = repos::scim_tokens::list(&mut *tx, tenant.id).await?;
    tx.commit().await?;
    Ok(ScimTokens {
        base_url: base_url(state, &tenant.slug),
        tokens,
    })
}

pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    input: NewScimToken,
) -> AppResult<CreatedScimToken> {
    let name = input.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(AppError::BadRequest("name must be 1-100 characters".into()));
    }
    let expires_at = match input.expires_in_days {
        Some(0) => {
            return Err(AppError::BadRequest(
                "expires_in_days must be at least 1".into(),
            ));
        }
        Some(d) if d > MAX_DAYS => {
            return Err(AppError::BadRequest(format!(
                "expires_in_days must be at most {MAX_DAYS}"
            )));
        }
        Some(d) => Some(Utc::now() + Duration::days(i64::from(d))),
        None => None,
    };
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let token = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let record = repos::scim_tokens::insert(
        &mut *tx,
        tenant_id,
        Uuid::now_v7(),
        name,
        &hash(&token),
        expires_at,
    )
    .await?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ScimTokenCreated {
            token_id: record.id,
        },
    ));
    Ok(CreatedScimToken { record, token })
}

pub async fn revoke(state: &AppState, tenant_id: Uuid, actor: Actor, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::scim_tokens::revoke(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    if !ok {
        return Err(AppError::NotFound("scim token"));
    }
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ScimTokenRevoked { token_id: id },
    ));
    Ok(())
}

pub struct Authenticated {
    pub token: ScimToken,
    pub tenant: Arc<Tenant>,
}

/// The tenant a bearer token provisions, or `None` for anything not live.
pub async fn authenticate(state: &AppState, token: &str) -> AppResult<Option<Authenticated>> {
    if !looks_like(token) || token.len() > 128 {
        return Ok(None);
    }
    let h = hash(token);
    // The token names no tenant, so every database is asked (home first).
    let mut rec = None;
    for database in state.db.all() {
        let mut tx = db::bypass_tx(&database.primary).await?;
        rec = repos::scim_tokens::find_by_hash(&mut *tx, &h).await?;
        tx.commit().await?;
        if rec.is_some() {
            break;
        }
    }
    let Some(rec) = rec else { return Ok(None) };
    if !rec.is_usable(Utc::now()) {
        return Ok(None);
    }
    let Some(tenant) = crate::services::tenants::get_cached(state, rec.tenant_id).await? else {
        return Ok(None);
    };
    if !tenant.is_active() {
        return Ok(None);
    }
    touch(state, &rec).await?;
    Ok(Some(Authenticated { token: rec, tenant }))
}

/// Record the use, at most once a minute per token.
async fn touch(state: &AppState, rec: &ScimToken) -> AppResult<()> {
    let mut conn = state.redis.get().await?;
    let claimed: Option<String> = redis::cmd("SET")
        .arg(format!(
            "{}:t:{}:scim_token:{}:touched",
            keys::PREFIX,
            rec.tenant_id,
            rec.id
        ))
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(TOUCH_INTERVAL_SECS)
        .query_async(&mut conn)
        .await?;
    drop(conn);
    if claimed.is_some() {
        let mut tx = db::tenant_tx(&state.db, rec.tenant_id).await?;
        repos::scim_tokens::touch(&mut *tx, rec.tenant_id, rec.id).await?;
        tx.commit().await?;
    }
    Ok(())
}
