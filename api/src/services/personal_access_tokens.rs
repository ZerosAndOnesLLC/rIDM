//! Personal access tokens: `rpat_<random>` bearer tokens a user mints for
//! scripts and integrations. Each carries a subset of what the user may
//! do — `account` for the self-service API, admin permission names for the
//! admin API — and is narrowed at use to what the user still holds, so a
//! removed role narrows every token at once. Only the SHA-256 of a token is
//! stored; the token is shown once.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult, FieldError};
use crate::models::{
    NewPersonalAccessToken, PAT_SCOPE_ACCOUNT, PersonalAccessToken, Tenant, User, UserStatus,
};
use crate::repos;
use crate::services::admin_access::{self, OrgScope, PermissionSet};
use crate::services::users;
use crate::state::AppState;

pub const PREFIX: &str = "rpat_";
/// `last_used_at` is written at most this often per token.
const TOUCH_INTERVAL_SECS: u64 = 60;

pub fn looks_like_pat(token: &str) -> bool {
    token.starts_with(PREFIX)
}

fn hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn random_token() -> Zeroizing<String> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    Zeroizing::new(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

/// The scopes a user may put on a token right now: `account`, plus every
/// admin permission they hold.
pub async fn available_scopes(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<String>> {
    let perms =
        admin_access::permissions_of_user(state, tenant_id, user_id, OrgScope::TenantWide).await?;
    let mut out = vec![PAT_SCOPE_ACCOUNT.to_string()];
    out.extend(perms.names().iter().cloned());
    Ok(out)
}

/// Mint a token for `user_id`. Scopes must be `account` or catalogue
/// permission names the user holds; the expiry is capped by the tenant.
pub async fn create(
    state: &AppState,
    tenant: &Tenant,
    actor: Actor,
    user_id: Uuid,
    input: NewPersonalAccessToken,
) -> AppResult<(Zeroizing<String>, PersonalAccessToken)> {
    let policy = &tenant.settings.account;
    if !policy.personal_tokens {
        return Err(AppError::Forbidden(
            "this organisation does not allow personal access tokens".into(),
        ));
    }
    let name = input.name.trim().to_string();
    if name.is_empty() || name.len() > 100 {
        return Err(AppError::Validation(vec![FieldError {
            field: "name".into(),
            message: "must be 1-100 characters".into(),
        }]));
    }
    let allowed = available_scopes(state, tenant.id, user_id).await?;
    let mut scopes: Vec<String> = vec![];
    for s in &input.scopes {
        let s = s.trim();
        if !allowed.iter().any(|a| a == s) {
            return Err(AppError::Validation(vec![FieldError {
                field: "scopes".into(),
                message: format!("`{s}` is not a scope you hold"),
            }]));
        }
        if !scopes.iter().any(|x| x == s) {
            scopes.push(s.to_string());
        }
    }
    if scopes.is_empty() {
        return Err(AppError::Validation(vec![FieldError {
            field: "scopes".into(),
            message: "at least one scope is required".into(),
        }]));
    }
    let max_days = policy.personal_token_max_days;
    let days = match (input.expires_in_days, max_days) {
        (Some(0), _) => {
            return Err(AppError::Validation(vec![FieldError {
                field: "expires_in_days".into(),
                message: "must be at least 1".into(),
            }]));
        }
        (Some(d), 0) => Some(d),
        (Some(d), max) if d <= max => Some(d),
        (Some(_), max) => {
            return Err(AppError::Validation(vec![FieldError {
                field: "expires_in_days".into(),
                message: format!("must be at most {max}"),
            }]));
        }
        (None, 0) => None,
        (None, max) => Some(max),
    };
    let expires_at = days.map(|d| Utc::now() + Duration::days(i64::from(d)));
    let token = random_token();
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    let record = repos::personal_access_tokens::insert(
        &mut *tx,
        tenant.id,
        repos::personal_access_tokens::NewToken {
            id: Uuid::now_v7(),
            user_id,
            name: &name,
            token_hash: &hash(&token),
            scopes: &scopes,
            expires_at,
        },
    )
    .await?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tenant.id),
        actor,
        EventKind::PersonalTokenCreated {
            user_id,
            token_id: record.id,
            scopes: scopes.clone(),
        },
    ));
    Ok((token, record))
}

pub async fn list(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<PersonalAccessToken>> {
    let mut tx = db::read_tx(&state.db, tenant_id).await?;
    let rows = repos::personal_access_tokens::list_for_user(&mut *tx, tenant_id, user_id).await?;
    tx.commit().await?;
    Ok(rows)
}

pub async fn revoke(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    user_id: Uuid,
    id: Uuid,
) -> AppResult<bool> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let revoked = repos::personal_access_tokens::revoke(&mut *tx, tenant_id, user_id, id).await?;
    tx.commit().await?;
    let ok = revoked.is_some();
    if let Some(h) = revoked {
        forget(state, &[h]).await?;
    }
    if ok {
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::PersonalTokenRevoked {
                user_id,
                token_id: id,
            },
        ));
    }
    Ok(ok)
}

pub async fn revoke_all_for_user(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<u64> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let hashes =
        repos::personal_access_tokens::revoke_all_for_user(&mut *tx, tenant_id, user_id).await?;
    tx.commit().await?;
    forget(state, &hashes).await?;
    Ok(hashes.len() as u64)
}

/// How long a token's record is served from the cache; a revocation evicts
/// it everywhere at once.
const RECORD_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// Evict tokens' records after they were revoked.
async fn forget(state: &AppState, hashes: &[Vec<u8>]) -> AppResult<()> {
    let evicted: Vec<String> = hashes.iter().map(|h| keys::pat_by_hash(h)).collect();
    for chunk in evicted.chunks(500) {
        state.cache.invalidate(chunk).await?;
    }
    Ok(())
}

/// The record behind a token hash, cached: the token names no tenant, so a
/// miss asks every database (home first).
async fn record_by_hash(
    state: &AppState,
    h: &[u8],
) -> AppResult<Option<std::sync::Arc<PersonalAccessToken>>> {
    let db = state.db.clone();
    let hash = h.to_vec();
    state
        .cache
        .get_or_load(&keys::pat_by_hash(h), RECORD_TTL, || async move {
            for database in db.all() {
                let mut tx = db::bypass_tx(&database.primary).await?;
                let rec = repos::personal_access_tokens::find_by_hash(&mut *tx, &hash).await?;
                tx.commit().await?;
                if rec.is_some() {
                    return Ok(rec);
                }
            }
            Ok(None)
        })
        .await
}

/// A token presented as a bearer, resolved to its record and user. `None`
/// for anything unknown, revoked, expired, or whose user cannot sign in.
pub struct Authenticated {
    pub token: PersonalAccessToken,
    pub user: User,
    pub tenant: std::sync::Arc<Tenant>,
    /// The token's admin permissions, narrowed to what the user still holds.
    pub permissions: PermissionSet,
}

pub async fn authenticate(state: &AppState, token: &str) -> AppResult<Option<Authenticated>> {
    if !looks_like_pat(token) || token.len() > 128 {
        return Ok(None);
    }
    let h = hash(token);
    let Some(rec) = record_by_hash(state, &h).await? else {
        return Ok(None);
    };
    let rec = (*rec).clone();
    if !rec.is_usable(Utc::now()) {
        return Ok(None);
    }
    let Some(tenant) = crate::services::tenants::get_cached(state, rec.tenant_id).await? else {
        return Ok(None);
    };
    if !tenant.is_active() {
        return Ok(None);
    }
    let user = match users::get(state, rec.tenant_id, rec.user_id).await {
        Ok(u) => u,
        Err(AppError::NotFound(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    if user.status != UserStatus::Active || user.is_locked_now() {
        return Ok(None);
    }
    let held =
        admin_access::permissions_of_user(state, rec.tenant_id, rec.user_id, OrgScope::TenantWide)
            .await?;
    let permissions = PermissionSet::new(
        rec.scopes
            .iter()
            .filter(|s| s.as_str() != PAT_SCOPE_ACCOUNT && held.allows(s))
            .cloned(),
    );
    touch(state, &rec).await?;
    Ok(Some(Authenticated {
        token: rec,
        user,
        tenant,
        permissions,
    }))
}

/// Record the use, at most once a minute per token.
async fn touch(state: &AppState, rec: &PersonalAccessToken) -> AppResult<()> {
    let mut conn = state.redis.get().await?;
    let claimed: Option<String> = redis::cmd("SET")
        .arg(keys::pat_touched(rec.tenant_id, rec.id))
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(TOUCH_INTERVAL_SECS)
        .query_async(&mut conn)
        .await?;
    drop(conn);
    if claimed.is_some() {
        let mut tx = db::tenant_tx(&state.db, rec.tenant_id).await?;
        repos::personal_access_tokens::touch(&mut *tx, rec.tenant_id, rec.id).await?;
        tx.commit().await?;
    }
    Ok(())
}

/// For introspection: the record behind a token within `tenant_id`.
pub async fn find(
    state: &AppState,
    tenant_id: Uuid,
    token: &str,
) -> AppResult<Option<PersonalAccessToken>> {
    if !looks_like_pat(token) || token.len() > 128 {
        return Ok(None);
    }
    let h = hash(token);
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rec = repos::personal_access_tokens::find_by_hash(&mut *tx, &h).await?;
    tx.commit().await?;
    Ok(rec.filter(|r| r.tenant_id == tenant_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_prefixed_random_and_hashed() {
        let a = random_token();
        let b = random_token();
        assert!(a.starts_with(PREFIX) && looks_like_pat(&a));
        assert_ne!(*a, *b);
        assert_ne!(hash(&a), hash(&b));
        assert!(!looks_like_pat("rt_x"));
    }
}
