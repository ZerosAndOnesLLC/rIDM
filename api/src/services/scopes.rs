//! Scopes: the standard OIDC set is seeded per tenant by the database; tenants
//! add their own (typically tied to a resource server).

use std::sync::Arc;
use std::time::Duration;

use ridm_core::events::Actor;
use uuid::Uuid;

use crate::cache::keys as cache_keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{NewScope, STANDARD_SCOPES, Scope};
use crate::repos;
use crate::state::AppState;

const SCOPES_CACHE_TTL: Duration = Duration::from_secs(300);

/// Scope name grammar (RFC 6749 §3.3): printable ASCII except `"` and `\`.
pub fn is_valid_scope_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
}

/// All scopes of a tenant (cached).
pub async fn list(state: &AppState, tenant_id: Uuid) -> AppResult<Arc<Vec<Scope>>> {
    let db = state.db.clone();
    let scopes = state
        .cache
        .get_or_load(
            &cache_keys::scopes(tenant_id),
            SCOPES_CACHE_TTL,
            || async move {
                let mut tx = db::tenant_tx(&db, tenant_id).await?;
                let rows = repos::scopes::list_all(&mut *tx, tenant_id).await?;
                tx.commit().await?;
                Ok(Some(rows))
            },
        )
        .await?;
    Ok(scopes.unwrap_or_default())
}

/// Split a space-separated scope string, dropping duplicates and blanks.
pub fn parse_scope_param(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for s in raw.split(' ').map(str::trim).filter(|s| !s.is_empty()) {
        if !out.iter().any(|x| x == s) {
            out.push(s.to_string());
        }
    }
    out
}

/// Which of `requested` exist for the tenant; the rest are returned as unknown.
pub async fn resolve(
    state: &AppState,
    tenant_id: Uuid,
    requested: &[String],
) -> AppResult<(Vec<Scope>, Vec<String>)> {
    let all = list(state, tenant_id).await?;
    let mut known = vec![];
    let mut unknown = vec![];
    for r in requested {
        match all.iter().find(|s| &s.name == r) {
            Some(s) => known.push(s.clone()),
            None => unknown.push(r.clone()),
        }
    }
    Ok((known, unknown))
}

pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    _actor: Actor,
    input: NewScope,
) -> AppResult<Scope> {
    if !is_valid_scope_name(&input.name) {
        return Err(AppError::BadRequest("invalid scope name".into()));
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let scope = repos::scopes::insert(&mut *tx, tenant_id, Uuid::now_v7(), &input)
        .await
        .map_err(|e| match AppError::from_db(e) {
            AppError::Conflict(_) => AppError::Conflict("scope already exists".into()),
            other => other,
        })?;
    tx.commit().await?;
    state
        .cache
        .invalidate(&[cache_keys::scopes(tenant_id)])
        .await?;
    Ok(scope)
}

pub async fn delete(state: &AppState, tenant_id: Uuid, _actor: Actor, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let all = repos::scopes::list_all(&mut *tx, tenant_id).await?;
    if let Some(s) = all.iter().find(|s| s.id == id)
        && STANDARD_SCOPES.contains(&s.name.as_str())
    {
        return Err(AppError::BadRequest(
            "standard scopes cannot be deleted".into(),
        ));
    }
    let ok = repos::scopes::delete(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    if !ok {
        return Err(AppError::NotFound("scope"));
    }
    state
        .cache
        .invalidate(&[cache_keys::scopes(tenant_id)])
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_grammar_and_parsing() {
        assert!(is_valid_scope_name("openid"));
        assert!(is_valid_scope_name("read:users"));
        assert!(is_valid_scope_name("https://api.example/read"));
        assert!(!is_valid_scope_name(""));
        assert!(!is_valid_scope_name("a b"));
        assert!(!is_valid_scope_name("a\"b"));
        assert_eq!(
            parse_scope_param("  openid profile  openid email "),
            vec!["openid", "profile", "email"]
        );
    }
}
