//! Scopes: the standard OIDC set is seeded per tenant by the database; tenants
//! add their own (typically tied to a resource server).

use std::sync::Arc;
use std::time::Duration;

use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use uuid::Uuid;

use crate::cache::keys as cache_keys;
use crate::db;
use crate::error::{AppError, AppResult, OAuthError, OAuthErrorCode};
use crate::models::{Client, NewScope, STANDARD_SCOPES, Scope, ScopeUpdate};
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

/// Scopes a grant may carry in a token for these audiences
/// (`resource_server_ids`): a scope bound to a resource server only with that
/// server among the audiences, and `offline_access` only when every audience
/// allows it (`allow_offline_access`; OIDC Core §11 lets the provider decline
/// it). Order is kept; scopes the tenant does not define pass through.
pub fn filter_for_audience(
    requested: &[String],
    defs: &[Scope],
    resource_server_ids: &[Uuid],
    offline_allowed: bool,
) -> Vec<String> {
    requested
        .iter()
        .filter(|name| offline_allowed || name.as_str() != "offline_access")
        .filter(|name| {
            defs.iter()
                .find(|d| &d.name == *name)
                .and_then(|d| d.resource_server_id)
                .is_none_or(|rs| resource_server_ids.contains(&rs))
        })
        .cloned()
        .collect()
}

/// [`filter_for_audience`] against the tenant's (cached) scope rows.
pub async fn granted_for_audience(
    state: &AppState,
    tenant_id: Uuid,
    requested: &[String],
    resource_server_ids: &[Uuid],
    offline_allowed: bool,
) -> AppResult<Vec<String>> {
    let defs = list(state, tenant_id).await?;
    Ok(filter_for_audience(
        requested,
        &defs,
        resource_server_ids,
        offline_allowed,
    ))
}

/// The scopes a request that names none is given: the tenant's
/// `is_default` scopes this client may hold, less `excluded`.
pub fn defaults_for(defs: &[Scope], allowed: &[String], excluded: &[&str]) -> Vec<String> {
    defs.iter()
        .filter(|d| d.is_default)
        .filter(|d| allowed.contains(&d.name) && !excluded.contains(&d.name.as_str()))
        .map(|d| d.name.clone())
        .collect()
}

/// The requested scope list, or the client's default scopes when the
/// request names none (the console's "granted by default": included when a
/// client asks for no scope).
pub async fn requested_or_default(
    state: &AppState,
    tenant_id: Uuid,
    requested: Vec<String>,
    allowed: &[String],
    excluded: &[&str],
) -> AppResult<Vec<String>> {
    if !requested.is_empty() {
        return Ok(requested);
    }
    let defs = list(state, tenant_id).await?;
    Ok(defaults_for(&defs, allowed, excluded))
}

/// A new grant's scopes, checked, with the audiences they imply.
#[derive(Debug)]
pub struct RequestedScopes {
    /// What the grant asks for: the request's scopes, or the client's
    /// defaults when it named none.
    pub scopes: Vec<String>,
    /// Identifiers of the resource servers the requested scopes are bound
    /// to, in order: requesting such a scope also targets its server.
    pub bound_audiences: Vec<String>,
}

/// Check the scopes a new grant (authorization, device or client
/// credentials request) asks for: default scopes when it names none (an
/// error when there are none and `required`), every scope known to the
/// tenant and allowed to the client, and every scope bound to a resource
/// server one the client may target.
pub async fn validate_request(
    state: &AppState,
    tenant_id: Uuid,
    client: &Client,
    requested: Vec<String>,
    excluded: &[&str],
    required: bool,
) -> Result<RequestedScopes, OAuthError> {
    let requested = requested_or_default(
        state,
        tenant_id,
        requested,
        &client.allowed_scopes,
        excluded,
    )
    .await?;
    if requested.is_empty() && required {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidScope,
            "scope is required",
        ));
    }
    let (known, unknown) = resolve(state, tenant_id, &requested).await?;
    if !unknown.is_empty() {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidScope,
            format!("unknown scope(s): {}", unknown.join(" ")),
        ));
    }
    let disallowed: Vec<&str> = known
        .iter()
        .map(|s| s.name.as_str())
        .filter(|n| !client.allowed_scopes.iter().any(|a| a == n))
        .collect();
    if !disallowed.is_empty() {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidScope,
            format!(
                "scope(s) not allowed for this client: {}",
                disallowed.join(" ")
            ),
        ));
    }
    let mut bound_audiences: Vec<String> = vec![];
    for scope in &known {
        let Some(rs_id) = scope.resource_server_id else {
            continue;
        };
        let rs = crate::services::resource_servers::get(state, tenant_id, rs_id).await?;
        if !client.may_target(&rs.identifier, rs.built_in) {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidScope,
                format!(
                    "scope `{}` belongs to resource `{}`, which this client may not target",
                    scope.name, rs.identifier
                ),
            ));
        }
        if !bound_audiences.contains(&rs.identifier) {
            bound_audiences.push(rs.identifier);
        }
    }
    Ok(RequestedScopes {
        scopes: requested,
        bound_audiences,
    })
}

/// The audiences a new grant targets: the resources it named, or when it
/// named none the client's default audiences; plus the resource servers its
/// bound scopes belong to. With no bound scopes nothing changes, so an empty
/// result still means "the client's default".
pub fn with_bound_audiences(
    explicit: Vec<String>,
    client_default: &[String],
    bound: Vec<String>,
) -> Vec<String> {
    if bound.is_empty() {
        return explicit;
    }
    let mut out = if explicit.is_empty() {
        client_default.to_vec()
    } else {
        explicit
    };
    for b in bound {
        if !out.contains(&b) {
            out.push(b);
        }
    }
    out
}

pub async fn get(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<Scope> {
    list(state, tenant_id)
        .await?
        .iter()
        .find(|s| s.id == id)
        .cloned()
        .ok_or(AppError::NotFound("scope"))
}

pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
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
        .invalidate(&[
            cache_keys::scopes(tenant_id),
            cache_keys::discovery(tenant_id),
        ])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ScopeCreated { scope_id: scope.id },
    ));
    Ok(scope)
}

/// Description, claims and default flag can change; the name cannot.
pub async fn update(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
    patch: ScopeUpdate,
) -> AppResult<Scope> {
    if patch.is_empty() {
        return get(state, tenant_id, id).await;
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let scope = repos::scopes::update(
        &mut *tx,
        tenant_id,
        id,
        patch.description.as_ref().map(|d| d.as_deref()),
        patch.claims.as_deref(),
        patch.is_default,
        patch.resource_server_id,
    )
    .await?
    .ok_or(AppError::NotFound("scope"))?;
    tx.commit().await?;
    state
        .cache
        .invalidate(&[
            cache_keys::scopes(tenant_id),
            cache_keys::discovery(tenant_id),
        ])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ScopeUpdated { scope_id: id },
    ));
    Ok(scope)
}

pub async fn delete(state: &AppState, tenant_id: Uuid, actor: Actor, id: Uuid) -> AppResult<()> {
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
        .invalidate(&[
            cache_keys::scopes(tenant_id),
            cache_keys::discovery(tenant_id),
        ])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ScopeDeleted { scope_id: id },
    ));
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

    fn scope(name: &str, rs: Option<Uuid>, is_default: bool) -> Scope {
        Scope {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            name: name.into(),
            description: None,
            claims: vec![],
            resource_server_id: rs,
            is_default,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn bound_scopes_need_their_audience_and_offline_needs_permission() {
        let orders = Uuid::now_v7();
        let billing = Uuid::now_v7();
        let defs = vec![
            scope("openid", None, true),
            scope("offline_access", None, false),
            scope("orders:read", Some(orders), false),
            scope("billing:read", Some(billing), false),
        ];
        let requested = names(&[
            "openid",
            "offline_access",
            "orders:read",
            "billing:read",
            "x",
        ]);
        assert_eq!(
            filter_for_audience(&requested, &defs, &[orders], true),
            names(&["openid", "offline_access", "orders:read", "x"])
        );
        assert_eq!(
            filter_for_audience(&requested, &defs, &[orders, billing], false),
            names(&["openid", "orders:read", "billing:read", "x"])
        );
        assert_eq!(
            filter_for_audience(&requested, &defs, &[], true),
            names(&["openid", "offline_access", "x"])
        );
    }

    #[test]
    fn defaults_are_the_default_scopes_the_client_may_hold() {
        let defs = vec![
            scope("openid", None, true),
            scope("profile", None, false),
            scope("orders:read", None, true),
            scope("audit:read", None, true),
        ];
        let allowed = names(&["openid", "profile", "orders:read"]);
        assert_eq!(
            defaults_for(&defs, &allowed, &[]),
            names(&["openid", "orders:read"])
        );
        assert_eq!(
            defaults_for(&defs, &allowed, &["openid", "offline_access"]),
            names(&["orders:read"])
        );
    }

    #[test]
    fn bound_audiences_join_the_requested_or_default_ones() {
        let default = names(&["https://a.example"]);
        // Nothing bound: unchanged, an empty list still meaning "default".
        assert!(with_bound_audiences(vec![], &default, vec![]).is_empty());
        assert_eq!(
            with_bound_audiences(names(&["https://b.example"]), &default, vec![]),
            names(&["https://b.example"])
        );
        // Bound scopes add their server to what was named ...
        assert_eq!(
            with_bound_audiences(
                names(&["https://b.example"]),
                &default,
                names(&["https://c.example", "https://b.example"])
            ),
            names(&["https://b.example", "https://c.example"])
        );
        // ... or to the client's default when nothing was.
        assert_eq!(
            with_bound_audiences(vec![], &default, names(&["https://c.example"])),
            names(&["https://a.example", "https://c.example"])
        );
        assert_eq!(
            with_bound_audiences(vec![], &[], names(&["https://c.example"])),
            names(&["https://c.example"])
        );
    }
}
