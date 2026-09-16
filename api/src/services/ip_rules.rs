//! Per-tenant (or per-client) IP allow/deny rules and their enforcement.
//!
//! Rules form two scopes: tenant-wide (`client_id` null) and per client.
//! Within a scope the most specific matching network decides; an address
//! matching no rule passes unless the scope holds any `allow` rule, in which
//! case the scope is an allow list and everything else is refused. Both
//! scopes must pass: the tenant scope is checked by the request guard on the
//! authorization, token and flow endpoints, the client scope once the client
//! is known (`/authorize`, and every client-authenticated endpoint).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{IpRule, IpRuleAction, IpRuleUpdate, NewIpRule};
use crate::repos;
use crate::state::AppState;

/// Rules are evicted eagerly on every change; the TTL only bounds staleness
/// after a missed invalidation.
const RULES_TTL: Duration = Duration::from_secs(300);

/// Every rule of the tenant, through the cache.
pub async fn cached(state: &AppState, tenant_id: Uuid) -> AppResult<Arc<Vec<IpRule>>> {
    let db = state.db.clone();
    let loaded = state
        .cache
        .get_or_load(&keys::ip_rules(tenant_id), RULES_TTL, || async move {
            let mut tx = db::tenant_tx(&db, tenant_id).await?;
            let rows = repos::ip_rules::list(&mut *tx, tenant_id, None).await?;
            tx.commit().await?;
            Ok(Some(rows))
        })
        .await?;
    Ok(loaded.unwrap_or_default())
}

/// Does `ip` pass the rules of one scope (`None` = tenant-wide)?
/// An unknown address only passes a scope without allow rules.
pub fn scope_allows(rules: &[IpRule], scope: Option<Uuid>, ip: Option<IpAddr>) -> bool {
    let mut has_allow = false;
    let mut best: Option<(u8, IpRuleAction)> = None;
    for r in rules.iter().filter(|r| r.client_id == scope) {
        if r.action == IpRuleAction::Allow {
            has_allow = true;
        }
        let Some(ip) = ip else { continue };
        let Ok(net) = r.cidr.parse::<ipnet::IpNet>() else {
            continue;
        };
        if net.contains(&ip) && best.is_none_or(|(len, _)| net.prefix_len() > len) {
            best = Some((net.prefix_len(), r.action));
        }
    }
    match best {
        Some((_, action)) => action == IpRuleAction::Allow,
        None => !has_allow,
    }
}

/// Tenant-wide rules for a request (the guard's check).
pub async fn tenant_allows(
    state: &AppState,
    tenant_id: Uuid,
    ip: Option<IpAddr>,
) -> AppResult<bool> {
    let rules = cached(state, tenant_id).await?;
    Ok(scope_allows(&rules, None, ip))
}

/// The client's own rules, once the client is known.
pub async fn client_allows(
    state: &AppState,
    tenant_id: Uuid,
    client_id: Uuid,
    ip: Option<IpAddr>,
) -> AppResult<bool> {
    let rules = cached(state, tenant_id).await?;
    Ok(scope_allows(&rules, Some(client_id), ip))
}

/// Refuse a client-scoped request from a disallowed address (`Forbidden`).
pub async fn require_client(
    state: &AppState,
    tenant_id: Uuid,
    client_id: Uuid,
    ip: Option<IpAddr>,
) -> AppResult<()> {
    match client_allows(state, tenant_id, client_id, ip).await {
        Ok(true) => Ok(()),
        Ok(false) => {
            tracing::info!(%tenant_id, %client_id, ip = ?ip, "client ip rule refused request");
            metrics::counter!("ridm_ip_rule_rejections_total", "scope" => "client").increment(1);
            Err(AppError::Forbidden(
                "this address may not use this client".into(),
            ))
        }
        // The rules being unreadable must not open the door.
        Err(err) => {
            tracing::warn!(error = %err, "ip rules unavailable; refusing");
            Err(AppError::Unavailable("ip rules unavailable".into()))
        }
    }
}

async fn evict(state: &AppState, tenant_id: Uuid) -> AppResult<()> {
    state.cache.invalidate(&[keys::ip_rules(tenant_id)]).await
}

/// Accepts `a.b.c.d`, `a.b.c.d/n`, `::1` or `2001:db8::/32`; returns the
/// canonical network form.
pub fn normalize_cidr(raw: &str) -> AppResult<String> {
    let s = raw.trim();
    let net: ipnet::IpNet = if let Ok(n) = s.parse::<ipnet::IpNet>() {
        n
    } else if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        ipnet::IpNet::from(ip)
    } else {
        return Err(AppError::BadRequest(format!(
            "cidr: `{s}` is not an IP address or network"
        )));
    };
    Ok(net.trunc().to_string())
}

pub async fn list(
    state: &AppState,
    tenant_id: Uuid,
    client_id: Option<Option<Uuid>>,
) -> AppResult<Vec<IpRule>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::ip_rules::list(&mut *tx, tenant_id, client_id).await?;
    tx.commit().await?;
    Ok(rows)
}

pub async fn get(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<IpRule> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let r = repos::ip_rules::find_by_id(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    r.ok_or(AppError::NotFound("ip rule"))
}

pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    input: NewIpRule,
) -> AppResult<IpRule> {
    let cidr = normalize_cidr(&input.cidr)?;
    if let Some(c) = input.client_id {
        crate::services::clients::get(state, tenant_id, c)
            .await
            .map_err(|_| AppError::BadRequest("client_id does not exist".into()))?;
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rule = repos::ip_rules::insert(
        &mut *tx,
        tenant_id,
        Uuid::now_v7(),
        input.client_id,
        input.action.unwrap_or(IpRuleAction::Deny),
        &cidr,
        input.description.as_deref(),
    )
    .await
    .map_err(|e| match AppError::from_db(e) {
        AppError::Conflict(_) => {
            AppError::Conflict("a rule for this network already exists".into())
        }
        other => other,
    })?;
    tx.commit().await?;
    evict(state, tenant_id).await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::IpRuleCreated { rule_id: rule.id },
    ));
    Ok(rule)
}

pub async fn update(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
    mut patch: IpRuleUpdate,
) -> AppResult<IpRule> {
    if let Some(c) = &patch.cidr {
        patch.cidr = Some(normalize_cidr(c)?);
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rule = repos::ip_rules::update(&mut *tx, tenant_id, id, &patch)
        .await
        .map_err(|e| match AppError::from_db(e) {
            AppError::Conflict(_) => {
                AppError::Conflict("a rule for this network already exists".into())
            }
            other => other,
        })?
        .ok_or(AppError::NotFound("ip rule"))?;
    tx.commit().await?;
    evict(state, tenant_id).await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::IpRuleUpdated { rule_id: id },
    ));
    Ok(rule)
}

pub async fn delete(state: &AppState, tenant_id: Uuid, actor: Actor, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::ip_rules::delete(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    if !ok {
        return Err(AppError::NotFound("ip rule"));
    }
    evict(state, tenant_id).await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::IpRuleDeleted { rule_id: id },
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn rule(scope: Option<Uuid>, action: IpRuleAction, cidr: &str) -> IpRule {
        IpRule {
            id: Uuid::new_v4(),
            tenant_id: Uuid::nil(),
            client_id: scope,
            action,
            cidr: cidr.into(),
            description: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn deny_list_scope() {
        let rules = [rule(None, IpRuleAction::Deny, "203.0.113.0/24")];
        assert!(!scope_allows(&rules, None, ip("203.0.113.9")));
        assert!(scope_allows(&rules, None, ip("198.51.100.1")));
        assert!(
            scope_allows(&rules, None, None),
            "no allow rules: unknown passes"
        );
        assert!(scope_allows(&[], None, ip("203.0.113.9")));
    }

    #[test]
    fn allow_list_scope_and_longest_prefix() {
        let rules = [
            rule(None, IpRuleAction::Allow, "10.0.0.0/8"),
            rule(None, IpRuleAction::Deny, "10.1.0.0/16"),
            rule(None, IpRuleAction::Allow, "10.1.2.0/24"),
        ];
        assert!(scope_allows(&rules, None, ip("10.9.9.9")));
        assert!(!scope_allows(&rules, None, ip("10.1.5.5")));
        assert!(scope_allows(&rules, None, ip("10.1.2.3")));
        assert!(!scope_allows(&rules, None, ip("192.0.2.1")), "allow list");
        assert!(
            !scope_allows(&rules, None, None),
            "allow list: unknown refused"
        );
    }

    #[test]
    fn scopes_are_independent() {
        let c = Uuid::new_v4();
        let rules = [
            rule(Some(c), IpRuleAction::Deny, "2001:db8::/32"),
            rule(None, IpRuleAction::Allow, "2001:db8::/32"),
        ];
        assert!(scope_allows(&rules, None, ip("2001:db8::1")));
        assert!(!scope_allows(&rules, Some(c), ip("2001:db8::1")));
        assert!(scope_allows(
            &rules,
            Some(Uuid::new_v4()),
            ip("2001:db8::1")
        ));
    }

    #[test]
    fn cidrs_normalize() {
        assert_eq!(normalize_cidr("203.0.113.7").unwrap(), "203.0.113.7/32");
        assert_eq!(normalize_cidr("203.0.113.9/24").unwrap(), "203.0.113.0/24");
        assert_eq!(normalize_cidr("2001:db8::1/32").unwrap(), "2001:db8::/32");
        assert_eq!(normalize_cidr("::1").unwrap(), "::1/128");
        assert!(normalize_cidr("not-an-ip").is_err());
        assert!(normalize_cidr("10.0.0.0/33").is_err());
    }
}
