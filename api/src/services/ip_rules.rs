//! Per-tenant (or per-client) IP allow/deny rules. Enforcement on the
//! authorization, token and flow endpoints is Phase 9.2.

use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{IpRule, IpRuleAction, IpRuleUpdate, NewIpRule};
use crate::repos;
use crate::state::AppState;

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
