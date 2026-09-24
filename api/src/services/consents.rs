//! Remembered user consent per client.

use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use uuid::Uuid;

use crate::db;
use crate::error::AppResult;
use crate::models::Consent;
use crate::repos;
use crate::state::AppState;

/// Scopes in `requested` the user has not yet granted to this client.
pub async fn missing_scopes(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: Uuid,
    requested: &[String],
) -> AppResult<Vec<String>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let existing = repos::consents::find(&mut *tx, tenant_id, user_id, client_id).await?;
    tx.commit().await?;
    let granted: Vec<String> = existing
        .filter(|c| c.revoked_at.is_none())
        .map(|c| c.scopes)
        .unwrap_or_default();
    Ok(requested
        .iter()
        .filter(|s| !granted.contains(s))
        .cloned()
        .collect())
}

pub async fn grant(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: Uuid,
    scopes: &[String],
) -> AppResult<Consent> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let c = repos::consents::upsert(&mut *tx, tenant_id, user_id, client_id, scopes).await?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        Actor::User { id: user_id },
        EventKind::ConsentGranted {
            user_id,
            client_id,
            scopes: scopes.to_vec(),
        },
    ));
    Ok(c)
}

pub async fn revoke(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    user_id: Uuid,
    client_id: Uuid,
) -> AppResult<bool> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::consents::revoke(&mut *tx, tenant_id, user_id, client_id).await?;
    tx.commit().await?;
    if ok {
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::ConsentRevoked { user_id, client_id },
        ));
    }
    Ok(ok)
}

pub async fn list_for_user(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<Consent>> {
    let mut tx = db::read_tx(&state.db, tenant_id).await?;
    let rows = repos::consents::list_for_user(&mut *tx, tenant_id, user_id).await?;
    tx.commit().await?;
    Ok(rows)
}
