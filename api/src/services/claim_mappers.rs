//! Claim mapper lifecycle. Mappers are read by the token pipeline through a
//! per-client cache keyed under a tenant-wide version token, so a change to
//! a tenant-wide mapper reaches every client at once.

use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde_json::Value;
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{ClaimMapper, ClaimMapperRow, ClaimMapperUpdate, MapperKind, NewClaimMapper};
use crate::repos;
use crate::state::AppState;

const MAPPERS_VERSION_TTL: u64 = 7 * 24 * 3600;

/// Current version token for a tenant's claim mappers (held briefly per
/// node, evicted everywhere by a bump).
pub async fn mappers_version(state: &AppState, tenant_id: Uuid) -> AppResult<String> {
    state
        .cache
        .version(
            &keys::mappers_version(tenant_id),
            std::time::Duration::from_secs(MAPPERS_VERSION_TTL),
        )
        .await
}

pub async fn bump_mappers_version(state: &AppState, tenant_id: Uuid) -> AppResult<()> {
    state
        .cache
        .bump_version(
            &keys::mappers_version(tenant_id),
            std::time::Duration::from_secs(MAPPERS_VERSION_TTL),
        )
        .await
}

fn validate_name(s: &str) -> AppResult<String> {
    let n = s.trim().to_string();
    if n.is_empty() || n.len() > 255 {
        return Err(AppError::BadRequest("name must be 1-255 characters".into()));
    }
    Ok(n)
}

/// Check a mapper document: it must parse as a known mapper type with at
/// least one target, and templates must compile.
pub fn validate_config(name: &str, config: &Value) -> AppResult<ClaimMapper> {
    let Some(obj) = config.as_object() else {
        return Err(AppError::BadRequest("config must be an object".into()));
    };
    if obj.contains_key("name") {
        return Err(AppError::BadRequest(
            "config.name is set from the mapper name".into(),
        ));
    }
    let mut doc = config.clone();
    doc["name"] = Value::String(name.to_string());
    let mapper: ClaimMapper = serde_json::from_value(doc)
        .map_err(|e| AppError::BadRequest(format!("invalid mapper config: {e}")))?;
    if mapper.include_in.is_empty() {
        return Err(AppError::BadRequest(
            "include_in must name at least one of access, id, userinfo".into(),
        ));
    }
    if let Some(claim) = mapper.claim_name()
        && (claim.is_empty() || claim.len() > 255 || claim.chars().any(char::is_whitespace))
    {
        return Err(AppError::BadRequest(
            "claim must be a non-empty name".into(),
        ));
    }
    if let Some(reason) = crate::services::claims::mapper_claim_refusal(&mapper) {
        return Err(AppError::BadRequest(reason));
    }
    if let MapperKind::Template { template, .. } = &mapper.kind {
        let mut hb = handlebars::Handlebars::new();
        hb.register_template_string("m", template)
            .map_err(|e| AppError::BadRequest(format!("template does not compile: {e}")))?;
    }
    Ok(mapper)
}

/// `None`: all; `Some(None)`: tenant-wide only; `Some(Some(c))`: one client's.
pub async fn list(
    state: &AppState,
    tenant_id: Uuid,
    scope: Option<Option<Uuid>>,
) -> AppResult<Vec<ClaimMapperRow>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::claim_mappers::list(&mut *tx, tenant_id, scope).await?;
    tx.commit().await?;
    Ok(rows)
}

pub async fn get(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<ClaimMapperRow> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let row = repos::claim_mappers::find_by_id(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    row.ok_or(AppError::NotFound("claim mapper"))
}

pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    input: NewClaimMapper,
) -> AppResult<ClaimMapperRow> {
    let name = validate_name(&input.name)?;
    validate_config(&name, &input.config)?;
    if let Some(c) = input.client_id {
        crate::services::clients::get(state, tenant_id, c)
            .await
            .map_err(|_| AppError::BadRequest("client_id does not exist".into()))?;
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let row = repos::claim_mappers::insert(
        &mut *tx,
        tenant_id,
        Uuid::now_v7(),
        input.client_id,
        &name,
        &input.config,
    )
    .await
    .map_err(AppError::from_db)?;
    tx.commit().await?;
    bump_mappers_version(state, tenant_id).await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ClaimMapperCreated { mapper_id: row.id },
    ));
    Ok(row)
}

pub async fn update(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
    patch: ClaimMapperUpdate,
) -> AppResult<ClaimMapperRow> {
    let current = get(state, tenant_id, id).await?;
    let name = match &patch.name {
        Some(n) => validate_name(n)?,
        None => current.name.clone(),
    };
    if let Some(cfg) = &patch.config {
        validate_config(&name, cfg)?;
    } else if patch.name.is_some() {
        validate_config(&name, &current.config)?;
    }
    if patch.name.is_none() && patch.config.is_none() {
        return Ok(current);
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let row = repos::claim_mappers::update(
        &mut *tx,
        tenant_id,
        id,
        patch.name.as_deref().map(|_| name.as_str()),
        patch.config.as_ref(),
    )
    .await
    .map_err(AppError::from_db)?
    .ok_or(AppError::NotFound("claim mapper"))?;
    tx.commit().await?;
    bump_mappers_version(state, tenant_id).await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ClaimMapperUpdated { mapper_id: id },
    ));
    Ok(row)
}

pub async fn delete(state: &AppState, tenant_id: Uuid, actor: Actor, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::claim_mappers::delete(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    if !ok {
        return Err(AppError::NotFound("claim mapper"));
    }
    bump_mappers_version(state, tenant_id).await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ClaimMapperDeleted { mapper_id: id },
    ));
    Ok(())
}
