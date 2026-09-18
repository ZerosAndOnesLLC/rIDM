//! Resource servers (API audiences) and their permissions. The per-tenant
//! built-in server `urn:ridm:admin` and its permission catalogue are seeded
//! by migration and cannot be changed or deleted; granting its permissions
//! to roles is how custom admin roles are built.

use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use std::sync::Arc;
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{
    NewPermission, NewResourceServer, Permission, ResourceServer, ResourceServerUpdate, SigningAlg,
};
use crate::repos;
use crate::services::roles;
use crate::state::AppState;

/// Cached audience lookups; every write evicts, the TTL bounds a missed one.
const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

fn validate_identifier(s: &str) -> AppResult<String> {
    let id = s.trim().to_string();
    if id.is_empty() || id.len() > 512 || id.chars().any(char::is_whitespace) {
        return Err(AppError::BadRequest(
            "identifier must be 1-512 characters without whitespace".into(),
        ));
    }
    Ok(id)
}

fn validate_name(s: &str) -> AppResult<String> {
    let n = s.trim().to_string();
    if n.is_empty() || n.len() > 255 {
        return Err(AppError::BadRequest("name must be 1-255 characters".into()));
    }
    Ok(n)
}

/// Any algorithm rIDM signs with, in its canonical spelling.
fn validate_signing_alg(alg: &str) -> AppResult<SigningAlg> {
    SigningAlg::ALL
        .into_iter()
        .find(|a| a.as_str() == alg)
        .ok_or_else(|| {
            let known: Vec<&str> = SigningAlg::ALL.iter().map(|a| a.as_str()).collect();
            AppError::BadRequest(format!(
                "unsupported signing_alg `{alg}` ({})",
                known.join(", ")
            ))
        })
}

/// Access tokens for a server with a `signing_alg` are signed with the
/// tenant's active key of that algorithm. Make sure one exists when the
/// setting is saved, so the first token request does not pay for (RSA) key
/// generation and a key problem surfaces here rather than at `/token`.
async fn ensure_signing_key(state: &AppState, tenant_id: Uuid, alg: SigningAlg) -> AppResult<()> {
    let tenant = crate::services::tenants::get_cached(state, tenant_id)
        .await?
        .ok_or(AppError::NotFound("tenant"))?;
    crate::services::keys::ensure_active_alg(state, tenant_id, &tenant.settings.keys, alg).await?;
    Ok(())
}

fn validate_ttl(ttl: Option<i32>) -> AppResult<()> {
    match ttl {
        Some(t) if !(60..=86_400).contains(&t) => Err(AppError::BadRequest(
            "token_ttl_secs must be between 60 and 86400".into(),
        )),
        _ => Ok(()),
    }
}

pub async fn list(state: &AppState, tenant_id: Uuid) -> AppResult<Vec<ResourceServer>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::resource_servers::list(&mut *tx, tenant_id).await?;
    tx.commit().await?;
    Ok(rows)
}

/// Resource server by identifier through the cache (the token endpoint's
/// audience lookup); evicted by every write to the server.
pub async fn find_by_identifier_cached(
    state: &AppState,
    tenant_id: Uuid,
    identifier: &str,
) -> AppResult<Option<Arc<ResourceServer>>> {
    let db = state.db.clone();
    let ident = identifier.to_string();
    state
        .cache
        .get_or_load(
            &crate::cache::keys::resource_server(tenant_id, identifier),
            CACHE_TTL,
            || async move {
                let mut tx = db::tenant_tx(&db, tenant_id).await?;
                let rs = repos::resource_servers::find_by_identifier(&mut *tx, tenant_id, &ident)
                    .await?;
                tx.commit().await?;
                Ok(rs)
            },
        )
        .await
}

/// Permission names `role_ids` hold on `rs_id`, cached under the roles
/// version so any grant change is seen at once.
pub async fn permissions_for_roles_cached(
    state: &AppState,
    tenant_id: Uuid,
    rs_id: Uuid,
    role_ids: &[Uuid],
) -> AppResult<Arc<Vec<String>>> {
    if role_ids.is_empty() {
        return Ok(Arc::new(vec![]));
    }
    let version = roles::roles_version(state, tenant_id).await?;
    let mut sorted: Vec<Uuid> = role_ids.to_vec();
    sorted.sort();
    sorted.dedup();
    let roles_key = {
        use sha2::Digest as _;
        let mut h = sha2::Sha256::new();
        for id in &sorted {
            h.update(id.as_bytes());
        }
        hex::encode(&h.finalize()[..12])
    };
    let db = state.db.clone();
    let key =
        crate::cache::keys::resource_server_permissions(tenant_id, &version, rs_id, &roles_key);
    let loaded = state
        .cache
        .get_or_load(&key, CACHE_TTL, || async move {
            let mut tx = db::tenant_tx(&db, tenant_id).await?;
            let perms =
                repos::resource_servers::permissions_for_roles(&mut *tx, tenant_id, rs_id, &sorted)
                    .await?;
            tx.commit().await?;
            Ok(Some(perms))
        })
        .await?;
    Ok(loaded.unwrap_or_default())
}

pub async fn get(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<ResourceServer> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rs = repos::resource_servers::find_by_id(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    rs.ok_or(AppError::NotFound("resource server"))
}

pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    input: NewResourceServer,
) -> AppResult<ResourceServer> {
    let identifier = validate_identifier(&input.identifier)?;
    let name = validate_name(&input.name)?;
    let alg = input
        .signing_alg
        .as_deref()
        .map(validate_signing_alg)
        .transpose()?;
    validate_ttl(input.token_ttl_secs)?;
    if let Some(alg) = alg {
        ensure_signing_key(state, tenant_id, alg).await?;
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rs = repos::resource_servers::insert(
        &mut *tx,
        tenant_id,
        Uuid::now_v7(),
        &identifier,
        &name,
        input.token_ttl_secs,
        input.signing_alg.as_deref(),
        input.allow_offline_access.unwrap_or(true),
    )
    .await
    .map_err(|e| match AppError::from_db(e) {
        AppError::Conflict(_) => AppError::Conflict("identifier already exists".into()),
        other => other,
    })?;
    tx.commit().await?;
    state
        .cache
        .invalidate(&[crate::cache::keys::resource_server(
            tenant_id,
            &rs.identifier,
        )])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ResourceServerCreated {
            resource_server_id: rs.id,
        },
    ));
    Ok(rs)
}

pub async fn update(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
    mut patch: ResourceServerUpdate,
) -> AppResult<ResourceServer> {
    if patch.is_empty() {
        return get(state, tenant_id, id).await;
    }
    if let Some(n) = &patch.name {
        patch.name = Some(validate_name(n)?);
    }
    let new_alg = match &patch.signing_alg {
        Some(Some(alg)) => Some(validate_signing_alg(alg)?),
        _ => None,
    };
    if let Some(t) = patch.token_ttl_secs {
        validate_ttl(t)?;
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let current = repos::resource_servers::find_by_id(&mut *tx, tenant_id, id)
        .await?
        .ok_or(AppError::NotFound("resource server"))?;
    if current.built_in {
        return Err(AppError::Forbidden(
            "built-in resource servers cannot be changed".into(),
        ));
    }
    let rs = repos::resource_servers::update(&mut *tx, tenant_id, id, &patch)
        .await?
        .ok_or(AppError::NotFound("resource server"))?;
    tx.commit().await?;
    if let Some(alg) = new_alg {
        ensure_signing_key(state, tenant_id, alg).await?;
    }
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ResourceServerUpdated {
            resource_server_id: id,
        },
    ));
    state
        .cache
        .invalidate(&[crate::cache::keys::resource_server(
            tenant_id,
            &rs.identifier,
        )])
        .await?;
    Ok(rs)
}

/// Deleting cascades to permissions, their grants and scopes bound to the
/// server, so the roles version moves.
pub async fn delete(state: &AppState, tenant_id: Uuid, actor: Actor, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let current = repos::resource_servers::find_by_id(&mut *tx, tenant_id, id)
        .await?
        .ok_or(AppError::NotFound("resource server"))?;
    if current.built_in {
        return Err(AppError::Forbidden(
            "built-in resource servers cannot be deleted".into(),
        ));
    }
    repos::resource_servers::delete(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    roles::bump_roles_version(state, tenant_id).await?;
    state
        .cache
        .invalidate(&[
            crate::cache::keys::scopes(tenant_id),
            crate::cache::keys::resource_server(tenant_id, &current.identifier),
        ])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::ResourceServerDeleted {
            resource_server_id: id,
        },
    ));
    Ok(())
}

// --- permissions ------------------------------------------------------------

pub async fn list_permissions(
    state: &AppState,
    tenant_id: Uuid,
    resource_server_id: Uuid,
) -> AppResult<Vec<Permission>> {
    get(state, tenant_id, resource_server_id).await?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows =
        repos::resource_servers::list_permissions(&mut *tx, tenant_id, resource_server_id).await?;
    tx.commit().await?;
    Ok(rows)
}

pub async fn get_permission(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<Permission> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let p = repos::resource_servers::find_permission(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    p.ok_or(AppError::NotFound("permission"))
}

fn validate_permission_name(s: &str) -> AppResult<String> {
    let n = s.trim().to_string();
    if n.is_empty() || n.len() > 255 || n.chars().any(char::is_whitespace) {
        return Err(AppError::BadRequest(
            "permission name must be 1-255 characters without whitespace".into(),
        ));
    }
    Ok(n)
}

pub async fn create_permission(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    resource_server_id: Uuid,
    input: NewPermission,
) -> AppResult<Permission> {
    let name = validate_permission_name(&input.name)?;
    let rs = get(state, tenant_id, resource_server_id).await?;
    if rs.built_in {
        return Err(AppError::Forbidden(
            "the built-in permission catalogue cannot be extended".into(),
        ));
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let p = repos::resource_servers::insert_permission(
        &mut *tx,
        tenant_id,
        Uuid::now_v7(),
        resource_server_id,
        &name,
        input.description.as_deref(),
    )
    .await
    .map_err(|e| match AppError::from_db(e) {
        AppError::Conflict(_) => AppError::Conflict("permission already exists".into()),
        other => other,
    })?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::PermissionCreated {
            resource_server_id,
            permission_id: p.id,
        },
    ));
    Ok(p)
}

pub async fn delete_permission(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    resource_server_id: Uuid,
    id: Uuid,
) -> AppResult<()> {
    let rs = get(state, tenant_id, resource_server_id).await?;
    if rs.built_in {
        return Err(AppError::Forbidden(
            "built-in permissions cannot be deleted".into(),
        ));
    }
    let p = get_permission(state, tenant_id, id).await?;
    if p.resource_server_id != resource_server_id {
        return Err(AppError::NotFound("permission"));
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    repos::resource_servers::delete_permission(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    roles::bump_roles_version(state, tenant_id).await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::PermissionDeleted {
            resource_server_id,
            permission_id: id,
        },
    ));
    Ok(())
}

// --- grants to roles ---------------------------------------------------------

pub async fn permissions_of_role(
    state: &AppState,
    tenant_id: Uuid,
    role_id: Uuid,
) -> AppResult<Vec<Permission>> {
    roles::get(state, tenant_id, role_id).await?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::resource_servers::permissions_of_role(&mut *tx, tenant_id, role_id).await?;
    tx.commit().await?;
    Ok(rows)
}

/// Grant a permission to a role. Built-in roles keep their seeded set.
/// Admin permissions are cached under the roles version, which moves here.
pub async fn grant(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    role_id: Uuid,
    permission_id: Uuid,
) -> AppResult<()> {
    let role = roles::get(state, tenant_id, role_id).await?;
    if role.built_in {
        return Err(AppError::Forbidden(
            "built-in roles cannot be changed".into(),
        ));
    }
    get_permission(state, tenant_id, permission_id).await?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let added =
        repos::resource_servers::assign_permission(&mut *tx, tenant_id, role_id, permission_id)
            .await?;
    tx.commit().await?;
    if added {
        roles::bump_roles_version(state, tenant_id).await?;
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::PermissionGranted {
                role_id,
                permission_id,
            },
        ));
    }
    Ok(())
}

pub async fn revoke(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    role_id: Uuid,
    permission_id: Uuid,
) -> AppResult<()> {
    let role = roles::get(state, tenant_id, role_id).await?;
    if role.built_in {
        return Err(AppError::Forbidden(
            "built-in roles cannot be changed".into(),
        ));
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let removed =
        repos::resource_servers::unassign_permission(&mut *tx, tenant_id, role_id, permission_id)
            .await?;
    tx.commit().await?;
    if !removed {
        return Err(AppError::NotFound("permission grant"));
    }
    roles::bump_roles_version(state, tenant_id).await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::PermissionRevoked {
            role_id,
            permission_id,
        },
    ));
    Ok(())
}
