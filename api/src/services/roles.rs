//! Roles, assignments, composites, and cached effective-role resolution.
//!
//! Effective roles are cached under a key that includes a per-tenant version
//! token. Any change that can affect role resolution (roles, composites,
//! assignments, group membership, group hierarchy) replaces the token, which
//! makes every cached resolution for the tenant unreachable at once without a
//! pattern delete.

use std::sync::Arc;
use std::time::Duration;

use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{NewRole, Principal, Role, RoleAssignment, RoleHolder, RoleUpdate};
use crate::repos;
use crate::state::AppState;
use crate::util::cursor::{Cursor, Page, page_size};

const EFFECTIVE_ROLES_TTL: Duration = Duration::from_secs(60);
const ROLES_VERSION_TTL: u64 = 24 * 60 * 60;

fn validate_name(name: &str) -> AppResult<String> {
    let n = name.trim();
    if n.is_empty() || n.len() > 255 {
        return Err(AppError::BadRequest("name must be 1-255 characters".into()));
    }
    Ok(n.to_string())
}

pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    mut input: NewRole,
) -> AppResult<Role> {
    input.name = validate_name(&input.name)?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    crate::services::limits::ensure_room(&mut *tx, tenant_id, crate::services::limits::ROLES)
        .await?;
    let role = repos::roles::insert(&mut *tx, tenant_id, Uuid::now_v7(), &input)
        .await
        .map_err(|e| match AppError::from_db(e) {
            AppError::Conflict(_) => {
                AppError::Conflict("a role with this name already exists".into())
            }
            other => other,
        })?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::RoleCreated { role_id: role.id },
    ));
    Ok(role)
}

pub async fn get(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<Role> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let r = repos::roles::find_by_id(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    r.ok_or(AppError::NotFound("role"))
}

pub async fn list(
    state: &AppState,
    tenant_id: Uuid,
    client_id: Option<Option<Uuid>>,
) -> AppResult<Vec<Role>> {
    let mut tx = db::read_tx(&state.db, tenant_id).await?;
    let rows = repos::roles::list_all(&mut *tx, tenant_id, client_id).await?;
    tx.commit().await?;
    Ok(rows)
}

pub async fn update(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
    mut patch: RoleUpdate,
) -> AppResult<Role> {
    if patch.is_empty() {
        return get(state, tenant_id, id).await;
    }
    if let Some(n) = &patch.name {
        patch.name = Some(validate_name(n)?);
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    ensure_not_built_in(&mut tx, tenant_id, id).await?;
    let role = repos::roles::update(&mut *tx, tenant_id, id, &patch)
        .await
        .map_err(|e| match AppError::from_db(e) {
            AppError::Conflict(_) => {
                AppError::Conflict("a role with this name already exists".into())
            }
            other => other,
        })?
        .ok_or(AppError::NotFound("role"))?;
    tx.commit().await?;
    // Names appear in tokens; cached resolutions carry the old name.
    bump_roles_version(state, tenant_id).await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::RoleUpdated { role_id: role.id },
    ));
    Ok(role)
}

pub async fn delete(state: &AppState, tenant_id: Uuid, actor: Actor, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    ensure_not_built_in(&mut tx, tenant_id, id).await?;
    let ok = repos::roles::delete(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    if !ok {
        return Err(AppError::NotFound("role"));
    }
    bump_roles_version(state, tenant_id).await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::RoleDeleted { role_id: id },
    ));
    Ok(())
}

/// Built-in admin roles (`ridm:*`) are seeded by migrations and are immutable;
/// they can still be assigned and used as composites.
async fn ensure_not_built_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    id: Uuid,
) -> AppResult<()> {
    match repos::roles::find_by_id(&mut **tx, tenant_id, id).await? {
        Some(r) if r.built_in => Err(AppError::Forbidden(
            "built-in roles cannot be renamed or deleted".into(),
        )),
        Some(_) => Ok(()),
        None => Err(AppError::NotFound("role")),
    }
}

fn principal_ids(p: Principal) -> (Option<Uuid>, Option<Uuid>) {
    match p {
        Principal::User { id } => (Some(id), None),
        Principal::Group { id } => (None, Some(id)),
    }
}

pub async fn assign(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    role_id: Uuid,
    principal: Principal,
) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    if repos::roles::find_by_id(&mut *tx, tenant_id, role_id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound("role"));
    }
    match principal {
        Principal::User { id } => {
            if repos::users::find_by_id(&mut *tx, tenant_id, id)
                .await?
                .filter(|u| u.deleted_at.is_none())
                .is_none()
            {
                return Err(AppError::NotFound("user"));
            }
        }
        Principal::Group { id } => {
            if repos::groups::find_by_id(&mut *tx, tenant_id, id)
                .await?
                .is_none()
            {
                return Err(AppError::NotFound("group"));
            }
        }
    }
    let added = repos::roles::assign(&mut *tx, tenant_id, role_id, principal, None)
        .await
        .map_err(AppError::from_db)?;
    tx.commit().await?;
    if added {
        bump_for(state, tenant_id, principal).await?;
        let (user_id, group_id) = principal_ids(principal);
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::RoleAssigned {
                role_id,
                user_id,
                group_id,
            },
        ));
    }
    Ok(())
}

pub async fn unassign(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    role_id: Uuid,
    principal: Principal,
) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let removed = repos::roles::unassign(&mut *tx, tenant_id, role_id, principal, None).await?;
    tx.commit().await?;
    if removed {
        bump_for(state, tenant_id, principal).await?;
        let (user_id, group_id) = principal_ids(principal);
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::RoleUnassigned {
                role_id,
                user_id,
                group_id,
            },
        ));
    }
    Ok(())
}

/// Users and groups holding the role directly.
/// One page of the principals holding a role directly, in grant order.
pub async fn holders_of(
    state: &AppState,
    tenant_id: Uuid,
    role_id: Uuid,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> AppResult<Page<RoleHolder>> {
    let after = cursor.map(Cursor::decode).transpose()?;
    let limit = page_size(limit);
    let mut tx = db::read_tx(&state.db, tenant_id).await?;
    let rows = repos::roles::holders(
        &mut *tx,
        tenant_id,
        repos::roles::HoldersOf::Role(role_id),
        after,
        limit,
    )
    .await?;
    tx.commit().await?;
    Ok(holders_page(rows, limit))
}

/// A page of holders from `limit + 1` rows.
pub fn holders_page(rows: Vec<RoleHolder>, limit: i64) -> Page<RoleHolder> {
    Page::from_rows(rows, limit, |h| Cursor {
        created_at: h.assignment.created_at,
        id: h.assignment.id,
    })
}

pub async fn assignments_of(
    state: &AppState,
    tenant_id: Uuid,
    principal: Principal,
) -> AppResult<Vec<RoleAssignment>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::roles::assignments_of(&mut *tx, tenant_id, principal).await?;
    tx.commit().await?;
    Ok(rows)
}

pub async fn add_composite(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    parent_role_id: Uuid,
    child_role_id: Uuid,
) -> AppResult<()> {
    if parent_role_id == child_role_id {
        return Err(AppError::BadRequest("a role cannot contain itself".into()));
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    for id in [parent_role_id, child_role_id] {
        if repos::roles::find_by_id(&mut *tx, tenant_id, id)
            .await?
            .is_none()
        {
            return Err(AppError::NotFound("role"));
        }
    }
    if repos::roles::composite_would_cycle(&mut *tx, tenant_id, parent_role_id, child_role_id)
        .await?
    {
        return Err(AppError::BadRequest(
            "adding this composite would create a cycle".into(),
        ));
    }
    let added = repos::roles::add_composite(&mut *tx, tenant_id, parent_role_id, child_role_id)
        .await
        .map_err(AppError::from_db)?;
    tx.commit().await?;
    if added {
        bump_roles_version(state, tenant_id).await?;
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::RoleCompositeAdded {
                parent_role_id,
                child_role_id,
            },
        ));
    }
    Ok(())
}

pub async fn remove_composite(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    parent_role_id: Uuid,
    child_role_id: Uuid,
) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let removed =
        repos::roles::remove_composite(&mut *tx, tenant_id, parent_role_id, child_role_id).await?;
    tx.commit().await?;
    if removed {
        bump_roles_version(state, tenant_id).await?;
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::RoleCompositeRemoved {
                parent_role_id,
                child_role_id,
            },
        ));
    }
    Ok(())
}

pub async fn composites_of(
    state: &AppState,
    tenant_id: Uuid,
    parent_role_id: Uuid,
) -> AppResult<Vec<Role>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::roles::composites_of(&mut *tx, tenant_id, parent_role_id).await?;
    tx.commit().await?;
    Ok(rows)
}

/// Current version token for a tenant's role graph, creating one if absent
/// (held briefly per node, evicted everywhere by a bump).
pub async fn roles_version(state: &AppState, tenant_id: Uuid) -> AppResult<String> {
    state
        .cache
        .version(
            &keys::roles_version(tenant_id),
            std::time::Duration::from_secs(ROLES_VERSION_TTL),
        )
        .await
}

/// Replace the version token, orphaning every cached resolution for the tenant.
pub async fn bump_roles_version(state: &AppState, tenant_id: Uuid) -> AppResult<()> {
    state
        .cache
        .bump_version(
            &keys::roles_version(tenant_id),
            std::time::Duration::from_secs(ROLES_VERSION_TTL),
        )
        .await
}

/// The version one user's cached access (roles, groups, organizations,
/// admin permissions) hangs off: the tenant's role graph, and that user's
/// own memberships and grants. A role or group-tree change moves the first
/// for everyone; a membership or a direct grant moves only the second.
pub async fn access_version(state: &AppState, tenant_id: Uuid, user_id: Uuid) -> AppResult<String> {
    let user_key = keys::user_access_version(tenant_id, user_id);
    let (tenant, user) = tokio::try_join!(
        roles_version(state, tenant_id),
        state
            .cache
            .version(&user_key, std::time::Duration::from_secs(ROLES_VERSION_TTL),),
    )?;
    Ok(format!("{tenant}.{user}"))
}

/// A change to what these users alone hold (a membership, a grant to the
/// user): only their cached access is orphaned.
pub async fn bump_user_access(state: &AppState, tenant_id: Uuid, users: &[Uuid]) -> AppResult<()> {
    let versions: Vec<String> = users
        .iter()
        .map(|u| keys::user_access_version(tenant_id, *u))
        .collect();
    for chunk in versions.chunks(500) {
        state
            .cache
            .bump_versions(chunk, std::time::Duration::from_secs(ROLES_VERSION_TTL))
            .await?;
    }
    Ok(())
}

/// After a grant to `principal` changed: a user's is theirs alone, a
/// group's reaches every member (and the members of its subgroups).
pub async fn bump_for(state: &AppState, tenant_id: Uuid, principal: Principal) -> AppResult<()> {
    match principal {
        Principal::User { id } => bump_user_access(state, tenant_id, &[id]).await,
        Principal::Group { .. } => bump_roles_version(state, tenant_id).await,
    }
}

/// Effective roles of a user (direct + groups incl. ancestors + composites),
/// cached. `org_id` is the organization the caller acts in; grants scoped to
/// another organization are left out.
pub async fn effective_roles(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    org_id: Option<Uuid>,
) -> AppResult<Arc<Vec<Role>>> {
    let version = access_version(state, tenant_id, user_id).await?;
    let key = keys::effective_roles(tenant_id, &version, user_id, org_id);
    let db = state.db.clone();
    let roles = state
        .cache
        .get_or_load(&key, EFFECTIVE_ROLES_TTL, || async move {
            let mut tx = db::tenant_tx(&db, tenant_id).await?;
            let rows =
                repos::roles::effective_roles_of_user(&mut *tx, tenant_id, user_id, org_id).await?;
            tx.commit().await?;
            Ok(Some(rows))
        })
        .await?;
    Ok(roles.unwrap_or_default())
}

/// Every role the user holds anywhere in the tenant, whatever organization a
/// grant is scoped to. Cached separately from the scoped resolutions, under
/// the same version token.
pub async fn effective_roles_anywhere(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Arc<Vec<Role>>> {
    let version = access_version(state, tenant_id, user_id).await?;
    let key = keys::effective_roles_anywhere(tenant_id, &version, user_id);
    let db = state.db.clone();
    let roles = state
        .cache
        .get_or_load(&key, EFFECTIVE_ROLES_TTL, || async move {
            let mut tx = db::tenant_tx(&db, tenant_id).await?;
            let rows = repos::roles::effective_roles_of_user_anywhere(&mut *tx, tenant_id, user_id)
                .await?;
            tx.commit().await?;
            Ok(Some(rows))
        })
        .await?;
    Ok(roles.unwrap_or_default())
}

/// Effective role names, for token claims.
pub async fn effective_role_names(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    org_id: Option<Uuid>,
) -> AppResult<Vec<String>> {
    Ok(effective_roles(state, tenant_id, user_id, org_id)
        .await?
        .iter()
        .map(|r| r.name.clone())
        .collect())
}
