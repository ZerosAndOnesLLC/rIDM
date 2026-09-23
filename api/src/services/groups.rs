//! Groups: nestable containers of users. Membership is inherited upwards
//! (a member of a child group is effectively a member of its ancestors).

use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{Group, GroupUpdate, NewGroup, User};
use crate::repos;
use crate::services::roles::bump_roles_version;
use crate::state::AppState;

/// Group memberships are versioned by the roles version; the TTL only bounds
/// a missed bump.
const GROUPS_TTL: std::time::Duration = std::time::Duration::from_secs(300);

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
    mut input: NewGroup,
) -> AppResult<Group> {
    input.name = validate_name(&input.name)?;
    if let Some(attrs) = &input.attributes
        && !attrs.is_object()
    {
        return Err(AppError::BadRequest(
            "attributes must be a JSON object".into(),
        ));
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    if let Some(parent) = input.parent_id
        && repos::groups::find_by_id(&mut *tx, tenant_id, parent)
            .await?
            .is_none()
    {
        return Err(AppError::BadRequest("parent group does not exist".into()));
    }
    let group = repos::groups::insert(&mut *tx, tenant_id, Uuid::now_v7(), &input)
        .await
        .map_err(|e| match AppError::from_db(e) {
            AppError::Conflict(_) => {
                AppError::Conflict("a sibling group with this name already exists".into())
            }
            other => other,
        })?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::GroupCreated { group_id: group.id },
    ));
    Ok(group)
}

pub async fn get(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<Group> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let g = repos::groups::find_by_id(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    g.ok_or(AppError::NotFound("group"))
}

pub async fn list(state: &AppState, tenant_id: Uuid) -> AppResult<Vec<Group>> {
    let mut tx = db::read_tx(&state.db, tenant_id).await?;
    let rows = repos::groups::list_all(&mut *tx, tenant_id).await?;
    tx.commit().await?;
    Ok(rows)
}

pub async fn update(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
    mut patch: GroupUpdate,
) -> AppResult<Group> {
    if patch.is_empty() {
        return get(state, tenant_id, id).await;
    }
    if let Some(n) = &patch.name {
        patch.name = Some(validate_name(n)?);
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    if let Some(Some(new_parent)) = patch.parent_id {
        if new_parent == id {
            return Err(AppError::BadRequest(
                "a group cannot be its own parent".into(),
            ));
        }
        // Moving under one of our own descendants would create a cycle.
        let ancestors_of_new_parent =
            repos::groups::ancestor_ids(&mut *tx, tenant_id, new_parent).await?;
        if ancestors_of_new_parent.is_empty() {
            return Err(AppError::BadRequest("parent group does not exist".into()));
        }
        if ancestors_of_new_parent.contains(&id) {
            return Err(AppError::BadRequest(
                "cannot move a group under one of its descendants".into(),
            ));
        }
    }
    let group = repos::groups::update(&mut *tx, tenant_id, id, &patch)
        .await
        .map_err(|e| match AppError::from_db(e) {
            AppError::Conflict(_) => {
                AppError::Conflict("a sibling group with this name already exists".into())
            }
            other => other,
        })?
        .ok_or(AppError::NotFound("group"))?;
    tx.commit().await?;
    if patch.parent_id.is_some() {
        bump_roles_version(state, tenant_id).await?;
    }
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::GroupUpdated { group_id: group.id },
    ));
    Ok(group)
}

/// Delete a group and (by cascade) its subgroups and memberships.
pub async fn delete(state: &AppState, tenant_id: Uuid, actor: Actor, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::groups::delete(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    if !ok {
        return Err(AppError::NotFound("group"));
    }
    bump_roles_version(state, tenant_id).await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::GroupDeleted { group_id: id },
    ));
    Ok(())
}

pub async fn add_member(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    group_id: Uuid,
    user_id: Uuid,
) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    if repos::groups::find_by_id(&mut *tx, tenant_id, group_id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound("group"));
    }
    if repos::users::find_by_id(&mut *tx, tenant_id, user_id)
        .await?
        .filter(|u| u.deleted_at.is_none())
        .is_none()
    {
        return Err(AppError::NotFound("user"));
    }
    let added = repos::groups::add_member(&mut *tx, tenant_id, group_id, user_id)
        .await
        .map_err(AppError::from_db)?;
    tx.commit().await?;
    if added {
        bump_roles_version(state, tenant_id).await?;
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::GroupMemberAdded { group_id, user_id },
        ));
    }
    Ok(())
}

pub async fn remove_member(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    group_id: Uuid,
    user_id: Uuid,
) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let removed = repos::groups::remove_member(&mut *tx, tenant_id, group_id, user_id).await?;
    tx.commit().await?;
    if removed {
        bump_roles_version(state, tenant_id).await?;
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::GroupMemberRemoved { group_id, user_id },
        ));
    }
    Ok(())
}

pub async fn members(state: &AppState, tenant_id: Uuid, group_id: Uuid) -> AppResult<Vec<User>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    if repos::groups::find_by_id(&mut *tx, tenant_id, group_id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound("group"));
    }
    let rows = repos::groups::members(&mut *tx, tenant_id, group_id).await?;
    tx.commit().await?;
    Ok(rows)
}

/// A user's groups, cached under the roles version (membership, group and
/// role changes all bump it), so token issuance does not walk the tree.
pub async fn groups_of_user(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    effective: bool,
) -> AppResult<Vec<Group>> {
    let version = crate::services::roles::roles_version(state, tenant_id).await?;
    let key = crate::cache::keys::user_groups(tenant_id, &version, user_id, effective);
    let db = state.db.clone();
    let loaded = state
        .cache
        .get_or_load(&key, GROUPS_TTL, || async move {
            let mut tx = db::tenant_tx(&db, tenant_id).await?;
            let rows = if effective {
                repos::groups::effective_groups_of_user(&mut *tx, tenant_id, user_id).await?
            } else {
                repos::groups::direct_groups_of_user(&mut *tx, tenant_id, user_id).await?
            };
            tx.commit().await?;
            Ok(Some(rows))
        })
        .await?;
    Ok(loaded.map(|g| (*g).clone()).unwrap_or_default())
}
