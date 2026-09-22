//! User lifecycle within a tenant. Passwords are handled by the password
//! service (Phase 1.4); this module owns identity data.

use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{NewUser, User, UserFilter, UserStatus, UserUpdate};
use crate::repos;
use crate::services::profile_schema;
use crate::state::AppState;
use crate::util::cursor::{Cursor, Page, page_size};

/// Lower-case and trim a username; reject characters that cannot appear in one.
pub fn normalize_username(raw: &str) -> AppResult<String> {
    let u = raw.trim().to_lowercase();
    if u.is_empty() || u.len() > 255 {
        return Err(AppError::BadRequest(
            "username must be 1-255 characters".into(),
        ));
    }
    if u.chars().any(char::is_whitespace) || u.chars().any(char::is_control) {
        return Err(AppError::BadRequest(
            "username must not contain whitespace".into(),
        ));
    }
    Ok(u)
}

/// Lower-case and trim an email; minimal structural validation.
pub fn normalize_email(raw: &str) -> AppResult<String> {
    let e = raw.trim().to_lowercase();
    if e.len() > 320 || !validator::ValidateEmail::validate_email(&e) {
        return Err(AppError::BadRequest("invalid email address".into()));
    }
    Ok(e)
}

pub fn normalize_phone(raw: &str) -> AppResult<String> {
    let p: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let digits = p.strip_prefix('+').unwrap_or(&p);
    if !p.starts_with('+')
        || digits.len() < 7
        || digits.len() > 15
        || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(AppError::BadRequest("phone must be in E.164 format".into()));
    }
    Ok(p)
}

pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    input: NewUser,
) -> AppResult<User> {
    let editor = profile_schema::Editor::from(&actor);
    create_as(state, tenant_id, actor, editor, input).await
}

/// [`create`] with the attributes written as `editor` instead of what the
/// actor implies: imports (bulk import, SCIM provisioning) are recorded as
/// the administrator or client that ran them but write as
/// [`profile_schema::Editor::System`], which may set `editable_by: none`
/// attributes.
pub async fn create_as(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    editor: profile_schema::Editor,
    mut input: NewUser,
) -> AppResult<User> {
    input.username = normalize_username(&input.username)?;
    input.email = input.email.as_deref().map(normalize_email).transpose()?;
    input.phone = input.phone.as_deref().map(normalize_phone).transpose()?;
    let schema = profile_schema::get(state, tenant_id).await?;
    let incoming = input
        .attributes
        .take()
        .unwrap_or_else(|| serde_json::Value::Object(Default::default()));
    input.attributes = Some(profile_schema::validate_attributes_with(
        &schema,
        &incoming,
        editor,
        None,
        !input.defer_required,
    )?);

    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let user = repos::users::insert(&mut *tx, tenant_id, Uuid::now_v7(), &input)
        .await
        .map_err(|e| match AppError::from_db(e) {
            AppError::Conflict(_) => AppError::Conflict("username or email already in use".into()),
            other => other,
        })?;
    tx.commit().await?;

    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::UserCreated { user_id: user.id },
    ));
    Ok(user)
}

pub async fn get(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<User> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let user = repos::users::find_by_id(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    user.filter(|u| u.deleted_at.is_none())
        .ok_or(AppError::NotFound("user"))
}

pub async fn find_by_identifier(
    state: &AppState,
    tenant_id: Uuid,
    identifier: &str,
) -> AppResult<Option<User>> {
    let ident = identifier.trim().to_lowercase();
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let user = repos::users::find_by_identifier(&mut *tx, tenant_id, &ident).await?;
    tx.commit().await?;
    Ok(user)
}

pub async fn update(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
    patch: UserUpdate,
) -> AppResult<User> {
    let editor = profile_schema::Editor::from(&actor);
    update_as(state, tenant_id, actor, editor, id, patch).await
}

/// [`update`] with the attributes written as `editor` (see [`create_as`]).
pub async fn update_as(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    editor: profile_schema::Editor,
    id: Uuid,
    mut patch: UserUpdate,
) -> AppResult<User> {
    if patch.is_empty() {
        return get(state, tenant_id, id).await;
    }
    patch.username = patch
        .username
        .as_deref()
        .map(normalize_username)
        .transpose()?;
    if let Some(Some(e)) = &patch.email {
        patch.email = Some(Some(normalize_email(e)?));
    }
    if let Some(Some(p)) = &patch.phone {
        patch.phone = Some(Some(normalize_phone(p)?));
    }

    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let before = repos::users::find_by_id(&mut *tx, tenant_id, id)
        .await?
        .filter(|u| u.deleted_at.is_none())
        .ok_or(AppError::NotFound("user"))?;
    if let Some(incoming) = patch.attributes.take() {
        let schema = profile_schema::get(state, tenant_id).await?;
        patch.attributes = Some(profile_schema::validate_attributes(
            &schema,
            &incoming,
            editor,
            Some(&before.attributes),
        )?);
    }
    // A directory user's username, email and mapped attributes belong to
    // the directory: written there first when it is writable, refused when
    // it is read-only. rIDM's own sync (the system actor) is the exception.
    // Directory users have no local password, so others skip the lookup.
    if before.password_hash.is_none()
        && !matches!(actor, Actor::System)
        && (patch.username.is_some() || patch.email.is_some() || patch.attributes.is_some())
    {
        crate::services::ldap::write_profile(state, tenant_id, &before, &patch).await?;
    }
    let user = repos::users::update(&mut *tx, tenant_id, id, &patch)
        .await
        .map_err(|e| match AppError::from_db(e) {
            AppError::Conflict(_) => AppError::Conflict("username or email already in use".into()),
            other => other,
        })?
        .ok_or(AppError::NotFound("user"))?;
    tx.commit().await?;

    state.events.publish(Event::new(
        Some(tenant_id),
        actor.clone(),
        EventKind::UserUpdated { user_id: user.id },
    ));
    if patch.email.is_some() && before.email != user.email {
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::EmailChanged {
                user_id: user.id,
                old_email: before.email.clone(),
                new_email: user.email.clone(),
            },
        ));
        let tenant = crate::services::tenants::get(state, tenant_id).await?;
        crate::services::notifications::email_changed(
            state,
            &tenant,
            &before,
            user.email.as_deref(),
        )
        .await;
    }
    // Disabled by any path (admin API, SCIM, import): signed out everywhere
    // at once, and the relying parties are told.
    if user.status == UserStatus::Disabled && before.status != UserStatus::Disabled {
        let tenant = crate::services::tenants::get(state, tenant_id).await?;
        crate::services::logout::end_sessions_for_user(state, &tenant, id, None).await?;
    }
    Ok(user)
}

/// Soft delete. The purge job removes the row after the retention period.
pub async fn delete(state: &AppState, tenant_id: Uuid, actor: Actor, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let deleted = repos::users::soft_delete(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    if !deleted {
        return Err(AppError::NotFound("user"));
    }
    state
        .cache
        .invalidate(&[crate::cache::keys::roles_version(tenant_id)])
        .await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::UserDeleted { user_id: id },
    ));
    // Deleted by any path (admin API, SCIM, self-service): signed out
    // everywhere, and the relying parties are told.
    let tenant = crate::services::tenants::get(state, tenant_id).await?;
    crate::services::logout::end_sessions_for_user(state, &tenant, id, None).await?;
    Ok(())
}

pub async fn list(
    state: &AppState,
    tenant_id: Uuid,
    filter: &UserFilter,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> AppResult<Page<User>> {
    let after = cursor.map(Cursor::decode).transpose()?;
    let limit = page_size(limit);
    let mut tx = db::read_tx(&state.db_read, tenant_id).await?;
    let rows = repos::users::list(&mut *tx, tenant_id, filter, after, limit).await?;
    tx.commit().await?;
    Ok(Page::from_rows(rows, limit, |u| Cursor {
        created_at: u.created_at,
        id: u.id,
    }))
}

pub async fn unlock(state: &AppState, tenant_id: Uuid, actor: Actor, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::users::unlock(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    if !ok {
        return Err(AppError::NotFound("user"));
    }
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::UserUpdated { user_id: id },
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_identifiers() {
        assert_eq!(normalize_username("  Alice ").unwrap(), "alice");
        assert!(normalize_username("a b").is_err());
        assert!(normalize_username("").is_err());
        assert_eq!(
            normalize_email(" Alice@Example.COM ").unwrap(),
            "alice@example.com"
        );
        assert!(normalize_email("not-an-email").is_err());
        assert_eq!(normalize_phone("+1 555 123 4567").unwrap(), "+15551234567");
        assert!(normalize_phone("5551234567").is_err());
        assert!(normalize_phone("+12ab").is_err());
    }
}
