//! User lifecycle within a tenant. Passwords are handled by the password
//! service (Phase 1.4); this module owns identity data.

use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{NewUser, User, UserFilter, UserUpdate};
use crate::repos;
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

fn validate_attributes(attrs: &serde_json::Value) -> AppResult<()> {
    if !attrs.is_object() {
        return Err(AppError::BadRequest(
            "attributes must be a JSON object".into(),
        ));
    }
    Ok(())
}

pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    mut input: NewUser,
) -> AppResult<User> {
    input.username = normalize_username(&input.username)?;
    input.email = input.email.as_deref().map(normalize_email).transpose()?;
    input.phone = input.phone.as_deref().map(normalize_phone).transpose()?;
    if let Some(attrs) = &input.attributes {
        validate_attributes(attrs)?;
    }

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
    if let Some(attrs) = &patch.attributes {
        validate_attributes(attrs)?;
    }

    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
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
        actor,
        EventKind::UserUpdated { user_id: user.id },
    ));
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
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
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
