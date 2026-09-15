//! Invitations: an admin invites an email address with roles/groups; the
//! invitee creates the account through a signed link.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::db;
use crate::error::{AppError, AppResult, FieldError};
use crate::messaging::{self, Outgoing};
use crate::models::{
    Invitation, MessageChannel, NewInvitation, NewUser, Principal, Tenant, User, UserStatus,
};
use crate::repos;
use crate::services::password::{self, SetPasswordOptions};
use crate::services::registration::RegistrationInput;
use crate::services::{roles, users};
use crate::state::AppState;
use crate::util::cursor::{Cursor, Page, page_size};

fn hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn new_token() -> String {
    let mut b = [0u8; 32];
    rand::fill(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

/// Create and email an invitation. Returns the invitation (the token is only in the email).
pub async fn create(
    state: &AppState,
    tenant: &Tenant,
    actor: Actor,
    input: NewInvitation,
) -> AppResult<Invitation> {
    let email = users::normalize_email(&input.email)?;
    if users::find_by_identifier(state, tenant.id, &email)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(
            "a user with this email already exists".into(),
        ));
    }
    let days = input.expires_days.unwrap_or(7).clamp(1, 90);
    let token = new_token();
    let invited_by = match &actor {
        Actor::User { id } | Actor::Admin { id } => Some(*id),
        _ => None,
    };
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    for r in &input.roles {
        if repos::roles::find_by_id(&mut *tx, tenant.id, *r)
            .await?
            .is_none()
        {
            return Err(AppError::BadRequest(format!("role {r} does not exist")));
        }
    }
    for g in &input.groups {
        if repos::groups::find_by_id(&mut *tx, tenant.id, *g)
            .await?
            .is_none()
        {
            return Err(AppError::BadRequest(format!("group {g} does not exist")));
        }
    }
    let inv = repos::invitations::insert(
        &mut *tx,
        tenant.id,
        Uuid::now_v7(),
        &email,
        &input.roles,
        &input.groups,
        input.org_id,
        &hash(&token),
        invited_by,
        Utc::now() + Duration::days(i64::from(days)),
    )
    .await
    .map_err(AppError::from_db)?;
    tx.commit().await?;
    send_email(state, tenant, &inv, &token, days).await?;
    state.events.publish(Event::new(
        Some(tenant.id),
        actor,
        EventKind::InvitationCreated {
            invitation_id: inv.id,
            email: inv.email.clone(),
        },
    ));
    Ok(inv)
}

async fn send_email(
    state: &AppState,
    tenant: &Tenant,
    inv: &Invitation,
    token: &str,
    days: u32,
) -> AppResult<()> {
    let inviter = match inv.invited_by {
        Some(id) => users::get(state, tenant.id, id)
            .await
            .map(|u| u.username)
            .unwrap_or_else(|_| "An administrator".into()),
        None => "An administrator".into(),
    };
    let link = state
        .config
        .ui_page("invite", &[("tenant", &tenant.slug), ("token", token)]);
    messaging::send(
        state,
        tenant,
        Outgoing {
            channel: MessageChannel::Email,
            event: "invitation",
            recipient: &inv.email,
            locale: None,
            vars: serde_json::json!({"inviter": inviter, "link": link, "expires_days": days}),
        },
    )
    .await?;
    Ok(())
}

/// Generate a fresh token and send the email again.
pub async fn resend(
    state: &AppState,
    tenant: &Tenant,
    actor: Actor,
    id: Uuid,
) -> AppResult<Invitation> {
    let token = new_token();
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    let inv = repos::invitations::find_by_id(&mut *tx, tenant.id, id)
        .await?
        .ok_or(AppError::NotFound("invitation"))?;
    if inv.accepted_at.is_some() || inv.revoked_at.is_some() {
        return Err(AppError::BadRequest("invitation is no longer open".into()));
    }
    let expires = Utc::now() + Duration::days(7);
    repos::invitations::set_token_hash(&mut *tx, tenant.id, id, &hash(&token), expires).await?;
    let inv = repos::invitations::find_by_id(&mut *tx, tenant.id, id)
        .await?
        .ok_or(AppError::NotFound("invitation"))?;
    tx.commit().await?;
    send_email(state, tenant, &inv, &token, 7).await?;
    let _ = actor;
    Ok(inv)
}

pub async fn revoke(state: &AppState, tenant_id: Uuid, actor: Actor, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::invitations::revoke(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    if !ok {
        return Err(AppError::NotFound("invitation"));
    }
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::InvitationRevoked { invitation_id: id },
    ));
    Ok(())
}

pub async fn list(
    state: &AppState,
    tenant_id: Uuid,
    open_only: bool,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> AppResult<Page<Invitation>> {
    let after = cursor.map(Cursor::decode).transpose()?;
    let limit = page_size(limit);
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::invitations::list(&mut *tx, tenant_id, open_only, after, limit).await?;
    tx.commit().await?;
    Ok(Page::from_rows(rows, limit, |i| Cursor {
        created_at: i.created_at,
        id: i.id,
    }))
}

/// What the invitee may see before accepting.
#[derive(Debug, Serialize)]
pub struct PublicInvitation {
    pub email: String,
    pub tenant: String,
    pub invited_by: Option<String>,
    pub expires_at: chrono::DateTime<Utc>,
}

/// Look up an open invitation by its token.
pub async fn lookup(
    state: &AppState,
    tenant: &Tenant,
    token: &str,
) -> AppResult<(Invitation, PublicInvitation)> {
    if token.is_empty() || token.len() > 128 {
        return Err(AppError::NotFound("invitation"));
    }
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    let inv = repos::invitations::find_by_token_hash(&mut *tx, tenant.id, &hash(token))
        .await?
        .filter(|i| i.is_open(Utc::now()))
        .ok_or(AppError::NotFound("invitation"))?;
    tx.commit().await?;
    let invited_by = match inv.invited_by {
        Some(id) => users::get(state, tenant.id, id)
            .await
            .ok()
            .map(|u| u.username),
        None => None,
    };
    let public = PublicInvitation {
        email: inv.email.clone(),
        tenant: tenant.display_name.clone(),
        invited_by,
        expires_at: inv.expires_at,
    };
    Ok((inv, public))
}

/// Accept: create the user (email already proven), assign roles and groups.
pub async fn accept(
    state: &AppState,
    tenant: &Tenant,
    token: &str,
    input: RegistrationInput,
) -> AppResult<User> {
    let (inv, _) = lookup(state, tenant, token).await?;
    if tenant.settings.registration.require_terms && !input.terms_accepted {
        return Err(AppError::Validation(vec![FieldError {
            field: "terms_accepted".into(),
            message: "the terms must be accepted".into(),
        }]));
    }
    if tenant.settings.auth.password && input.password.as_deref().unwrap_or_default().is_empty() {
        return Err(AppError::Validation(vec![FieldError {
            field: "password".into(),
            message: "password is required".into(),
        }]));
    }
    let username = match input
        .username
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
    {
        Some(u) => users::normalize_username(u)?,
        None => inv.email.clone(),
    };
    let user = users::create(
        state,
        tenant.id,
        Actor::System,
        NewUser {
            username,
            email: Some(inv.email.clone()),
            email_verified: true,
            status: Some(UserStatus::Active),
            attributes: input.attributes.clone(),
            locale: input.locale.clone(),
            org_id: inv.org_id,
            ..Default::default()
        },
    )
    .await?;
    if let Some(pw) = input.password.filter(|p| !p.is_empty())
        && let Err(e) = password::set_password(
            state,
            tenant.id,
            &tenant.settings.password,
            Actor::User { id: user.id },
            user.id,
            Zeroizing::new(pw),
            SetPasswordOptions {
                must_change: false,
                skip_policy: false,
                by_user: true,
            },
        )
        .await
    {
        let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
        repos::users::hard_delete(&mut *tx, tenant.id, user.id).await?;
        tx.commit().await?;
        return Err(e);
    }
    for r in &inv.roles {
        roles::assign(
            state,
            tenant.id,
            Actor::System,
            *r,
            Principal::User { id: user.id },
        )
        .await?;
    }
    for g in &inv.groups {
        crate::services::groups::add_member(state, tenant.id, Actor::System, *g, user.id).await?;
    }
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    if input.terms_accepted {
        repos::users::set_terms_accepted(&mut *tx, tenant.id, user.id).await?;
    }
    let accepted = repos::invitations::mark_accepted(&mut *tx, tenant.id, inv.id).await?;
    tx.commit().await?;
    if !accepted {
        return Err(AppError::Conflict("invitation was already used".into()));
    }
    state.events.publish(Event::new(
        Some(tenant.id),
        Actor::User { id: user.id },
        EventKind::InvitationAccepted {
            invitation_id: inv.id,
            user_id: user.id,
        },
    ));
    users::get(state, tenant.id, user.id).await
}
