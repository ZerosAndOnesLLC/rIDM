//! Account recovery: password reset by emailed token and verification resend.
//! Requests never reveal whether an account exists and are rate-limited.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use redis::AsyncCommands as _;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::messaging::{self, Outgoing};
use crate::models::{MessageChannel, Tenant, User, UserStatus};
use crate::repos;
use crate::services::password::{self, SetPasswordOptions};
use crate::services::{logout, passwordless, refresh_tokens, registration, users};
use crate::state::AppState;

pub const RESET_TTL_SECS: u64 = 60 * 60;

fn hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

/// Send a reset link if the identifier belongs to an account with an email.
pub async fn request_password_reset(
    state: &AppState,
    tenant: &Tenant,
    identifier: &str,
    requested_locales: &[String],
) -> AppResult<()> {
    let identifier = identifier.trim().to_lowercase();
    if identifier.is_empty() {
        return Err(AppError::BadRequest("identifier is required".into()));
    }
    passwordless::check_send_limit(state, tenant.id, &format!("reset:{identifier}")).await?;
    let Some(user) = users::find_by_identifier(state, tenant.id, &identifier).await? else {
        return Ok(());
    };
    if user.status == UserStatus::Disabled || user.email.is_none() {
        return Ok(());
    }
    passwordless::check_send_limit(state, tenant.id, &format!("reset:user:{}", user.id)).await?;
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(
            keys::password_reset(tenant.id, &hash(&token)),
            user.id.to_string(),
            RESET_TTL_SECS,
        )
        .await?;
    let link = state
        .config
        .ui_page("recover", &[("tenant", &tenant.slug), ("token", &token)]);
    messaging::send(
        state,
        tenant,
        Outgoing {
            channel: MessageChannel::Email,
            event: "password_reset",
            recipient: user.email.as_deref().unwrap_or_default(),
            locale: Some(&crate::services::locale::negotiate(
                requested_locales,
                user.locale.as_deref(),
                &tenant.settings.locale,
            )),
            vars: messaging::vars::link(&user.username, &link, RESET_TTL_SECS / 60),
        },
    )
    .await?;
    state.events.publish(Event::new(
        Some(tenant.id),
        Actor::System,
        EventKind::PasswordResetRequested { user_id: user.id },
    ));
    Ok(())
}

/// Redeem a reset token: set the new password (policy enforced), unlock the
/// account, and revoke every refresh token so stolen sessions die with it.
pub async fn complete_password_reset(
    state: &AppState,
    tenant: &Tenant,
    token: &str,
    new_password: Zeroizing<String>,
) -> AppResult<User> {
    if token.is_empty() || token.len() > 128 {
        return Err(AppError::NotFound("reset token"));
    }
    let key = keys::password_reset(tenant.id, &hash(token));
    let mut conn = state.redis.get().await?;
    // Peek first so a policy failure does not burn the token.
    let raw: Option<String> = conn.get(&key).await?;
    let user_id: Uuid = raw
        .and_then(|r| Uuid::parse_str(&r).ok())
        .ok_or(AppError::NotFound("reset token"))?;
    password::set_password(
        state,
        tenant.id,
        &tenant.settings.password,
        Actor::User { id: user_id },
        user_id,
        new_password,
        SetPasswordOptions {
            must_change: false,
            skip_policy: false,
            by_user: true,
            notify: true,
        },
    )
    .await?;
    let _: () = conn.del(&key).await?;
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    repos::users::unlock(&mut *tx, tenant.id, user_id).await?;
    // Resetting via email proves control of the address.
    repos::users::update(
        &mut *tx,
        tenant.id,
        user_id,
        &crate::models::UserUpdate {
            email_verified: Some(true),
            ..Default::default()
        },
    )
    .await?;
    tx.commit().await?;
    // Whoever knew the old password may hold a session: end them all (the
    // relying parties are told) along with every refresh token.
    logout::end_sessions_for_user(state, tenant, user_id, None).await?;
    refresh_tokens::revoke_for_user(state, tenant.id, Actor::User { id: user_id }, user_id, None)
        .await?;
    state.events.publish(Event::new(
        Some(tenant.id),
        Actor::User { id: user_id },
        EventKind::PasswordResetCompleted { user_id },
    ));
    users::get(state, tenant.id, user_id).await
}

/// Send the verification email again for an unverified account.
pub async fn resend_verification(
    state: &AppState,
    tenant: &Tenant,
    identifier: &str,
) -> AppResult<()> {
    let identifier = identifier.trim().to_lowercase();
    if identifier.is_empty() {
        return Err(AppError::BadRequest("identifier is required".into()));
    }
    passwordless::check_send_limit(state, tenant.id, &format!("verify:{identifier}")).await?;
    let Some(user) = users::find_by_identifier(state, tenant.id, &identifier).await? else {
        return Ok(());
    };
    if user.email_verified || user.email.is_none() || user.status == UserStatus::Disabled {
        return Ok(());
    }
    registration::send_verification(state, tenant, &user, None).await
}
