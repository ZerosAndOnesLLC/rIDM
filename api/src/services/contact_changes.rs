//! Changing the email address or phone number of one's own account.
//!
//! A change is proven before it lands: a six-digit code goes to the new
//! address or number, and only the right code (within the attempt limit and
//! before it expires) moves the account over, marking the new destination
//! verified. Codes are the passwordless module's (hashed in Redis, single
//! use, expiring, attempt-limited); the pending destination lives next to
//! the code and asking for a code again within the cooldown reuses the one
//! that went out. The previous address is told afterwards by the user
//! service's `email_changed` notice.

use redis::AsyncCommands as _;
use ridm_core::events::Actor;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult, FieldError};
use crate::messaging::{self, Outgoing};
use crate::models::{MessageChannel, Tenant, User, UserUpdate};
use crate::repos;
use crate::services::otp_factors::{self, Sent};
use crate::services::passwordless::{self, OTP_TTL_SECS};
use crate::services::{locale, users};
use crate::state::AppState;

/// A second request for a code within this window reuses the pending one.
pub const RESEND_COOLDOWN_SECS: u64 = otp_factors::RESEND_COOLDOWN_SECS;

/// Which contact detail is changing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Contact {
    Email,
    Phone,
}

impl Contact {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Phone => "phone",
        }
    }

    fn message_channel(self) -> MessageChannel {
        match self {
            Self::Email => MessageChannel::Email,
            Self::Phone => MessageChannel::Sms,
        }
    }

    fn mask(self, destination: &str) -> String {
        match self {
            Self::Email => otp_factors::mask_email(destination),
            Self::Phone => otp_factors::mask_phone(destination),
        }
    }

    fn normalize(self, raw: &str) -> AppResult<String> {
        let value = raw.trim();
        let result = match self {
            Self::Email => users::normalize_email(value),
            Self::Phone => users::normalize_phone(value),
        };
        result.map_err(|e| match e {
            AppError::BadRequest(message) => AppError::Validation(vec![FieldError {
                field: self.as_str().into(),
                message,
            }]),
            other => other,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Pending {
    destination: String,
}

/// The changes awaiting their code, masked for display.
#[derive(Debug, Default, Serialize, utoipa::ToSchema)]
pub struct PendingChanges {
    pub email: Option<String>,
    pub phone: Option<String>,
}

async fn load_pending(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    contact: Contact,
) -> AppResult<Option<String>> {
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = conn
        .get(keys::contact_change(tenant_id, user_id, contact.as_str()))
        .await?;
    Ok(raw
        .and_then(|r| serde_json::from_str::<Pending>(&r).ok())
        .map(|p| p.destination))
}

/// The user's pending changes, masked.
pub async fn pending(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<PendingChanges> {
    Ok(PendingChanges {
        email: load_pending(state, tenant_id, user_id, Contact::Email)
            .await?
            .map(|d| Contact::Email.mask(&d)),
        phone: load_pending(state, tenant_id, user_id, Contact::Phone)
            .await?
            .map(|d| Contact::Phone.mask(&d)),
    })
}

/// Drop a pending change and its code.
pub async fn cancel(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    contact: Contact,
) -> AppResult<()> {
    let c = contact.as_str();
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .del(&[
            keys::contact_change(tenant_id, user_id, c),
            keys::contact_change_code(tenant_id, user_id, c),
            keys::contact_change_cooldown(tenant_id, user_id, c),
        ])
        .await?;
    Ok(())
}

async fn deliver(
    state: &AppState,
    tenant: &Tenant,
    user: &User,
    contact: Contact,
    destination: &str,
    code: &str,
) -> AppResult<()> {
    let locale = locale::negotiate(&[], user.locale.as_deref(), &tenant.settings.locale);
    messaging::send(state, tenant, Outgoing {
        channel: contact.message_channel(),
        event: "otp",
        recipient: destination,
        locale: Some(&locale),
        vars: serde_json::json!({"user": {"username": user.username}, "code": code, "expires_minutes": OTP_TTL_SECS / 60}),
    })
    .await?;
    Ok(())
}

/// Start a change: a code goes to `raw` (an email address, or a phone number
/// in E.164). The destination is held until [`confirm`] proves it or the
/// code expires; a different destination replaces a pending one and discards
/// its code.
pub async fn begin(
    state: &AppState,
    tenant: &Tenant,
    user: &User,
    contact: Contact,
    raw: &str,
) -> AppResult<Sent> {
    let destination = contact.normalize(raw)?;
    let same = match contact {
        Contact::Email => user.email.as_deref() == Some(&destination) && user.email_verified,
        Contact::Phone => user.phone.as_deref() == Some(&destination) && user.phone_verified,
    };
    if same {
        return Err(AppError::Validation(vec![FieldError {
            field: contact.as_str().into(),
            message: "is already the verified one on the account".into(),
        }]));
    }
    if contact == Contact::Email {
        let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
        let taken = repos::users::find_by_email(&mut *tx, tenant.id, &destination)
            .await?
            .is_some_and(|other| other.id != user.id);
        tx.commit().await?;
        if taken {
            return Err(AppError::Conflict("email address already in use".into()));
        }
    }
    let c = contact.as_str();
    let pending_key = keys::contact_change(tenant.id, user.id, c);
    let mut conn = state.redis.get().await?;
    let previous: Option<String> = conn.get(&pending_key).await?;
    if let Some(prev) = previous.and_then(|r| serde_json::from_str::<Pending>(&r).ok())
        && prev.destination != destination
    {
        let _: () = conn
            .del(&[
                keys::contact_change_code(tenant.id, user.id, c),
                keys::contact_change_cooldown(tenant.id, user.id, c),
            ])
            .await?;
    }
    let _: () = conn
        .set_ex(
            &pending_key,
            serde_json::to_string(&Pending {
                destination: destination.clone(),
            })?,
            OTP_TTL_SECS,
        )
        .await?;
    // The cooldown is claimed atomically, so concurrent requests send once.
    let claimed: Option<String> = redis::cmd("SET")
        .arg(keys::contact_change_cooldown(tenant.id, user.id, c))
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(RESEND_COOLDOWN_SECS)
        .query_async(&mut conn)
        .await?;
    drop(conn);
    if claimed.is_some() {
        passwordless::check_send_limit(state, tenant.id, &format!("contact:{}", user.id)).await?;
        let code = passwordless::store_code(
            state,
            &keys::contact_change_code(tenant.id, user.id, c),
            user.id,
        )
        .await?;
        deliver(state, tenant, user, contact, &destination, &code).await?;
    }
    Ok(Sent {
        sent: true,
        destination: contact.mask(&destination),
    })
}

/// Prove the pending change. `Ok(None)` is a wrong code (the change stays
/// pending while attempts remain); success moves the account to the new
/// destination, verified, and returns the updated user.
pub async fn confirm(
    state: &AppState,
    tenant: &Tenant,
    user: &User,
    contact: Contact,
    code: &str,
) -> AppResult<Option<User>> {
    let c = contact.as_str();
    let Some(destination) = load_pending(state, tenant.id, user.id, contact).await? else {
        return Err(AppError::BadRequest(format!(
            "no {} change is pending; request a code first",
            c
        )));
    };
    let code_key = keys::contact_change_code(tenant.id, user.id, c);
    match passwordless::check_code(state, &code_key, code).await? {
        Some(uid) if uid == user.id => {}
        _ => {
            // The attempt limit or the clock ended the code: the change is over.
            let mut conn = state.redis.get().await?;
            let alive: bool = conn.exists(&code_key).await?;
            if !alive {
                cancel(state, tenant.id, user.id, contact).await?;
            }
            return Ok(None);
        }
    }
    let patch = match contact {
        Contact::Email => UserUpdate {
            email: Some(Some(destination)),
            email_verified: Some(true),
            ..Default::default()
        },
        Contact::Phone => UserUpdate {
            phone: Some(Some(destination)),
            phone_verified: Some(true),
            ..Default::default()
        },
    };
    let updated = users::update(
        state,
        tenant.id,
        Actor::User { id: user.id },
        user.id,
        patch,
    )
    .await
    .map_err(|e| match e {
        AppError::Conflict(_) => AppError::Conflict("email address already in use".into()),
        other => other,
    })?;
    cancel(state, tenant.id, user.id, contact).await?;
    Ok(Some(updated))
}

/// Take the phone number off the account. A number that backs an SMS
/// second factor stays until that factor is removed.
pub async fn remove_phone(state: &AppState, tenant: &Tenant, user: &User) -> AppResult<User> {
    if user.phone.is_none() {
        return Err(AppError::NotFound("phone number"));
    }
    if otp_factors::enrolled(state, tenant.id, user.id, otp_factors::Channel::Sms).await? {
        return Err(AppError::BadRequest(
            "the number is used for codes by text message; remove that second step first".into(),
        ));
    }
    cancel(state, tenant.id, user.id, Contact::Phone).await?;
    users::update(
        state,
        tenant.id,
        Actor::User { id: user.id },
        user.id,
        UserUpdate {
            phone: Some(None),
            ..Default::default()
        },
    )
    .await
}
