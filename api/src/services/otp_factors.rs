//! Email and SMS one-time codes as second factors.
//!
//! Enrolling proves the channel once with a code sent to the address or
//! number; one `email_otp` or `sms_otp` credential row then marks the factor
//! (its encrypted material is the destination that was proven, its label a
//! masked form for display). Later sign-ins send a code to the account's
//! current, verified email or phone. Codes are the passwordless module's:
//! hashed in Redis, bound to the flow, single-use, expiring and
//! attempt-limited. Sends are rate-limited per user, and a code asked for
//! again within the cooldown is not sent twice.

use redis::AsyncCommands as _;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult, FieldError};
use crate::messaging::{self, Outgoing};
use crate::models::{MessageChannel, Tenant, User, UserUpdate};
use crate::repos;
use crate::services::credential_secrets::encrypt;
use crate::services::login_flows::LoginFlow;
use crate::services::passwordless::{self, OTP_TTL_SECS};
use crate::services::{locale, notifications, users};
use crate::state::AppState;

pub const KIND_EMAIL: &str = "email_otp";
pub const KIND_SMS: &str = "sms_otp";
/// A second request for a code within this window reuses the pending one.
pub const RESEND_COOLDOWN_SECS: u64 = 20;
const ENROLMENT_TTL_SECS: u64 = OTP_TTL_SECS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Email,
    Sms,
}

impl Channel {
    /// The `credentials.type` of the factor.
    pub fn kind(self) -> &'static str {
        match self {
            Self::Email => KIND_EMAIL,
            Self::Sms => KIND_SMS,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Sms => "sms",
        }
    }

    /// `amr` values a passed code asserts.
    pub fn amr(self) -> &'static [&'static str] {
        match self {
            Self::Email => &["otp"],
            Self::Sms => &["otp", "sms"],
        }
    }

    /// Does the tenant offer this factor for enrolment?
    pub fn offered(self, tenant: &Tenant) -> bool {
        let m = &tenant.settings.mfa_methods;
        match self {
            Self::Email => m.email_otp,
            Self::Sms => m.sms_otp,
        }
    }

    fn message_channel(self) -> MessageChannel {
        match self {
            Self::Email => MessageChannel::Email,
            Self::Sms => MessageChannel::Sms,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Email => "email code",
            Self::Sms => "SMS code",
        }
    }

    fn mask(self, destination: &str) -> String {
        match self {
            Self::Email => mask_email(destination),
            Self::Sms => mask_phone(destination),
        }
    }
}

/// Encrypted material of the credential row: what was proven at enrolment.
#[derive(Debug, Serialize, Deserialize)]
struct FactorData {
    destination: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingEnrolment {
    destination: String,
}

/// Where a code went, as told to the user (masked).
#[derive(Debug, Clone, Serialize)]
pub struct Sent {
    pub sent: bool,
    pub destination: String,
}

/// `alice@example.com` → `a•••@example.com`.
pub fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => {
            let first = local.chars().next().unwrap_or('•');
            format!("{first}•••@{domain}")
        }
        None => "•••".into(),
    }
}

/// `+15551234567` → `•••••••••67`: the last two digits only.
pub fn mask_phone(phone: &str) -> String {
    let digits: Vec<char> = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    let keep = digits.len().min(2);
    let hidden = "•".repeat(digits.len().saturating_sub(keep).max(3));
    let tail: String = digits[digits.len() - keep..].iter().collect();
    format!("{hidden}{tail}")
}

fn code_key(tenant_id: Uuid, flow_id: Uuid, channel: Channel, purpose: &str) -> String {
    keys::flow_otp(
        tenant_id,
        flow_id,
        &format!("mfa:{}:{purpose}", channel.as_str()),
    )
}

/// The address or number a verification code goes to: the account's
/// current one, which enrolment or a passwordless sign-in verified.
fn destination_of(user: &User, channel: Channel) -> Option<&str> {
    match channel {
        Channel::Email => user.email.as_deref().filter(|_| user.email_verified),
        Channel::Sms => user.phone.as_deref().filter(|_| user.phone_verified),
    }
}

/// Has the user enrolled this channel as a factor?
pub async fn enrolled(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    channel: Channel,
) -> AppResult<bool> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let n =
        repos::credentials::count_of_types(&mut *tx, tenant_id, user_id, &[channel.kind()]).await?;
    tx.commit().await?;
    Ok(n > 0)
}

/// Send `code` over the channel in the user's locale.
async fn deliver(
    state: &AppState,
    tenant: &Tenant,
    flow: &LoginFlow,
    user: &User,
    channel: Channel,
    destination: &str,
    code: &str,
) -> AppResult<()> {
    let locale = locale::negotiate(
        &flow.request.ui_locales,
        user.locale.as_deref(),
        &tenant.settings.locale,
    );
    messaging::send(state, tenant, Outgoing {
        channel: channel.message_channel(),
        event: "otp",
        recipient: destination,
        locale: Some(&locale),
        vars: serde_json::json!({"user": {"username": user.username}, "code": code, "expires_minutes": OTP_TTL_SECS / 60}),
    })
    .await?;
    Ok(())
}

/// Store and send a code for the flow unless one went out moments ago. The
/// cooldown is claimed atomically, so concurrent requests (a double-fired
/// effect) send once and count once.
async fn issue(
    state: &AppState,
    tenant: &Tenant,
    flow: &LoginFlow,
    user: &User,
    channel: Channel,
    purpose: &str,
    destination: &str,
) -> AppResult<Sent> {
    let mut conn = state.redis.get().await?;
    let claimed: Option<String> = redis::cmd("SET")
        .arg(keys::otp_factor_cooldown(
            tenant.id,
            flow.id,
            channel.as_str(),
            purpose,
        ))
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(RESEND_COOLDOWN_SECS)
        .query_async(&mut *conn)
        .await?;
    if claimed.is_some() {
        let key = code_key(tenant.id, flow.id, channel, purpose);
        passwordless::check_send_limit(state, tenant.id, &format!("mfa:{}", user.id)).await?;
        let code = passwordless::store_code(state, &key, user.id).await?;
        deliver(state, tenant, flow, user, channel, destination, &code).await?;
    }
    Ok(Sent {
        sent: true,
        destination: channel.mask(destination),
    })
}

/// Start enrolling the channel: a code goes to the account's email, or to
/// `phone` (E.164) when given, else the account's phone. The destination is
/// held for the flow until [`confirm_enrolment`] proves it.
pub async fn begin_enrolment(
    state: &AppState,
    tenant: &Tenant,
    flow: &LoginFlow,
    user: &User,
    channel: Channel,
    phone: Option<&str>,
) -> AppResult<Sent> {
    if !channel.offered(tenant) {
        return Err(AppError::BadRequest(format!(
            "{}s are disabled for this tenant",
            channel.name()
        )));
    }
    if enrolled(state, tenant.id, user.id, channel).await? {
        return Err(AppError::BadRequest(format!(
            "an {} factor is already enrolled",
            channel.name()
        )));
    }
    let destination = match channel {
        Channel::Email => user.email.clone().ok_or_else(|| {
            AppError::Validation(vec![FieldError {
                field: "email".into(),
                message: "the account has no email address".into(),
            }])
        })?,
        Channel::Sms => match phone.map(str::trim).filter(|p| !p.is_empty()) {
            Some(p) => users::normalize_phone(p)?,
            None => user.phone.clone().ok_or_else(|| {
                AppError::Validation(vec![FieldError {
                    field: "phone".into(),
                    message: "a phone number is required".into(),
                }])
            })?,
        },
    };
    let pending_key = keys::otp_factor_enrolment(tenant.id, flow.id, channel.as_str());
    let mut conn = state.redis.get().await?;
    // A code sent to one destination must never prove another: switching
    // numbers mid-enrolment discards the pending code.
    let previous: Option<String> = conn.get(&pending_key).await?;
    if let Some(prev) = previous.and_then(|r| serde_json::from_str::<PendingEnrolment>(&r).ok())
        && prev.destination != destination
    {
        let _: () = conn
            .del(&[
                code_key(tenant.id, flow.id, channel, "enrol"),
                keys::otp_factor_cooldown(tenant.id, flow.id, channel.as_str(), "enrol"),
            ])
            .await?;
    }
    let _: () = conn
        .set_ex(
            &pending_key,
            serde_json::to_string(&PendingEnrolment {
                destination: destination.clone(),
            })?,
            ENROLMENT_TTL_SECS,
        )
        .await?;
    issue(state, tenant, flow, user, channel, "enrol", &destination).await
}

/// Prove the pending enrolment. `Ok(false)` is a wrong code (the enrolment
/// stays pending); success stores the factor and marks the destination
/// verified on the account (an SMS enrolment with a new number saves it).
pub async fn confirm_enrolment(
    state: &AppState,
    tenant: &Tenant,
    flow: &LoginFlow,
    user: &User,
    channel: Channel,
    code: &str,
) -> AppResult<bool> {
    let pending_key = keys::otp_factor_enrolment(tenant.id, flow.id, channel.as_str());
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = conn.get(&pending_key).await?;
    let Some(raw) = raw else {
        return Err(AppError::BadRequest(format!(
            "no {} enrolment is pending",
            channel.name()
        )));
    };
    let pending: PendingEnrolment = serde_json::from_str(&raw)?;
    let key = code_key(tenant.id, flow.id, channel, "enrol");
    match passwordless::check_code(state, &key, code).await? {
        Some(uid) if uid == user.id => {}
        _ => return Ok(false),
    }
    let destination = pending.destination;
    let id = Uuid::now_v7();
    let enc = encrypt(
        state,
        tenant.id,
        id,
        &FactorData {
            destination: destination.clone(),
        },
    )
    .await?;
    let label = channel.mask(&destination);
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    repos::credentials::insert(
        &mut *tx,
        tenant.id,
        repos::credentials::NewCredential {
            id,
            user_id: user.id,
            kind: channel.kind(),
            label: Some(&label),
            data_enc: &enc.to_bytes(),
            key_version: enc.key_version as i32,
            external_id: None,
        },
    )
    .await?;
    tx.commit().await?;
    let _: () = conn.del(&pending_key).await?;
    // The code proved control of the destination.
    let patch = match channel {
        Channel::Email if user.email.as_deref() == Some(&destination) && !user.email_verified => {
            Some(UserUpdate {
                email_verified: Some(true),
                ..Default::default()
            })
        }
        Channel::Sms if user.phone.as_deref() != Some(&destination) || !user.phone_verified => {
            Some(UserUpdate {
                phone: Some(Some(destination)),
                phone_verified: Some(true),
                ..Default::default()
            })
        }
        _ => None,
    };
    if let Some(patch) = patch {
        users::update(
            state,
            tenant.id,
            Actor::User { id: user.id },
            user.id,
            patch,
        )
        .await?;
    }
    let change = match channel {
        Channel::Email => "email code factor enrolled",
        Channel::Sms => "SMS code factor enrolled",
    };
    state.events.publish(Event::new(
        Some(tenant.id),
        Actor::User { id: user.id },
        EventKind::MfaChanged {
            user_id: user.id,
            change: change.into(),
        },
    ));
    let notice = match channel {
        Channel::Email => "Codes by email were added as a second step",
        Channel::Sms => "Codes by text message were added as a second step",
    };
    notifications::mfa_changed(state, tenant.id, user.id, notice).await;
    Ok(true)
}

/// Send a sign-in code to the enrolled channel.
pub async fn send_code(
    state: &AppState,
    tenant: &Tenant,
    flow: &LoginFlow,
    user: &User,
    channel: Channel,
) -> AppResult<Sent> {
    if !enrolled(state, tenant.id, user.id, channel).await? {
        return Err(AppError::BadRequest(format!(
            "no {} factor is enrolled",
            channel.name()
        )));
    }
    let Some(destination) = destination_of(user, channel) else {
        return Err(AppError::BadRequest(format!(
            "the account has no verified {} for its {} factor",
            match channel {
                Channel::Email => "email address",
                Channel::Sms => "phone number",
            },
            channel.name()
        )));
    };
    issue(state, tenant, flow, user, channel, "verify", destination).await
}

/// Check a sign-in code sent by [`send_code`]; `false` when wrong or spent.
pub async fn verify(
    state: &AppState,
    tenant: &Tenant,
    flow: &LoginFlow,
    user: &User,
    channel: Channel,
    code: &str,
) -> AppResult<bool> {
    let key = code_key(tenant.id, flow.id, channel, "verify");
    match passwordless::check_code(state, &key, code).await? {
        Some(uid) if uid == user.id => {}
        _ => return Ok(false),
    }
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    let rows =
        repos::credentials::list_secrets_of_type(&mut *tx, tenant.id, user.id, channel.kind())
            .await?;
    for row in rows {
        repos::credentials::touch_last_used(&mut *tx, tenant.id, row.id).await?;
    }
    tx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_keep_only_what_identifies_the_channel() {
        assert_eq!(mask_email("alice@example.com"), "a•••@example.com");
        assert_eq!(mask_email("nonsense"), "•••");
        assert_eq!(mask_phone("+15551234567"), "•••••••••67");
        assert_eq!(mask_phone("+1"), "•••1");
    }
}
