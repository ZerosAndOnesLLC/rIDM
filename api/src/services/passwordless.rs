//! Passwordless first factors: magic links (email), email one-time codes and
//! SMS one-time codes. Codes and tokens are stored hashed in Redis, bound to
//! the login flow, single-use, expiring, and attempt-limited. Sends are
//! rate-limited per identifier and never reveal whether an account exists.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use redis::AsyncCommands as _;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;

use crate::cache::keys;
use crate::error::{AppError, AppResult, FieldError};
use crate::messaging::{self, Outgoing};
use crate::models::{MessageChannel, Tenant, User, UserStatus};
use crate::services::login_flows::LoginFlow;
use crate::services::users;
use crate::state::AppState;

pub const OTP_TTL_SECS: u64 = 10 * 60;
pub const MAGIC_LINK_TTL_SECS: u64 = 15 * 60;
pub const OTP_MAX_ATTEMPTS: u32 = 5;
/// Sends per identifier within the window.
pub const SEND_LIMIT: i64 = 3;
pub const SEND_WINDOW_SECS: u64 = 10 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    MagicLink,
    EmailOtp,
    SmsOtp,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MagicLink => "magic_link",
            Self::EmailOtp => "email_otp",
            Self::SmsOtp => "sms_otp",
        }
    }

    fn channel(self) -> &'static str {
        match self {
            Self::MagicLink | Self::EmailOtp => "email",
            Self::SmsOtp => "sms",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct OtpRecord {
    user_id: Uuid,
    code_hash: String,
    attempts: u32,
    expires_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct MagicRecord {
    flow_id: Uuid,
    user_id: Uuid,
    expires_at: i64,
}

fn hash(s: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(s.as_bytes()))
}

fn six_digits() -> String {
    let mut b = [0u8; 4];
    rand::fill(&mut b);
    format!("{:06}", u32::from_le_bytes(b) % 1_000_000)
}

fn enabled(tenant: &Tenant, method: Method) -> bool {
    let a = &tenant.settings.auth;
    match method {
        Method::MagicLink => a.magic_link,
        Method::EmailOtp => a.email_otp,
        Method::SmsOtp => a.sms_otp,
    }
}

pub async fn check_send_limit(
    state: &AppState,
    tenant_id: Uuid,
    identifier: &str,
) -> AppResult<()> {
    let key = keys::passwordless_sends(tenant_id, identifier);
    let mut conn = state.redis.get().await?;
    let n: i64 = conn.incr(&key, 1).await?;
    if n == 1 {
        let _: () = conn.expire(&key, SEND_WINDOW_SECS as i64).await?;
    }
    if n > SEND_LIMIT {
        return Err(AppError::RateLimited {
            retry_after_secs: SEND_WINDOW_SECS,
        });
    }
    Ok(())
}

/// Look up the user for a passwordless send. `None` is indistinguishable
/// from success to the caller (the API always answers "sent if it exists").
async fn eligible_user(
    state: &AppState,
    tenant_id: Uuid,
    identifier: &str,
    method: Method,
) -> AppResult<Option<User>> {
    let Some(user) = users::find_by_identifier(state, tenant_id, identifier).await? else {
        return Ok(None);
    };
    if user.status != UserStatus::Active && user.status != UserStatus::Pending {
        return Ok(None);
    }
    let ok = match method {
        Method::MagicLink | Method::EmailOtp => user.email.is_some(),
        Method::SmsOtp => user.phone.is_some() && user.phone_verified,
    };
    Ok(ok.then_some(user))
}

/// Start a passwordless attempt: generate, store, send. Always `Ok(())` for
/// unknown identifiers (no enumeration), errors only for policy/rate limits.
pub async fn send(
    state: &AppState,
    tenant: &Tenant,
    flow: &LoginFlow,
    method: Method,
    identifier: &str,
) -> AppResult<()> {
    if !enabled(tenant, method) {
        return Err(AppError::BadRequest(format!(
            "{} is disabled for this tenant",
            method.as_str()
        )));
    }
    let identifier = identifier.trim().to_lowercase();
    if identifier.is_empty() {
        return Err(AppError::Validation(vec![FieldError {
            field: "identifier".into(),
            message: "identifier is required".into(),
        }]));
    }
    // Throttle per presented identifier (enumeration attempts) and per
    // resolved user (a real account cannot be spammed via its aliases).
    check_send_limit(state, tenant.id, &identifier).await?;
    let Some(user) = eligible_user(state, tenant.id, &identifier, method).await? else {
        return Ok(());
    };
    check_send_limit(state, tenant.id, &format!("user:{}", user.id)).await?;
    let mut conn = state.redis.get().await?;
    let locale = Some(crate::services::locale::negotiate(
        &flow.request.ui_locales,
        user.locale.as_deref(),
        &tenant.settings.locale,
    ));
    match method {
        Method::MagicLink => {
            let mut bytes = [0u8; 32];
            rand::fill(&mut bytes);
            let token = URL_SAFE_NO_PAD.encode(bytes);
            let rec = MagicRecord {
                flow_id: flow.id,
                user_id: user.id,
                expires_at: Utc::now().timestamp() + MAGIC_LINK_TTL_SECS as i64,
            };
            let _: () = conn
                .set_ex(
                    keys::magic_link(tenant.id, &hash(&token)),
                    serde_json::to_string(&rec)?,
                    MAGIC_LINK_TTL_SECS,
                )
                .await?;
            let link = state.config.ui_page(
                "login",
                &[
                    ("tenant", &tenant.slug),
                    ("flow", &flow.id.to_string()),
                    ("magic", &token),
                ],
            );
            messaging::send(state, tenant, Outgoing {
                channel: MessageChannel::Email,
                event: "magic_link",
                recipient: user.email.as_deref().unwrap_or_default(),
                locale: locale.as_deref(),
                vars: serde_json::json!({"user": {"username": user.username}, "link": link, "expires_minutes": MAGIC_LINK_TTL_SECS / 60}),
            })
            .await?;
        }
        Method::EmailOtp | Method::SmsOtp => {
            let code = six_digits();
            let rec = OtpRecord {
                user_id: user.id,
                code_hash: hash(&code),
                attempts: 0,
                expires_at: Utc::now().timestamp() + OTP_TTL_SECS as i64,
            };
            let _: () = conn
                .set_ex(
                    keys::flow_otp(tenant.id, flow.id, method.channel()),
                    serde_json::to_string(&rec)?,
                    OTP_TTL_SECS,
                )
                .await?;
            let (channel, recipient) = match method {
                Method::EmailOtp => (
                    MessageChannel::Email,
                    user.email.clone().unwrap_or_default(),
                ),
                _ => (MessageChannel::Sms, user.phone.clone().unwrap_or_default()),
            };
            messaging::send(state, tenant, Outgoing {
                channel,
                event: "otp",
                recipient: &recipient,
                locale: locale.as_deref(),
                vars: serde_json::json!({"user": {"username": user.username}, "code": code, "expires_minutes": OTP_TTL_SECS / 60}),
            })
            .await?;
        }
    }
    state.events.publish(Event::new(
        Some(tenant.id),
        Actor::System,
        EventKind::PasswordlessSent {
            user_id: user.id,
            method: method.as_str().into(),
        },
    ));
    Ok(())
}

/// Result of a successful verification: which user authenticated.
pub struct Verified {
    pub user_id: Uuid,
    pub method: Method,
}

/// Check an OTP for the flow; consumes it on success and after the attempt limit.
pub async fn verify_otp(
    state: &AppState,
    tenant: &Tenant,
    flow: &LoginFlow,
    method: Method,
    code: &str,
) -> AppResult<Option<Verified>> {
    if !matches!(method, Method::EmailOtp | Method::SmsOtp) {
        return Err(AppError::BadRequest("not an otp method".into()));
    }
    let key = keys::flow_otp(tenant.id, flow.id, method.channel());
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = conn.get(&key).await?;
    let Some(raw) = raw else { return Ok(None) };
    let mut rec: OtpRecord = serde_json::from_str(&raw)?;
    if rec.expires_at <= Utc::now().timestamp() {
        let _: () = conn.del(&key).await?;
        return Ok(None);
    }
    let code = code.trim();
    let ok = code.len() == 6 && bool::from(hash(code).as_bytes().ct_eq(rec.code_hash.as_bytes()));
    if ok {
        let _: () = conn.del(&key).await?;
        return Ok(Some(Verified {
            user_id: rec.user_id,
            method,
        }));
    }
    rec.attempts += 1;
    if rec.attempts >= OTP_MAX_ATTEMPTS {
        let _: () = conn.del(&key).await?;
    } else {
        let ttl = (rec.expires_at - Utc::now().timestamp()).max(1) as u64;
        let _: () = conn.set_ex(&key, serde_json::to_string(&rec)?, ttl).await?;
    }
    Ok(None)
}

/// Redeem a magic-link token for the flow it was issued for (single use).
pub async fn verify_magic_link(
    state: &AppState,
    tenant: &Tenant,
    flow: &LoginFlow,
    token: &str,
) -> AppResult<Option<Verified>> {
    if token.is_empty() || token.len() > 128 {
        return Ok(None);
    }
    let key = keys::magic_link(tenant.id, &hash(token));
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = redis::cmd("GETDEL")
        .arg(&key)
        .query_async(&mut conn)
        .await?;
    let Some(raw) = raw else { return Ok(None) };
    let rec: MagicRecord = serde_json::from_str(&raw)?;
    if rec.flow_id != flow.id || rec.expires_at <= Utc::now().timestamp() {
        return Ok(None);
    }
    Ok(Some(Verified {
        user_id: rec.user_id,
        method: Method::MagicLink,
    }))
}

/// Proof of control over the email/phone: mark it verified if it was not.
pub async fn mark_contact_verified(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    method: Method,
) -> AppResult<()> {
    let patch = match method {
        Method::MagicLink | Method::EmailOtp => crate::models::UserUpdate {
            email_verified: Some(true),
            ..Default::default()
        },
        Method::SmsOtp => crate::models::UserUpdate {
            phone_verified: Some(true),
            ..Default::default()
        },
    };
    users::update(
        state,
        tenant_id,
        Actor::User { id: user_id },
        user_id,
        patch,
    )
    .await
    .map(|_| ())
}
