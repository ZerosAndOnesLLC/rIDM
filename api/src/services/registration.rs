//! Self-registration and email verification.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use redis::AsyncCommands as _;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult, FieldError};
use crate::messaging::{self, Outgoing};
use crate::models::{MessageChannel, NewUser, Tenant, User, UserStatus, UserUpdate};
use crate::repos;
use crate::services::password::{self, SetPasswordOptions};
use crate::services::users;
use crate::state::AppState;

pub const VERIFICATION_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RegistrationInput {
    pub username: Option<String>,
    pub email: String,
    pub password: Option<String>,
    pub attributes: Option<Value>,
    pub terms_accepted: bool,
    pub locale: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VerificationRecord {
    user_id: Uuid,
    flow_id: Option<Uuid>,
}

fn hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

/// Policy checks that do not need the database.
pub fn check_policy(tenant: &Tenant, input: &RegistrationInput) -> AppResult<()> {
    let policy = &tenant.settings.registration;
    if !policy.enabled {
        return Err(AppError::Forbidden(
            "self-registration is disabled for this tenant".into(),
        ));
    }
    let email = input.email.trim().to_lowercase();
    if !policy.allowed_email_domains.is_empty() {
        let domain = email.rsplit('@').next().unwrap_or_default();
        if !policy
            .allowed_email_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(domain))
        {
            return Err(AppError::Validation(vec![FieldError {
                field: "email".into(),
                message: "email domain is not allowed to register".into(),
            }]));
        }
    }
    if policy.require_terms && !input.terms_accepted {
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
    Ok(())
}

/// Create the account. Returns the user and whether verification is pending.
pub async fn register(
    state: &AppState,
    tenant: &Tenant,
    input: RegistrationInput,
    flow_id: Option<Uuid>,
    requested_locales: &[String],
) -> AppResult<(User, bool)> {
    check_policy(tenant, &input)?;
    // A locale the form supplied wins when the tenant supports it; otherwise
    // the flow's `ui_locales`, then the tenant default.
    let mut preferred: Vec<String> = input.locale.iter().cloned().collect();
    preferred.extend_from_slice(requested_locales);
    let locale = crate::services::locale::negotiate(&preferred, None, &tenant.settings.locale);
    let email = users::normalize_email(&input.email)?;
    let username = match input
        .username
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
    {
        Some(u) => users::normalize_username(u)?,
        None => email.clone(),
    };
    let needs_verification = tenant.settings.registration.require_email_verification;
    let user = users::create(
        state,
        tenant.id,
        Actor::System,
        NewUser {
            username,
            email: Some(email.clone()),
            email_verified: false,
            status: Some(if needs_verification {
                UserStatus::Pending
            } else {
                UserStatus::Active
            }),
            attributes: input.attributes.clone(),
            locale: Some(locale),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| match e {
        AppError::Conflict(_) => {
            AppError::Conflict("an account with this email or username already exists".into())
        }
        other => other,
    })?;
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
                notify: false,
            },
        )
        .await
    {
        // Roll back the half-created account so the email can be retried.
        let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
        repos::users::hard_delete(&mut *tx, tenant.id, user.id).await?;
        tx.commit().await?;
        return Err(e);
    }
    if input.terms_accepted {
        let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
        repos::users::set_terms_accepted(&mut *tx, tenant.id, user.id).await?;
        tx.commit().await?;
    }
    if needs_verification {
        send_verification(state, tenant, &user, flow_id).await?;
    }
    state.events.publish(Event::new(
        Some(tenant.id),
        Actor::User { id: user.id },
        EventKind::UserRegistered {
            user_id: user.id,
            verified: !needs_verification,
        },
    ));
    let user = users::get(state, tenant.id, user.id).await?;
    Ok((user, needs_verification))
}

/// Issue a verification token and email the link (`/verify/?tenant&token[&flow]`).
pub async fn send_verification(
    state: &AppState,
    tenant: &Tenant,
    user: &User,
    flow_id: Option<Uuid>,
) -> AppResult<()> {
    let Some(email) = &user.email else {
        return Err(AppError::BadRequest("user has no email address".into()));
    };
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let rec = VerificationRecord {
        user_id: user.id,
        flow_id,
    };
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(
            keys::email_verification(tenant.id, &hash(&token)),
            serde_json::to_string(&rec)?,
            VERIFICATION_TTL_SECS,
        )
        .await?;
    let mut params = vec![("tenant", tenant.slug.clone()), ("token", token)];
    if let Some(f) = flow_id {
        params.push(("flow", f.to_string()));
    }
    let refs: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let link = state.config.ui_page("verify", &refs);
    messaging::send(state, tenant, Outgoing {
        channel: MessageChannel::Email,
        event: "verify_email",
        recipient: email,
        locale: user.locale.as_deref(),
        vars: serde_json::json!({"user": {"username": user.username}, "link": link, "expires_minutes": VERIFICATION_TTL_SECS / 60}),
    })
    .await?;
    Ok(())
}

/// Outcome of confirming a verification token.
pub struct Confirmed {
    pub user: User,
    pub flow_id: Option<Uuid>,
}

/// Redeem a verification token: activates the account and marks the email verified.
pub async fn confirm(state: &AppState, tenant: &Tenant, token: &str) -> AppResult<Confirmed> {
    if token.is_empty() || token.len() > 128 {
        return Err(AppError::NotFound("verification token"));
    }
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = redis::cmd("GETDEL")
        .arg(keys::email_verification(tenant.id, &hash(token)))
        .query_async(&mut conn)
        .await?;
    let rec: VerificationRecord = raw
        .and_then(|r| serde_json::from_str(&r).ok())
        .ok_or(AppError::NotFound("verification token"))?;
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    let user = repos::users::find_by_id(&mut *tx, tenant.id, rec.user_id)
        .await?
        .filter(|u| u.deleted_at.is_none())
        .ok_or(AppError::NotFound("user"))?;
    let patch = UserUpdate {
        email_verified: Some(true),
        status: Some(if user.status == UserStatus::Pending {
            UserStatus::Active
        } else {
            user.status
        }),
        ..Default::default()
    };
    let user = repos::users::update(&mut *tx, tenant.id, user.id, &patch)
        .await?
        .ok_or(AppError::NotFound("user"))?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tenant.id),
        Actor::User { id: user.id },
        EventKind::EmailVerified { user_id: user.id },
    ));
    Ok(Confirmed {
        user,
        flow_id: rec.flow_id,
    })
}
