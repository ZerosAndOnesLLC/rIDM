//! Administrators signing in as users (impersonation).
//!
//! An administrator holding `ridm:users:impersonate`, in a tenant whose
//! `settings.impersonation.enabled` is on, asks for a ticket naming a user and
//! a reason ([`request`]). The ticket is a one-time URL on the tenant's issuer,
//! good for [`TICKET_TTL_SECS`]; the browser that opens it gets an ordinary SSO
//! session as the user ([`redeem`]) that also names the administrator. From
//! there every client works as it would for the user, except that:
//!
//! * every token minted from the session carries `act` naming the
//!   administrator (RFC 8693 §4.1), and expires with the session;
//! * every event the session causes names the administrator
//!   ([`ridm_core::events::acting`]), and the audit log records it;
//! * the account API refuses credential changes, account deletion, linked
//!   identities and personal access tokens, and no consent can be granted;
//! * the session owes no second factor, password change or risk step-up —
//!   the administrator could not pass them, and the user's policy is about
//!   the user's sign-ins.
//!
//! Users holding any admin permission cannot be impersonated, so taking on
//! someone's identity can never widen what an administrator may do.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use redis::AsyncCommands as _;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _, acting};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::cache::keys;
use crate::error::{AppError, AppResult};
use crate::models::{ImpersonationPolicy, Tenant, UserStatus};
use crate::services::admin_access::{self, OrgScope};
use crate::services::sessions::{self, Impersonator, NewImpersonatedSession, SsoSession};
use crate::services::{tenants, tokens, users};
use crate::state::AppState;

/// The admin permission impersonation needs.
pub const PERMISSION: &str = "ridm:users:impersonate";
/// How long a ticket waits to be opened.
pub const TICKET_TTL_SECS: u64 = 60;
/// The longest reason an administrator may give.
pub const REASON_MAX_CHARS: usize = 500;

pub fn validate_policy(policy: &ImpersonationPolicy) -> AppResult<()> {
    if !(1..=ImpersonationPolicy::MAX_MINUTES).contains(&policy.max_minutes) {
        return Err(AppError::BadRequest(format!(
            "impersonation.max_minutes must be 1-{}",
            ImpersonationPolicy::MAX_MINUTES
        )));
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct Ticket {
    user_id: Uuid,
    impersonator: Impersonator,
    reason: String,
}

fn hash(ticket: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(ticket.as_bytes()))
}

/// Fail unless `impersonator` may sign in as `user_id` right now.
async fn check_target(
    state: &AppState,
    tenant: &Tenant,
    user_id: Uuid,
    impersonator: &Impersonator,
) -> AppResult<()> {
    if impersonator.user_id == user_id && impersonator.tenant_id == tenant.id {
        return Err(AppError::BadRequest(
            "you cannot impersonate yourself".into(),
        ));
    }
    let user = users::get(state, tenant.id, user_id).await?;
    if user.deleted_at.is_some() {
        return Err(AppError::NotFound("user"));
    }
    if !tenant.settings.impersonation.enabled {
        return Err(AppError::Forbidden(
            "impersonation is not enabled for this tenant".into(),
        ));
    }
    if user.status != UserStatus::Active {
        return Err(AppError::Conflict(
            "only active users can be impersonated".into(),
        ));
    }
    let held =
        admin_access::permissions_of_user(state, tenant.id, user_id, OrgScope::Anywhere).await?;
    if !held.is_empty() {
        return Err(AppError::Forbidden(
            "administrators cannot be impersonated".into(),
        ));
    }
    Ok(())
}

/// A ticket ready to open in a browser.
pub struct Issued {
    pub url: String,
    pub expires_at: DateTime<Utc>,
}

/// Check that `impersonator` may sign in as `user_id` and mint the ticket.
pub async fn request(
    state: &AppState,
    tenant: &Tenant,
    user_id: Uuid,
    impersonator: Impersonator,
    reason: &str,
    request_meta: (Option<String>, Option<String>),
) -> AppResult<Issued> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(AppError::BadRequest("a reason is required".into()));
    }
    if reason.chars().count() > REASON_MAX_CHARS {
        return Err(AppError::BadRequest(format!(
            "the reason is longer than {REASON_MAX_CHARS} characters"
        )));
    }
    check_target(state, tenant, user_id, &impersonator).await?;

    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let ticket = URL_SAFE_NO_PAD.encode(bytes);
    let admin_id = impersonator.user_id;
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(
            keys::impersonation_ticket(tenant.id, &hash(&ticket)),
            serde_json::to_string(&Ticket {
                user_id,
                impersonator,
                reason: reason.to_string(),
            })?,
            TICKET_TTL_SECS,
        )
        .await?;
    drop(conn);

    let (ip, user_agent) = request_meta;
    state.events.publish(
        Event::new(
            Some(tenant.id),
            Actor::Admin { id: admin_id },
            EventKind::ImpersonationRequested {
                user_id,
                reason: reason.to_string(),
            },
        )
        .with_request(ip, user_agent),
    );
    let mut url = url::Url::parse(&format!("{}/impersonate", tokens::issuer(state, tenant)))
        .map_err(|e| AppError::Internal(format!("issuer is not a URL: {e}")))?;
    url.query_pairs_mut().append_pair("ticket", &ticket);
    Ok(Issued {
        url: url.into(),
        expires_at: Utc::now() + chrono::Duration::seconds(TICKET_TTL_SECS as i64),
    })
}

/// Open the impersonated session a ticket stands for. `replaced` is the
/// browser's own live session in this tenant, if it had one: it is put back
/// when the impersonation ends.
pub async fn redeem(
    state: &AppState,
    tenant: &Tenant,
    ticket: &str,
    replaced: Option<&SsoSession>,
    ip: Option<String>,
    user_agent: Option<String>,
) -> AppResult<SsoSession> {
    if ticket.is_empty() || ticket.len() > 128 {
        return Err(AppError::NotFound("impersonation ticket"));
    }
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = redis::cmd("GETDEL")
        .arg(keys::impersonation_ticket(tenant.id, &hash(ticket)))
        .query_async(&mut conn)
        .await?;
    drop(conn);
    let t: Ticket = raw
        .and_then(|r| serde_json::from_str(&r).ok())
        .ok_or(AppError::NotFound("impersonation ticket"))?;
    // A minute has passed at most, but the policy, the user, their roles or
    // the administrator's may have changed in it.
    check_target(state, tenant, t.user_id, &t.impersonator).await?;
    let reaches = t.impersonator.tenant_id == tenant.id
        || t.impersonator.tenant_id == crate::models::MASTER_TENANT_ID;
    let held = admin_access::permissions_of_user(
        state,
        t.impersonator.tenant_id,
        t.impersonator.user_id,
        OrgScope::TenantWide,
    )
    .await?;
    if !reaches || !held.allows(PERMISSION) {
        return Err(AppError::Forbidden(format!(
            "missing permission `{PERMISSION}`"
        )));
    }

    let admin_id = t.impersonator.user_id;
    let admin_tenant = t.impersonator.tenant_id;
    acting::set(admin_id);
    let lifetime = chrono::Duration::minutes(i64::from(tenant.settings.impersonation.max_minutes));
    let session = sessions::create_impersonated(
        state,
        tenant,
        NewImpersonatedSession {
            user_id: t.user_id,
            impersonator: t.impersonator,
            reason: &t.reason,
            lifetime,
            ip: ip.clone(),
            user_agent: user_agent.clone(),
        },
    )
    .await?;
    if let Some(own) = replaced.filter(|s| s.impersonator.is_none()) {
        let ttl = sessions::remaining(&session).as_secs().max(1);
        let mut conn = state.redis.get().await?;
        let _: () = conn
            .set_ex(
                keys::impersonation_restore(tenant.id, session.id),
                own.id.to_string(),
                ttl,
            )
            .await?;
    }
    let admin = Actor::Admin { id: admin_id };
    state.events.publish(
        Event::new(
            Some(tenant.id),
            admin.clone(),
            EventKind::SessionCreated {
                session_id: session.id,
                user_id: t.user_id,
            },
        )
        .with_request(ip.clone(), user_agent.clone()),
    );
    state.events.publish(
        Event::new(
            Some(tenant.id),
            admin,
            EventKind::ImpersonationStarted {
                user_id: t.user_id,
                session_id: session.id,
                impersonator_id: admin_id,
                impersonator_tenant_id: admin_tenant,
                reason: t.reason,
            },
        )
        .with_request(ip, user_agent),
    );
    Ok(session)
}

/// End an impersonated session (its tokens and its relying parties with
/// it). Returns the browser's own session to put back, when it is still live.
pub async fn end(
    state: &AppState,
    tenant: &Tenant,
    session: &SsoSession,
) -> AppResult<Option<SsoSession>> {
    if session.impersonator.is_none() {
        return Err(AppError::BadRequest(
            "this session is not an impersonation".into(),
        ));
    }
    crate::services::logout::end_session(state, tenant, session.id).await?;
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = redis::cmd("GETDEL")
        .arg(keys::impersonation_restore(tenant.id, session.id))
        .query_async(&mut conn)
        .await?;
    drop(conn);
    let Some(own) = raw.and_then(|r| Uuid::parse_str(&r).ok()) else {
        return Ok(None);
    };
    sessions::get(state, tenant.id, own, &tenant.settings.session).await
}

/// Record the end of an impersonated session that was just revoked. The
/// administrator is the actor when they ended it from inside the session;
/// otherwise (another administrator, the user, a sign-out everywhere) the
/// system is.
pub fn announce_end(state: &AppState, session: &SsoSession) {
    let Some(imp) = &session.impersonator else {
        return;
    };
    let actor = if acting::current() == Some(imp.user_id) {
        Actor::Admin { id: imp.user_id }
    } else {
        Actor::System
    };
    state.events.publish(Event::new(
        Some(session.tenant_id),
        actor,
        EventKind::ImpersonationEnded {
            user_id: session.user_id,
            session_id: session.id,
            impersonator_id: imp.user_id,
        },
    ));
}

/// What tokens minted from an impersonated session carry: the `act` claim
/// naming the administrator, and the instant they must expire by.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Acting {
    pub act: Value,
    pub until: DateTime<Utc>,
}

/// [`Acting`] for `session`, `None` for an ordinary one.
pub async fn acting(state: &AppState, session: &SsoSession) -> AppResult<Option<Acting>> {
    let Some(imp) = &session.impersonator else {
        return Ok(None);
    };
    let admin_tenant = tenants::get_cached(state, imp.tenant_id)
        .await?
        .ok_or(AppError::NotFound("tenant"))?;
    Ok(Some(Acting {
        act: act_claim(imp, &tokens::issuer(state, &admin_tenant)),
        until: session.expires_at,
    }))
}

/// `act` for an administrator of the tenant at `issuer`: their subject there,
/// qualified by the issuer since it is often another tenant's (`master`).
pub fn act_claim(imp: &Impersonator, issuer: &str) -> Value {
    json!({ "sub": imp.user_id.to_string(), "iss": issuer })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_bounds_the_session_length() {
        let mut p = ImpersonationPolicy::default();
        assert!(validate_policy(&p).is_ok());
        p.max_minutes = 0;
        assert!(validate_policy(&p).is_err());
        p.max_minutes = ImpersonationPolicy::MAX_MINUTES;
        assert!(validate_policy(&p).is_ok());
        p.max_minutes += 1;
        assert!(validate_policy(&p).is_err());
    }

    #[test]
    fn act_names_the_administrator_and_their_issuer() {
        let imp = Impersonator {
            user_id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            username: "root".into(),
        };
        let act = act_claim(&imp, "https://id.example/t/master");
        assert_eq!(act["sub"], Uuid::nil().to_string());
        assert_eq!(act["iss"], "https://id.example/t/master");
        assert!(act.get("act").is_none());
    }
}
