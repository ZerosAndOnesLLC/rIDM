//! Security notices to users: new device sign-in, password changed, MFA
//! changed, email changed. Sent through the tenant's messaging settings in
//! the user's locale; a failure to send is logged and never fails the action
//! that triggered it.

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::messaging::{self, Outgoing};
use crate::models::{MessageChannel, Tenant, User};
use crate::services::{tenants, users};
use crate::state::AppState;

fn when() -> String {
    Utc::now().format("%Y-%m-%d %H:%M UTC").to_string()
}

async fn load(state: &AppState, tenant_id: Uuid, user_id: Uuid) -> Option<(Tenant, User)> {
    let tenant = match tenants::get(state, tenant_id).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(%tenant_id, error = %e, "notification skipped: tenant lookup failed");
            return None;
        }
    };
    let user = match users::get(state, tenant_id, user_id).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(%tenant_id, %user_id, error = %e, "notification skipped: user lookup failed");
            return None;
        }
    };
    Some((tenant, user))
}

/// Email the user, or text them when they have no email but a phone and the
/// event has an SMS template. `to` overrides the address (e.g. the old email).
async fn deliver(
    state: &AppState,
    tenant: &Tenant,
    user: &User,
    event: &str,
    to: Option<&str>,
    vars: serde_json::Value,
) {
    let (channel, recipient) = match to.or(user.email.as_deref()) {
        Some(email) => (MessageChannel::Email, email.to_string()),
        None => match user.phone.as_deref().filter(|_| user.phone_verified) {
            Some(phone) if event == "new_device" => (MessageChannel::Sms, phone.to_string()),
            _ => {
                tracing::debug!(user = %user.id, event, "notification skipped: no contact address");
                return;
            }
        },
    };
    let vars = messaging::vars::notification(&user.username, &when(), vars);
    let outgoing = Outgoing {
        channel,
        event,
        recipient: &recipient,
        locale: user.locale.as_deref(),
        vars,
    };
    if let Err(e) = messaging::send(state, tenant, outgoing).await {
        tracing::warn!(user = %user.id, event, error = %e, "security notification not sent");
    }
}

pub async fn new_device_login(
    state: &AppState,
    tenant: &Tenant,
    user: &User,
    ip: Option<&str>,
    user_agent: Option<&str>,
) {
    if !tenant.settings.notifications.new_device {
        return;
    }
    deliver(
        state,
        tenant,
        user,
        "new_device",
        None,
        messaging::vars::new_device(
            ip.unwrap_or("unknown"),
            user_agent.unwrap_or("unknown device"),
        ),
    )
    .await;
}

pub async fn password_changed(state: &AppState, tenant_id: Uuid, user_id: Uuid) {
    let Some((tenant, user)) = load(state, tenant_id, user_id).await else {
        return;
    };
    if !tenant.settings.notifications.password_changed {
        return;
    }
    deliver(state, &tenant, &user, "password_changed", None, json!({})).await;
}

/// Sent to the previous address, which is the one that can still object.
pub async fn email_changed(
    state: &AppState,
    tenant: &Tenant,
    before: &User,
    new_email: Option<&str>,
) {
    if !tenant.settings.notifications.email_changed {
        return;
    }
    let Some(old) = before.email.as_deref() else {
        return;
    };
    deliver(
        state,
        tenant,
        before,
        "email_changed",
        Some(old),
        messaging::vars::email_changed(new_email.unwrap_or("(removed)")),
    )
    .await;
}

pub async fn mfa_changed(state: &AppState, tenant_id: Uuid, user_id: Uuid, change: &str) {
    let Some((tenant, user)) = load(state, tenant_id, user_id).await else {
        return;
    };
    if !tenant.settings.notifications.mfa_changed {
        return;
    }
    deliver(
        state,
        &tenant,
        &user,
        "mfa_changed",
        None,
        messaging::vars::mfa_changed(change),
    )
    .await;
}
