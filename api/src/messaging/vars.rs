//! Template variables, per event: one definition shared by the real sends and
//! the console's preview ([`sample`]), so a template that previews cleanly
//! renders the same variables when it is sent.
//!
//! | Event | Variables |
//! |-------|-----------|
//! | `verify_email`, `password_reset`, `magic_link` | `user.username`, `link`, `expires_minutes` |
//! | `otp` | `user.username`, `code`, `expires_minutes` |
//! | `invitation` | `inviter`, `link`, `expires_days` |
//! | `new_device` | `user.username`, `when`, `user_agent`, `ip` |
//! | `password_changed` | `user.username`, `when` |
//! | `mfa_changed` | `user.username`, `when`, `change` |
//! | `email_changed` | `user.username`, `when`, `new_email` |
//! | `backchannel_request` | `user.username`, `when`, `client_name`, `binding_message`, `link`, `expires_minutes` |
//!
//! Every message also gets `tenant.display_name` and `tenant.slug` ([`tenant`],
//! added by [`crate::messaging::send`]).

use serde_json::{Value, json};

use crate::models::Tenant;

/// `tenant`, present in every message.
pub fn tenant(tenant: &Tenant) -> Value {
    json!({"display_name": tenant.display_name, "slug": tenant.slug})
}

/// `verify_email`, `password_reset` and `magic_link`: a link that expires.
pub fn link(username: &str, link: &str, expires_minutes: u64) -> Value {
    json!({"user": {"username": username}, "link": link, "expires_minutes": expires_minutes})
}

/// `otp`: a one-time code.
pub fn code(username: &str, code: &str, expires_minutes: u64) -> Value {
    json!({"user": {"username": username}, "code": code, "expires_minutes": expires_minutes})
}

/// `invitation`: who invited, the acceptance link and its lifetime.
pub fn invitation(inviter: &str, link: &str, expires_days: u32) -> Value {
    json!({"inviter": inviter, "link": link, "expires_days": expires_days})
}

/// The event-specific part of `new_device`.
pub fn new_device(ip: &str, user_agent: &str) -> Value {
    json!({"ip": ip, "user_agent": user_agent})
}

/// The event-specific part of `mfa_changed`.
pub fn mfa_changed(change: &str) -> Value {
    json!({"change": change})
}

/// The event-specific part of `email_changed`.
pub fn email_changed(new_email: &str) -> Value {
    json!({"new_email": new_email})
}

/// The event-specific part of `backchannel_request`: who asks, the text
/// their device shows (empty when none), and where to answer.
pub fn backchannel_request(
    client_name: &str,
    binding_message: Option<&str>,
    link: &str,
    expires_minutes: u64,
) -> Value {
    json!({
        "client_name": client_name,
        "binding_message": binding_message.unwrap_or_default(),
        "link": link,
        "expires_minutes": expires_minutes,
    })
}

/// A security notification (`new_device`, `password_changed`, `mfa_changed`,
/// `email_changed`): the event's own fields plus `user` and `when`.
pub fn notification(username: &str, when: &str, mut fields: Value) -> Value {
    if !fields.is_object() {
        fields = json!({});
    }
    fields["user"] = json!({"username": username});
    fields["when"] = json!(when);
    fields
}

/// The variables of `event` with sample values, `tenant` included: what the
/// console's preview renders a template with. `None` for an unknown event.
pub fn sample(event: &str, t: &Tenant) -> Option<Value> {
    const USER: &str = "sample";
    const WHEN: &str = "2026-01-31 09:30 UTC";
    let mut vars = match event {
        "verify_email" | "password_reset" | "magic_link" => {
            link(USER, "https://example.com/verify?token=sample", 15)
        }
        "otp" => code(USER, "123456", 10),
        "invitation" => invitation("admin", "https://example.com/invite?token=sample", 7),
        "new_device" => notification(USER, WHEN, new_device("203.0.113.7", "Sample Browser")),
        "password_changed" => notification(USER, WHEN, json!({})),
        "mfa_changed" => notification(USER, WHEN, mfa_changed("authenticator app added")),
        "email_changed" => notification(USER, WHEN, email_changed("new@example.com")),
        "backchannel_request" => notification(
            USER,
            WHEN,
            backchannel_request(
                "Sample Bank",
                Some("K7 R2"),
                "https://example.com/account/approvals/?request=sample",
                10,
            ),
        ),
        _ => return None,
    };
    vars["tenant"] = tenant(t);
    Some(vars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::{EVENTS, builtin_template};
    use crate::models::MessageChannel;

    #[test]
    fn every_event_has_samples() {
        let t = Tenant {
            id: uuid::Uuid::nil(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            status: crate::models::TenantStatus::Active,
            settings: sqlx::types::Json(Default::default()),
            pairwise_salt: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        for event in EVENTS {
            let vars = sample(event, &t).unwrap_or_else(|| panic!("{event}"));
            assert!(vars["tenant"]["slug"].is_string(), "{event}");
        }
        assert!(sample("nope", &t).is_none());

        // Every placeholder of every built-in template is a variable the
        // event really carries (strict mode fails on a missing one), so the
        // preview shows what a recipient would see.
        let mut strict = handlebars::Handlebars::new();
        strict.set_strict_mode(true);
        for event in EVENTS {
            let vars = sample(event, &t).unwrap();
            for channel in [MessageChannel::Email, MessageChannel::Sms] {
                let Some(tpl) = builtin_template(channel, event) else {
                    continue;
                };
                for src in [
                    tpl.subject.as_deref(),
                    Some(tpl.body_text.as_str()),
                    tpl.body_html.as_deref(),
                ]
                .into_iter()
                .flatten()
                {
                    strict
                        .render_template(src, &vars)
                        .unwrap_or_else(|e| panic!("{event} ({channel:?}): {e}"));
                }
            }
        }
    }
}
