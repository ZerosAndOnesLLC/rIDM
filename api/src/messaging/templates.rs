//! Message templates: built-in English defaults, per-tenant overrides per
//! locale, Handlebars rendering. Lookup order: exact locale → language →
//! tenant default → built-in.

use std::collections::BTreeMap;

use handlebars::Handlebars;
use serde_json::Value;
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::MessageChannel;
use crate::repos;
use crate::state::AppState;

/// A renderable template.
#[derive(Debug, Clone, PartialEq)]
pub struct Template {
    pub subject: Option<String>,
    pub body_text: String,
    pub body_html: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Rendered {
    pub subject: Option<String>,
    pub body_text: String,
    pub body_html: Option<String>,
}

/// Events rIDM sends messages for.
pub const EVENTS: [&str; 9] = [
    "verify_email",
    "password_reset",
    "magic_link",
    "otp",
    "invitation",
    "new_device",
    "password_changed",
    "mfa_changed",
    "email_changed",
];

fn builtin(channel: MessageChannel, event: &str) -> Option<Template> {
    let t = |subject: &str, text: &str, html: &str| Template {
        subject: Some(subject.into()),
        body_text: text.into(),
        body_html: Some(html.into()),
    };
    let sms = |text: &str| Template {
        subject: None,
        body_text: text.into(),
        body_html: None,
    };
    Some(match (channel, event) {
        (MessageChannel::Email, "verify_email") => t(
            "Verify your email for {{tenant.display_name}}",
            "Hi {{user.username}},\n\nConfirm your email address by opening this link:\n{{link}}\n\nThe link expires in {{expires_minutes}} minutes. If you did not create an account, ignore this message.",
            "<p>Hi {{user.username}},</p><p>Confirm your email address:</p><p><a href=\"{{link}}\">Verify email</a></p><p>The link expires in {{expires_minutes}} minutes. If you did not create an account, ignore this message.</p>",
        ),
        (MessageChannel::Email, "password_reset") => t(
            "Reset your password for {{tenant.display_name}}",
            "Hi {{user.username}},\n\nReset your password using this link:\n{{link}}\n\nThe link expires in {{expires_minutes}} minutes. If you did not request a reset, ignore this message.",
            "<p>Hi {{user.username}},</p><p><a href=\"{{link}}\">Reset your password</a></p><p>The link expires in {{expires_minutes}} minutes. If you did not request a reset, ignore this message.</p>",
        ),
        (MessageChannel::Email, "magic_link") => t(
            "Sign in to {{tenant.display_name}}",
            "Hi {{user.username}},\n\nSign in with this link:\n{{link}}\n\nIt expires in {{expires_minutes}} minutes and works once.",
            "<p>Hi {{user.username}},</p><p><a href=\"{{link}}\">Sign in</a></p><p>The link expires in {{expires_minutes}} minutes and works once.</p>",
        ),
        (MessageChannel::Email, "otp") => t(
            "Your {{tenant.display_name}} code: {{code}}",
            "Your one-time code is {{code}}. It expires in {{expires_minutes}} minutes.",
            "<p>Your one-time code is <strong>{{code}}</strong>. It expires in {{expires_minutes}} minutes.</p>",
        ),
        (MessageChannel::Email, "invitation") => t(
            "You are invited to {{tenant.display_name}}",
            "{{inviter}} invited you to {{tenant.display_name}}.\n\nAccept the invitation:\n{{link}}\n\nThe invitation expires in {{expires_days}} days.",
            "<p>{{inviter}} invited you to {{tenant.display_name}}.</p><p><a href=\"{{link}}\">Accept invitation</a></p><p>The invitation expires in {{expires_days}} days.</p>",
        ),
        (MessageChannel::Email, "new_device") => t(
            "New sign-in to {{tenant.display_name}}",
            "Hi {{user.username}},\n\nA new device signed in to your account.\nWhen: {{when}}\nDevice: {{user_agent}}\nIP: {{ip}}\n\nIf this was not you, change your password now.",
            "<p>Hi {{user.username}},</p><p>A new device signed in to your account.</p><ul><li>When: {{when}}</li><li>Device: {{user_agent}}</li><li>IP: {{ip}}</li></ul><p>If this was not you, change your password now.</p>",
        ),
        (MessageChannel::Email, "password_changed") => t(
            "Your {{tenant.display_name}} password was changed",
            "Hi {{user.username}},\n\nYour password was changed on {{when}}. If this was not you, contact support immediately.",
            "<p>Hi {{user.username}},</p><p>Your password was changed on {{when}}. If this was not you, contact support immediately.</p>",
        ),
        (MessageChannel::Email, "mfa_changed") => t(
            "Your {{tenant.display_name}} sign-in security changed",
            "Hi {{user.username}},\n\nYour multi-factor authentication settings changed on {{when}}: {{change}}. If this was not you, contact support immediately.",
            "<p>Hi {{user.username}},</p><p>Your multi-factor authentication settings changed on {{when}}: {{change}}. If this was not you, contact support immediately.</p>",
        ),
        (MessageChannel::Email, "email_changed") => t(
            "Your {{tenant.display_name}} email address changed",
            "Hi {{user.username}},\n\nThe email address on your account changed to {{new_email}} on {{when}}. If this was not you, contact support immediately.",
            "<p>Hi {{user.username}},</p><p>The email address on your account changed to {{new_email}} on {{when}}. If this was not you, contact support immediately.</p>",
        ),
        (MessageChannel::Sms, "otp") => {
            sms("{{tenant.display_name}} code: {{code}} (expires in {{expires_minutes}} min)")
        }
        (MessageChannel::Sms, "magic_link") => sms("Sign in to {{tenant.display_name}}: {{link}}"),
        (MessageChannel::Sms, "new_device") => sms(
            "{{tenant.display_name}}: new sign-in from {{user_agent}} ({{ip}}). Not you? Change your password.",
        ),
        _ => return None,
    })
}

/// Locale candidates in lookup order: `de-CH` → `de` (then tenant default, then built-in).
fn locale_chain(locale: &str, tenant_default: &str) -> Vec<String> {
    let mut chain = vec![];
    let l = locale.trim().to_lowercase().replace('_', "-");
    if !l.is_empty() {
        chain.push(l.clone());
        if let Some((lang, _)) = l.split_once('-') {
            chain.push(lang.to_string());
        }
    }
    let d = tenant_default.trim().to_lowercase();
    if !d.is_empty() && !chain.contains(&d) {
        chain.push(d);
    }
    if !chain.iter().any(|c| c == "en") {
        chain.push("en".into());
    }
    chain
}

/// Resolve the template for an event, honouring tenant overrides.
pub async fn resolve(
    state: &AppState,
    tenant_id: Uuid,
    tenant_default_locale: &str,
    channel: MessageChannel,
    event: &str,
    locale: &str,
) -> AppResult<Template> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    for candidate in locale_chain(locale, tenant_default_locale) {
        if let Some(t) =
            repos::messages::find_template(&mut *tx, tenant_id, channel, event, &candidate).await?
        {
            tx.commit().await?;
            return Ok(Template {
                subject: t.subject,
                body_text: t.body_text,
                body_html: t.body_html,
            });
        }
    }
    tx.commit().await?;
    builtin(channel, event).ok_or_else(|| {
        AppError::BadRequest(format!("no template for {} `{event}`", channel.as_str()))
    })
}

/// Render with Handlebars (HTML-escaping applies to the HTML body only).
pub fn render(template: &Template, vars: &Value) -> AppResult<Rendered> {
    let mut hb = Handlebars::new();
    hb.set_strict_mode(false);
    let render_text = |src: &str| -> AppResult<String> {
        let mut h = Handlebars::new();
        h.register_escape_fn(handlebars::no_escape);
        h.render_template(src, vars)
            .map_err(|e| AppError::BadRequest(format!("template error: {e}")))
    };
    let subject = template.subject.as_deref().map(render_text).transpose()?;
    let body_text = render_text(&template.body_text)?;
    let body_html = template
        .body_html
        .as_deref()
        .map(|src| {
            hb.render_template(src, vars)
                .map_err(|e| AppError::BadRequest(format!("template error: {e}")))
        })
        .transpose()?;
    Ok(Rendered {
        subject,
        body_text,
        body_html,
    })
}

/// Validate a template by rendering it with placeholder data.
pub fn validate(template: &Template) -> AppResult<()> {
    let sample: BTreeMap<&str, Value> = [
        (
            "tenant",
            serde_json::json!({"display_name": "Example", "slug": "example"}),
        ),
        (
            "user",
            serde_json::json!({"username": "sample", "email": "sample@example.com"}),
        ),
        ("link", Value::String("https://example.com/x".into())),
        ("code", Value::String("123456".into())),
        ("expires_minutes", Value::from(15)),
        ("expires_days", Value::from(7)),
    ]
    .into_iter()
    .collect();
    render(template, &serde_json::to_value(sample)?).map(|_| ())
}

pub fn builtin_template(channel: MessageChannel, event: &str) -> Option<Template> {
    builtin(channel, event)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_chain_order() {
        assert_eq!(locale_chain("de-CH", "fr"), vec!["de-ch", "de", "fr", "en"]);
        assert_eq!(locale_chain("", "en"), vec!["en"]);
        assert_eq!(locale_chain("en", "en"), vec!["en"]);
        assert_eq!(locale_chain("pt_BR", "pt"), vec!["pt-br", "pt", "en"]);
    }

    #[test]
    fn builtins_render_and_html_is_escaped() {
        for e in EVENTS {
            let t = builtin(MessageChannel::Email, e).unwrap_or_else(|| panic!("{e}"));
            validate(&t).unwrap();
        }
        let t = builtin(MessageChannel::Email, "otp").unwrap();
        let r = render(&t, &serde_json::json!({"tenant": {"display_name": "A<B"}, "code": "<b>1</b>", "expires_minutes": 5})).unwrap();
        assert_eq!(
            r.subject.as_deref(),
            Some("Your A<B code: <b>1</b>"),
            "text/subject is not HTML-escaped"
        );
        assert!(
            r.body_html.unwrap().contains("&lt;b&gt;1&lt;/b&gt;"),
            "html body is escaped"
        );
        assert!(builtin(MessageChannel::Sms, "invitation").is_none());
    }
}
