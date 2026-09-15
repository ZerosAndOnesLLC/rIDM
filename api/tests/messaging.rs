mod common;

use std::sync::Arc;

use async_trait::async_trait;
use common::TestApp;
use ridm_api::messaging::{self, Outgoing, SenderFactory};
use ridm_api::models::{
    EmailProviderConfig, MessageChannel, MessageStatus, ProviderKind, SmsProviderConfig,
    TenantSettings,
};
use ridm_api::services::provider_settings;
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::state::AppState;
use ridm_core::events::Actor;
use ridm_core::providers::{EmailSender, SmsSender};
use ridm_core::test_support::{MockEmailSender, MockSmsSender};
use serde_json::json;
use uuid::Uuid;

/// Factory handing every tenant the same mocks (so tests can inspect them).
struct MockFactory {
    email: Arc<MockEmailSender>,
    sms: Arc<MockSmsSender>,
    email_enabled: bool,
}

#[async_trait]
impl SenderFactory for MockFactory {
    async fn email(
        &self,
        _: &AppState,
        _: Uuid,
    ) -> ridm_api::error::AppResult<Option<Arc<dyn EmailSender>>> {
        Ok(self
            .email_enabled
            .then(|| self.email.clone() as Arc<dyn EmailSender>))
    }
    async fn sms(
        &self,
        _: &AppState,
        _: Uuid,
    ) -> ridm_api::error::AppResult<Option<Arc<dyn SmsSender>>> {
        Ok(Some(self.sms.clone()))
    }
}

fn with_mocks(
    app: &TestApp,
    email_enabled: bool,
) -> (AppState, Arc<MockEmailSender>, Arc<MockSmsSender>) {
    let email = Arc::new(MockEmailSender::new());
    let sms = Arc::new(MockSmsSender::new());
    let mut state = app.state.clone();
    state.senders = Arc::new(MockFactory {
        email: email.clone(),
        sms: sms.clone(),
        email_enabled,
    });
    (state, email, sms)
}

#[tokio::test]
async fn renders_with_locale_fallback_and_tenant_overrides_and_delivers() {
    let app = TestApp::spawn().await;
    let (state, email, sms) = with_mocks(&app, true);
    let tenant = tenants::get(&state, app.tenant.id).await.unwrap();

    let msg = messaging::send(
        &state,
        &tenant,
        Outgoing {
            channel: MessageChannel::Email,
            event: "otp",
            recipient: "alice@example.com",
            locale: Some("de-CH"),
            vars: json!({"user": {"username": "alice"}, "code": "123456", "expires_minutes": 5}),
        },
    )
    .await
    .unwrap();
    assert_eq!(msg.status, MessageStatus::Sent, "{msg:?}");
    assert_eq!(msg.attempts, 1);
    let sent = email.last().unwrap();
    assert_eq!(sent.to[0].email, "alice@example.com");
    assert!(sent.subject.contains("123456"));
    assert!(sent.text.contains("123456"));
    assert!(
        sent.html
            .as_deref()
            .unwrap()
            .contains("<strong>123456</strong>")
    );

    // A German override for the tenant is picked up for de-CH via the language fallback.
    let mut tx = ridm_api::db::tenant_tx(&state.db, tenant.id).await.unwrap();
    ridm_api::repos::messages::upsert_template(
        &mut *tx,
        tenant.id,
        MessageChannel::Email,
        "otp",
        "de",
        Some("Ihr Code: {{code}}"),
        "Ihr Code lautet {{code}}.",
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let msg = messaging::send(
        &state,
        &tenant,
        Outgoing {
            channel: MessageChannel::Email,
            event: "otp",
            recipient: "alice@example.com",
            locale: Some("de-CH"),
            vars: json!({"code": "654321", "expires_minutes": 5}),
        },
    )
    .await
    .unwrap();
    assert_eq!(msg.subject.as_deref(), Some("Ihr Code: 654321"));
    assert!(
        email.last().unwrap().html.is_none(),
        "override without html sends text only"
    );
    // Other locales still use the built-in.
    let msg = messaging::send(
        &state,
        &tenant,
        Outgoing {
            channel: MessageChannel::Email,
            event: "otp",
            recipient: "bob@example.com",
            locale: Some("fr"),
            vars: json!({"code": "1", "expires_minutes": 5}),
        },
    )
    .await
    .unwrap();
    assert!(msg.subject.unwrap().starts_with("Your "));

    // SMS through the mock; tenant name is injected.
    let msg = messaging::send(
        &state,
        &tenant,
        Outgoing {
            channel: MessageChannel::Sms,
            event: "otp",
            recipient: "+15550001111",
            locale: None,
            vars: json!({"code": "9999", "expires_minutes": 5}),
        },
    )
    .await
    .unwrap();
    assert_eq!(msg.status, MessageStatus::Sent);
    assert!(sms.last().unwrap().body.contains(&tenant.display_name));
    assert!(
        messaging::send(
            &state,
            &tenant,
            Outgoing {
                channel: MessageChannel::Sms,
                event: "invitation",
                recipient: "+1",
                locale: None,
                vars: json!({})
            }
        )
        .await
        .is_err(),
        "no sms template for invitation"
    );
}

#[tokio::test]
async fn retries_with_backoff_then_dead_letters_and_can_be_redelivered() {
    let app = TestApp::spawn().await;
    let (state, email, _) = with_mocks(&app, true);
    let tenant = tenants::get(&state, app.tenant.id).await.unwrap();
    email.fail_next(2);
    let msg = messaging::send(&state, &tenant, Outgoing {
        channel: MessageChannel::Email, event: "password_reset", recipient: "alice@example.com", locale: None,
        vars: json!({"user": {"username": "alice"}, "link": "https://x/reset", "expires_minutes": 15}),
    }).await.unwrap();
    assert_eq!(msg.status, MessageStatus::Queued);
    assert_eq!(msg.attempts, 1);
    assert!(msg.last_error.as_deref().unwrap().contains("mock failure"));
    assert!(
        msg.next_attempt_at > chrono::Utc::now() + chrono::Duration::seconds(30),
        "backoff scheduled"
    );
    // Not due yet: the job does nothing.
    assert_eq!(
        messaging::deliver_due(&state, tenant.id, 10).await.unwrap(),
        (0, 0)
    );
    // Make it due and retry: second failure, then success on the third attempt.
    let make_due = |id: Uuid| {
        let st = state.clone();
        let tid = tenant.id;
        async move {
            let mut tx = ridm_api::db::tenant_tx(&st.db, tid).await.unwrap();
            sqlx::query("UPDATE outbound_messages SET next_attempt_at = now() WHERE id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
    };
    make_due(msg.id).await;
    assert_eq!(
        messaging::deliver_due(&state, tenant.id, 10).await.unwrap(),
        (0, 1)
    );
    make_due(msg.id).await;
    assert_eq!(
        messaging::deliver_due(&state, tenant.id, 10).await.unwrap(),
        (1, 0)
    );
    let recent = messaging::recent(&state, tenant.id, Some(MessageStatus::Sent), 10)
        .await
        .unwrap();
    assert!(recent.iter().any(|m| m.id == msg.id && m.attempts == 3));

    // Exhausting the budget dead-letters; redeliver resets it.
    email.fail_next(100);
    let msg = messaging::send(
        &state,
        &tenant,
        Outgoing {
            channel: MessageChannel::Email,
            event: "otp",
            recipient: "a@b.c",
            locale: None,
            vars: json!({"code": "1", "expires_minutes": 1}),
        },
    )
    .await
    .unwrap();
    for _ in 0..10 {
        make_due(msg.id).await;
        messaging::deliver_due(&state, tenant.id, 10).await.unwrap();
    }
    let dead = messaging::recent(&state, tenant.id, Some(MessageStatus::Dead), 10)
        .await
        .unwrap();
    assert!(dead.iter().any(|m| m.id == msg.id), "{dead:?}");
    email.fail_next(0);
    messaging::redeliver(&state, tenant.id, msg.id)
        .await
        .unwrap();
    assert_eq!(
        messaging::deliver_due(&state, tenant.id, 10).await.unwrap(),
        (1, 0)
    );

    // No sender configured at all → queued with a configuration error, never sent.
    let (no_email, _, _) = with_mocks(&app, false);
    let msg = messaging::send(
        &no_email,
        &tenant,
        Outgoing {
            channel: MessageChannel::Email,
            event: "otp",
            recipient: "a@b.c",
            locale: None,
            vars: json!({"code": "1", "expires_minutes": 1}),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        msg.status,
        MessageStatus::Dead,
        "configuration errors are not retried: {msg:?}"
    );
}

#[tokio::test]
async fn tenant_provider_settings_select_real_senders() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    tenants::update(
        &app.state,
        Actor::System,
        tid,
        TenantUpdate {
            settings: Some(TenantSettings::default()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // Nothing configured and no SMTP defaults: no email sender, no sms sender.
    assert!(
        app.state
            .senders
            .email(&app.state, tid)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        app.state
            .senders
            .sms(&app.state, tid)
            .await
            .unwrap()
            .is_none()
    );
    provider_settings::set(
        &app.state,
        tid,
        ProviderKind::Smtp,
        &EmailProviderConfig::Http {
            url: "https://mail.example/send".into(),
            auth_header: Some("Bearer x".into()),
            from: "no-reply@example.com".into(),
        },
    )
    .await
    .unwrap();
    provider_settings::set(
        &app.state,
        tid,
        ProviderKind::Sms,
        &SmsProviderConfig {
            url: "https://sms.example/send".into(),
            auth_header: None,
            from: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        app.state
            .senders
            .email(&app.state, tid)
            .await
            .unwrap()
            .unwrap()
            .name(),
        "http"
    );
    assert_eq!(
        app.state
            .senders
            .sms(&app.state, tid)
            .await
            .unwrap()
            .unwrap()
            .name(),
        "http"
    );
    provider_settings::set(
        &app.state,
        tid,
        ProviderKind::Smtp,
        &EmailProviderConfig::Smtp(ridm_api::models::SmtpConfig {
            host: "localhost".into(),
            port: 1025,
            username: None,
            password: None,
            from: "rIDM <no-reply@example.com>".into(),
            security: "none".into(),
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        app.state
            .senders
            .email(&app.state, tid)
            .await
            .unwrap()
            .unwrap()
            .name(),
        "smtp"
    );
    // Settings are per tenant.
    let other = common::create_tenant(&app.state.db).await;
    assert!(
        app.state
            .senders
            .email(&app.state, other.id)
            .await
            .unwrap()
            .is_none()
    );
}
