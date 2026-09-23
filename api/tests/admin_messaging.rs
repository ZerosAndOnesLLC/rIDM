//! Phase 5.8: messaging admin — delivery settings with test sends, template
//! overrides with preview, and the delivery log.

mod common;

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use common::admin::{admin_token, call, get_json};
use common::{TestApp, create_tenant};
use reqwest::Method;
use ridm_api::messaging::{self, Outgoing};
use ridm_api::models::{MASTER_TENANT_ID, MessageChannel};
use ridm_api::services::admin_access::{
    ADMIN_ROLE, CLIENT_MANAGER_ROLE, OWNER_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE,
};
use ridm_api::services::tenants;
use ridm_api::state::AppState;
use serde_json::{Value, json};

/// Webhook receiver the test app serves itself: records every email and SMS
/// delivered over HTTP, with the authorization header seen.
#[derive(Default)]
struct Received {
    emails: Vec<(Option<String>, Value)>,
    sms: Vec<(Option<String>, Value)>,
}

type Inbox = Arc<Mutex<Received>>;

fn webhook_routes(inbox: Inbox) -> Router<AppState> {
    let for_email = inbox.clone();
    let for_sms = inbox;
    Router::new()
        .route(
            "/_test/email",
            post(
                move |headers: HeaderMap, axum::Json(body): axum::Json<Value>| {
                    let inbox = for_email.clone();
                    async move {
                        let auth = headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string);
                        inbox.lock().unwrap().emails.push((auth, body));
                        StatusCode::OK
                    }
                },
            ),
        )
        .route(
            "/_test/sms",
            post(
                move |headers: HeaderMap, axum::Json(body): axum::Json<Value>| {
                    let inbox = for_sms.clone();
                    async move {
                        let auth = headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string);
                        inbox.lock().unwrap().sms.push((auth, body));
                        StatusCode::OK
                    }
                },
            ),
        )
        .route(
            "/_test/broken",
            post(|_: State<AppState>| async { StatusCode::BAD_GATEWAY }),
        )
}

async fn fixture() -> (TestApp, Inbox) {
    let inbox: Inbox = Arc::default();
    let app = TestApp::spawn_with(webhook_routes(inbox.clone())).await;
    (app, inbox)
}

#[tokio::test]
async fn delivery_settings_round_trip_with_secrets_redacted_and_test_sends() {
    let (app, inbox) = fixture().await;
    let base = format!("/admin/tenants/{}/messaging", app.tenant.slug);
    let t = admin_token(&app, app.tenant.id, ADMIN_ROLE).await;

    // Nothing configured for the tenant: the server default (if any) or none.
    let (status, initial, _) = get_json(&app, &format!("{base}/email"), Some(&t)).await;
    assert_eq!(status, 200, "{initial}");
    assert_ne!(initial["source"], "tenant");
    let (status, sms, _) = get_json(&app, &format!("{base}/sms"), Some(&t)).await;
    assert_eq!(status, 200);
    assert_eq!(sms["configured"], false);

    // Validation.
    for body in [
        json!({"type": "smtp", "host": "", "port": 25, "from": "x@y.z"}),
        json!({"type": "smtp", "host": "mail.example", "port": 587, "from": "x@y.z", "security": "weird"}),
        json!({"type": "http", "url": "ftp://x", "from": "x@y.z"}),
        json!({"type": "http", "url": "http://example.com/hook", "from": "x@y.z"}),
        json!({"type": "carrier-pigeon"}),
    ] {
        let (status, err, _) = call(
            &app,
            Method::PUT,
            &format!("{base}/email"),
            Some(&t),
            Some(&body),
        )
        .await;
        assert_eq!(status, 400, "{body} -> {err}");
    }

    // SMTP settings: password stored, never returned, kept when omitted.
    let (status, saved, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/email"),
        Some(&t),
        Some(&json!({"type": "smtp", "host": "mail.example", "port": 587, "username": "u", "password": "p", "from": "rIDM <no-reply@example.com>"})),
    )
    .await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(saved["source"], "tenant");
    assert_eq!(saved["type"], "smtp");
    assert_eq!(saved["security"], "starttls");
    assert_eq!(saved["password_set"], true);
    assert!(saved.get("password").is_none());
    let (_, again, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/email"),
        Some(&t),
        Some(&json!({"type": "smtp", "host": "mail2.example", "port": 465, "username": "u", "from": "no-reply@example.com", "security": "tls"})),
    )
    .await;
    assert_eq!(again["host"], "mail2.example");
    assert_eq!(again["password_set"], true, "omitted password kept");

    // HTTP delivery, exercised end to end through the tenant's own sender.
    let hook = app.url("/_test/email");
    let (status, http, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/email"),
        Some(&t),
        Some(&json!({"type": "http", "url": hook, "auth_header": "Bearer hook-secret", "from": "no-reply@example.com"})),
    )
    .await;
    assert_eq!(status, 200, "{http}");
    assert_eq!(http["type"], "http");
    assert_eq!(http["auth_header_set"], true);
    assert!(http.get("auth_header").is_none());
    let (status, sent, _) = call(
        &app,
        Method::POST,
        &format!("{base}/email/test"),
        Some(&t),
        Some(&json!({"to": "Ops@Example.com"})),
    )
    .await;
    assert_eq!(status, 200, "{sent}");
    assert_eq!(sent["sender"], "http");
    assert_eq!(sent["to"], "ops@example.com");
    {
        common::settle(&app.state).await;
        let got = inbox.lock().unwrap();
        let (auth, body) = got.emails.last().expect("webhook hit");
        assert_eq!(auth.as_deref(), Some("Bearer hook-secret"));
        assert_eq!(body["to"][0], "ops@example.com");
        assert!(
            body["subject"]
                .as_str()
                .unwrap()
                .starts_with("Test message")
        );
    }
    let (status, err, _) = call(
        &app,
        Method::POST,
        &format!("{base}/email/test"),
        Some(&t),
        Some(&json!({"to": "not-an-email"})),
    )
    .await;
    assert_eq!(status, 400, "{err}");
    // A failing backend is reported, not swallowed.
    call(
        &app,
        Method::PUT,
        &format!("{base}/email"),
        Some(&t),
        Some(&json!({"type": "http", "url": app.url("/_test/broken"), "from": "no-reply@example.com"})),
    )
    .await;
    let (status, err, _) = call(
        &app,
        Method::POST,
        &format!("{base}/email/test"),
        Some(&t),
        Some(&json!({"to": "ops@example.com"})),
    )
    .await;
    assert_eq!(status, 503, "{err}");
    let (status, cleared, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/email"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200, "{cleared}");
    assert_ne!(cleared["source"], "tenant");

    // SMS.
    let (status, err, _) = call(
        &app,
        Method::POST,
        &format!("{base}/sms/test"),
        Some(&t),
        Some(&json!({"to": "+15550001111"})),
    )
    .await;
    assert_eq!(status, 400, "nothing configured: {err}");
    let (status, sms, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/sms"),
        Some(&t),
        Some(&json!({"url": app.url("/_test/sms"), "auth_header": "Key k", "from": "RIDM"})),
    )
    .await;
    assert_eq!(status, 200, "{sms}");
    assert_eq!(sms["configured"], true);
    assert_eq!(sms["auth_header_set"], true);
    assert!(sms.get("auth_header").is_none());
    let (status, sent, _) = call(
        &app,
        Method::POST,
        &format!("{base}/sms/test"),
        Some(&t),
        Some(&json!({"to": "+1 555 000 1111"})),
    )
    .await;
    assert_eq!(status, 200, "{sent}");
    assert_eq!(sent["to"], "+15550001111");
    {
        common::settle(&app.state).await;
        let got = inbox.lock().unwrap();
        let (auth, body) = got.sms.last().expect("sms webhook hit");
        assert_eq!(auth.as_deref(), Some("Key k"));
        assert_eq!(body["to"], "+15550001111");
        assert_eq!(body["from"], "RIDM");
    }
    let (_, kept, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/sms"),
        Some(&t),
        Some(&json!({"url": app.url("/_test/sms")})),
    )
    .await;
    assert_eq!(kept["auth_header_set"], true, "omitted auth header kept");
    let (status, err, _) = call(
        &app,
        Method::POST,
        &format!("{base}/sms/test"),
        Some(&t),
        Some(&json!({"to": "12345"})),
    )
    .await;
    assert_eq!(status, 400, "{err}");
    let (_, off, _) = call(&app, Method::DELETE, &format!("{base}/sms"), Some(&t), None).await;
    assert_eq!(off["configured"], false);
}

#[tokio::test]
async fn template_overrides_preview_and_apply_to_sent_mail() {
    let (app, inbox) = fixture().await;
    let tid = app.tenant.id;
    let base = format!("/admin/tenants/{}/messaging", app.tenant.slug);
    let t = admin_token(&app, tid, ADMIN_ROLE).await;

    let (status, catalogue, _) = get_json(&app, &format!("{base}/templates"), Some(&t)).await;
    assert_eq!(status, 200, "{catalogue}");
    assert!(
        catalogue["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e == "invitation")
    );
    assert!(catalogue["overrides"].as_array().unwrap().is_empty());

    // Built-in shown as the starting point.
    let (status, builtin, _) = get_json(
        &app,
        &format!("{base}/templates/email/password_reset/de"),
        Some(&t),
    )
    .await;
    assert_eq!(status, 200, "{builtin}");
    assert_eq!(builtin["source"], "builtin");
    assert!(builtin["body_text"].as_str().unwrap().contains("{{link}}"));
    let (status, _, _) = get_json(
        &app,
        &format!("{base}/templates/email/not_an_event/de"),
        Some(&t),
    )
    .await;
    assert_eq!(status, 400);
    let (status, _, _) = get_json(&app, &format!("{base}/templates/fax/otp/de"), Some(&t)).await;
    assert_eq!(status, 400);

    // Validation of overrides.
    for (path, body) in [
        ("email/password_reset/de", json!({"body_text": "x"})),
        (
            "email/password_reset/de",
            json!({"subject": "s", "body_text": "{{#if"}),
        ),
        ("sms/otp/de", json!({"subject": "s", "body_text": "x"})),
        (
            "email/password_reset/bad_locale!",
            json!({"subject": "s", "body_text": "x"}),
        ),
        (
            "email/password_reset/de",
            json!({"subject": "s", "body_text": "x", "colour": "red"}),
        ),
    ] {
        let (status, err, _) = call(
            &app,
            Method::PUT,
            &format!("{base}/templates/{path}"),
            Some(&t),
            Some(&body),
        )
        .await;
        assert_eq!(status, 400, "{path} {body} -> {err}");
    }

    // Override, preview stored and draft, then see it used for real mail.
    let (status, saved, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/templates/email/password_reset/de"),
        Some(&t),
        Some(&json!({"subject": "Passwort zurücksetzen bei {{tenant.display_name}}", "body_text": "Hallo {{user.username}}, Link: {{link}}"})),
    )
    .await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(saved["source"], "override");
    let (_, catalogue, _) = get_json(&app, &format!("{base}/templates"), Some(&t)).await;
    assert_eq!(catalogue["overrides"].as_array().unwrap().len(), 1);
    assert_eq!(catalogue["overrides"][0]["locale"], "de");
    let (status, preview, _) = call(
        &app,
        Method::POST,
        &format!("{base}/templates/preview"),
        Some(&t),
        Some(&json!({"event": "password_reset", "locale": "de-AT", "vars": {"user": {"username": "maria"}}})),
    )
    .await;
    assert_eq!(status, 200, "{preview}");
    assert!(
        preview["subject"]
            .as_str()
            .unwrap()
            .starts_with("Passwort zurücksetzen bei")
    );
    assert!(
        preview["body_text"]
            .as_str()
            .unwrap()
            .starts_with("Hallo maria, Link: https://")
    );
    let (status, draft, _) = call(
        &app,
        Method::POST,
        &format!("{base}/templates/preview"),
        Some(&t),
        Some(&json!({"channel": "sms", "event": "otp", "draft": {"body_text": "Code {{code}} für {{tenant.display_name}}"}})),
    )
    .await;
    assert_eq!(status, 200, "{draft}");
    assert!(
        draft["body_text"]
            .as_str()
            .unwrap()
            .starts_with("Code 123456 für")
    );
    assert!(draft["subject"].is_null());
    let (status, err, _) = call(
        &app,
        Method::POST,
        &format!("{base}/templates/preview"),
        Some(&t),
        Some(&json!({"event": "otp", "draft": {"subject": "s", "body_text": "{{#each"}})),
    )
    .await;
    assert_eq!(status, 400, "{err}");

    // Real delivery through the queue picks the override for a German user.
    call(
        &app,
        Method::PUT,
        &format!("{base}/email"),
        Some(&t),
        Some(&json!({"type": "http", "url": app.url("/_test/email"), "from": "no-reply@example.com"})),
    )
    .await;
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    messaging::send(
        &app.state,
        &tenant,
        Outgoing {
            channel: MessageChannel::Email,
            event: "password_reset",
            recipient: "maria@example.com",
            locale: Some("de"),
            vars: json!({"user": {"username": "maria"}, "link": "https://x.example/r?token=abc", "expires_minutes": 15}),
        },
    )
    .await
    .unwrap();
    {
        common::settle(&app.state).await;
        let got = inbox.lock().unwrap();
        let (_, body) = got.emails.last().expect("delivered");
        assert!(
            body["subject"]
                .as_str()
                .unwrap()
                .starts_with("Passwort zurücksetzen")
        );
        assert!(body["text"].as_str().unwrap().contains("Hallo maria"));
    }

    // The log shows the delivery without its body; redeliver needs a dead message.
    let (status, log, _) = get_json(&app, &format!("{base}/log"), Some(&t)).await;
    assert_eq!(status, 200, "{log}");
    let entry = log
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["recipient"] == "maria@example.com")
        .expect("logged");
    assert_eq!(entry["status"], "sent");
    assert!(entry.get("body_text").is_none() && entry.get("body_html").is_none());
    let (status, _, _) = call(
        &app,
        Method::POST,
        &format!("{base}/log/{}/redeliver", entry["id"].as_str().unwrap()),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 400, "only dead messages");
    let (_, sent_only, _) = get_json(&app, &format!("{base}/log?status=dead"), Some(&t)).await;
    assert!(sent_only.as_array().unwrap().is_empty());

    // Delete the override: back to the built-in.
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/templates/email/password_reset/de"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/templates/email/password_reset/de"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);
    let (_, back, _) = get_json(
        &app,
        &format!("{base}/templates/email/password_reset/de"),
        Some(&t),
    )
    .await;
    assert_eq!(back["source"], "builtin");
}

#[tokio::test]
async fn built_in_roles_map_onto_messaging_routes() {
    let (app, _) = fixture().await;
    let base = format!("/admin/tenants/{}/messaging", app.tenant.slug);
    for (role, read, write) in [
        (OWNER_ROLE, 200, 200),
        (ADMIN_ROLE, 200, 200),
        (USER_MANAGER_ROLE, 403, 403),
        (CLIENT_MANAGER_ROLE, 403, 403),
        (VIEWER_ROLE, 200, 403),
    ] {
        let t = admin_token(&app, app.tenant.id, role).await;
        let (status, body, _) = get_json(&app, &format!("{base}/templates"), Some(&t)).await;
        assert_eq!(status, read, "{role} read: {body}");
        let (status, body, _) = call(
            &app,
            Method::PUT,
            &format!("{base}/templates/sms/otp/en"),
            Some(&t),
            Some(&json!({"body_text": "Code {{code}}"})),
        )
        .await;
        assert_eq!(status, write, "{role} write: {body}");
    }
    let (status, _, _) = get_json(&app, &format!("{base}/email"), None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn messaging_settings_are_confined_to_the_admins_tenant() {
    let (app, _) = fixture().await;
    let other = create_tenant(&app.state.db).await;
    let t = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let global = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/messaging/email", other.slug),
        Some(&t),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/messaging/email", other.slug),
        Some(&global),
    )
    .await;
    assert_eq!(status, 200);
}
