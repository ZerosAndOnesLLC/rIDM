//! Phase 5.10: webhooks — signed deliveries, retries, dead-lettering,
//! redelivery, test pings and the dispatcher on real events.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use common::admin::{admin_token, call, get_json};
use common::{TestApp, create_tenant};
use hmac::{Hmac, KeyInit as _, Mac as _};
use reqwest::Method;
use ridm_api::models::MASTER_TENANT_ID;
use ridm_api::services::admin_access::{
    ADMIN_ROLE, CLIENT_MANAGER_ROLE, OWNER_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE,
};
use serde_json::{Value, json};
use sha2::Sha256;
use uuid::Uuid;

#[derive(Default)]
struct Received {
    hits: Vec<(HeaderMap, Vec<u8>)>,
}
type Inbox = Arc<Mutex<Received>>;

fn receiver(inbox: Inbox) -> Router<ridm_api::state::AppState> {
    let ok = inbox.clone();
    Router::new()
        .route(
            "/_test/hook",
            post(move |headers: HeaderMap, body: axum::body::Bytes| {
                let inbox = ok.clone();
                async move {
                    inbox.lock().unwrap().hits.push((headers, body.to_vec()));
                    (StatusCode::OK, "thanks")
                }
            }),
        )
        .route(
            "/_test/fail",
            post(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
        )
        .route(
            "/_test/reject",
            post(|| async { (StatusCode::BAD_REQUEST, "no") }),
        )
}

fn verify_signature(secret: &str, headers: &HeaderMap, body: &[u8]) -> bool {
    let sig = headers["x-ridm-signature"].to_str().unwrap();
    let (t, v1) = sig.split_once(',').unwrap();
    let t = t.strip_prefix("t=").unwrap();
    let v1 = v1.strip_prefix("v1=").unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(t.as_bytes());
    mac.update(b".");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes()) == v1
}

async fn wait_deliveries(
    app: &TestApp,
    path: &str,
    bearer: &str,
    pred: impl Fn(&Value) -> bool,
) -> Value {
    for _ in 0..100 {
        let (status, body, _) = get_json(app, path, Some(bearer)).await;
        assert_eq!(status, 200, "{body}");
        if pred(&body) {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("deliveries did not appear in time at {path}");
}

#[tokio::test]
async fn admin_runs_the_webhook_lifecycle_with_signed_deliveries() {
    let inbox: Inbox = Arc::default();
    let app = TestApp::spawn_with(receiver(inbox.clone())).await;
    let tid = app.tenant.id;
    let base = format!("/admin/tenants/{}/webhooks", app.tenant.slug);
    let t = admin_token(&app, tid, ADMIN_ROLE).await;
    let hook = app.url("/_test/hook");

    // Validation.
    for body in [
        json!({"name": "x", "url": hook, "events": []}),
        json!({"name": "x", "url": hook, "events": ["User.Created"]}),
        json!({"name": "x", "url": "http://example.com/h", "events": ["*"]}),
        json!({"name": "x", "url": hook, "events": ["*"], "headers": {"Host": "evil"}}),
        json!({"name": "x", "url": hook, "events": ["*"], "headers": {"X-Ridm-Event": "spoof"}}),
        json!({"name": "x", "url": hook, "events": ["*"], "max_attempts": 0}),
        json!({"name": "x", "url": hook, "events": ["*"], "colour": "red"}),
    ] {
        let (status, err, _) = call(&app, Method::POST, &base, Some(&t), Some(&body)).await;
        assert_eq!(status, 400, "{body} -> {err}");
    }

    // Create: secret shown once, never again.
    let (status, created, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"name": "CRM sync", "url": hook, "events": ["user.*", "webhook.test"], "headers": {"X-Api-Key": "k1"}})),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_str().unwrap().to_string();
    let secret = created["secret"].as_str().unwrap().to_string();
    assert!(secret.starts_with("whsec_"));
    assert!(created.get("secret_enc").is_none());
    let (status, got, _) = get_json(&app, &format!("{base}/{id}"), Some(&t)).await;
    assert_eq!(status, 200, "{got}");
    assert!(got.get("secret").is_none() && got.get("secret_enc").is_none());
    assert_eq!(got["events"], json!(["user.*", "webhook.test"]));
    let (_, list, _) = get_json(&app, &base, Some(&t)).await;
    assert!(list.as_array().unwrap().iter().any(|w| w["id"] == id));

    // Test ping: delivered synchronously, signed, with the static header.
    let (status, ping, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{id}/test"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200, "{ping}");
    assert_eq!(ping["status"], "delivered");
    assert_eq!(ping["event_name"], "webhook.test");
    assert_eq!(ping["last_status"], 200);
    assert_eq!(ping["response_snippet"], "thanks");
    {
        let got = inbox.lock().unwrap();
        let (headers, body) = got.hits.last().expect("ping received");
        assert_eq!(headers["x-ridm-event"], "webhook.test");
        assert_eq!(headers["x-ridm-webhook"], id.as_str());
        assert_eq!(headers["x-api-key"], "k1");
        assert!(verify_signature(&secret, headers, body));
        assert!(!verify_signature("whsec_wrong", headers, body));
        let doc: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(doc["event"]["kind"]["type"], "webhook_test");
        assert_eq!(doc["delivery_id"], ping["id"]);
    }

    // A real event flows through the dispatcher and the delivery job.
    let (status, user, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/users", app.tenant.slug),
        Some(&t),
        Some(&json!({"username": "hooked"})),
    )
    .await;
    assert_eq!(status, 201, "{user}");
    let deliveries = wait_deliveries(&app, &format!("{base}/{id}/deliveries"), &t, |d| {
        d.as_array()
            .unwrap()
            .iter()
            .any(|x| x["event_name"] == "user.created")
    })
    .await;
    let pending = deliveries
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["event_name"] == "user.created")
        .unwrap()
        .clone();
    // The dispatcher sends at once (Phase 9.5), so the row is pending only
    // for an instant; the job (every tenant of the shared database) is a
    // no-op for it afterwards and must not fail.
    let after = wait_deliveries(
        &app,
        &format!("{base}/{id}/deliveries/{}", pending["id"].as_str().unwrap()),
        &t,
        |d| d["status"] == "delivered",
    )
    .await;
    assert_eq!(after["status"], "delivered");
    ridm_api::jobs::webhook_delivery::run_once(&app.state)
        .await
        .unwrap()
        .unwrap();
    {
        let got = inbox.lock().unwrap();
        let (headers, body) = got.hits.last().unwrap();
        assert_eq!(headers["x-ridm-event"], "user.created");
        assert!(verify_signature(&secret, headers, body));
        let doc: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(doc["event"]["kind"]["user_id"], user["id"]);
    }
    // Events outside the subscription are not queued.
    let (_, all, _) = get_json(&app, &format!("{base}/{id}/deliveries"), Some(&t)).await;
    assert!(
        all.as_array().unwrap().iter().all(|x| x["event_name"]
            .as_str()
            .unwrap()
            .starts_with("user.")
            || x["event_name"] == "webhook.test")
    );

    // Rotate the secret: the next delivery is signed with the new one.
    let (status, rotated, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{id}/secret"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 201, "{rotated}");
    let secret2 = rotated["secret"].as_str().unwrap().to_string();
    assert_ne!(secret2, secret);
    call(
        &app,
        Method::POST,
        &format!("{base}/{id}/test"),
        Some(&t),
        None,
    )
    .await;
    {
        let got = inbox.lock().unwrap();
        let (headers, body) = got.hits.last().unwrap();
        assert!(verify_signature(&secret2, headers, body));
        assert!(!verify_signature(&secret, headers, body));
    }

    // Failures: 5xx retries with backoff, 4xx is dead at once, and a dead
    // delivery can be redelivered after the endpoint is fixed.
    let (status, patched, _) = call(
        &app,
        Method::PATCH,
        &format!("{base}/{id}"),
        Some(&t),
        Some(&json!({"url": app.url("/_test/fail"), "max_attempts": 3})),
    )
    .await;
    assert_eq!(status, 200, "{patched}");
    let (_, failing, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{id}/test"),
        Some(&t),
        None,
    )
    .await;
    // Test pings get a single attempt.
    assert_eq!(failing["status"], "dead", "{failing}");
    assert_eq!(failing["last_status"], 500);
    assert!(failing["last_error"].as_str().unwrap().contains("500"));
    assert_eq!(failing["response_snippet"], "boom");
    call(
        &app,
        Method::PATCH,
        &format!("{base}/{id}"),
        Some(&t),
        Some(&json!({"url": app.url("/_test/reject")})),
    )
    .await;
    let (_, rejected, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{id}/test"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(rejected["status"], "dead");
    assert_eq!(rejected["last_status"], 400);
    call(
        &app,
        Method::PATCH,
        &format!("{base}/{id}"),
        Some(&t),
        Some(&json!({"url": hook})),
    )
    .await;
    let (status, redelivered, _) = call(
        &app,
        Method::POST,
        &format!(
            "{base}/{id}/deliveries/{}/redeliver",
            failing["id"].as_str().unwrap()
        ),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200, "{redelivered}");
    assert_eq!(redelivered["status"], "delivered");
    assert_eq!(redelivered["attempts"], 1, "attempts restart on redelivery");
    let (_, dead_only, _) = get_json(
        &app,
        &format!("{base}/{id}/deliveries?status=dead"),
        Some(&t),
    )
    .await;
    assert!(
        dead_only
            .as_array()
            .unwrap()
            .iter()
            .all(|d| d["status"] == "dead")
    );

    // Disabled webhooks receive nothing new.
    call(
        &app,
        Method::PATCH,
        &format!("{base}/{id}"),
        Some(&t),
        Some(&json!({"enabled": false})),
    )
    .await;
    let before = inbox.lock().unwrap().hits.len();
    call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/users", app.tenant.slug),
        Some(&t),
        Some(&json!({"username": "unhooked"})),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    ridm_api::jobs::webhook_delivery::run_once(&app.state)
        .await
        .unwrap();
    assert_eq!(inbox.lock().unwrap().hits.len(), before);

    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = get_json(&app, &format!("{base}/{id}"), Some(&t)).await;
    assert_eq!(status, 404);
    let (status, _, _) = get_json(&app, &format!("{base}/{id}/deliveries"), Some(&t)).await;
    assert_eq!(status, 404, "deliveries go with the webhook");
}

#[tokio::test]
async fn built_in_roles_map_onto_webhook_routes_and_tenants_are_confined() {
    let inbox: Inbox = Arc::default();
    let app = TestApp::spawn_with(receiver(inbox)).await;
    let base = format!("/admin/tenants/{}/webhooks", app.tenant.slug);
    let hook = app.url("/_test/hook");
    for (role, list, create) in [
        (OWNER_ROLE, 200, 201),
        (ADMIN_ROLE, 200, 201),
        (USER_MANAGER_ROLE, 403, 403),
        (CLIENT_MANAGER_ROLE, 403, 403),
        (VIEWER_ROLE, 200, 403),
    ] {
        let t = admin_token(&app, app.tenant.id, role).await;
        let (status, body, _) = get_json(&app, &base, Some(&t)).await;
        assert_eq!(status, list, "{role} list: {body}");
        let (status, body, _) = call(
            &app,
            Method::POST,
            &base,
            Some(&t),
            Some(&json!({"name": role, "url": hook, "events": ["*"]})),
        )
        .await;
        assert_eq!(status, create, "{role} create: {body}");
    }
    let (status, _, _) = get_json(&app, &base, None).await;
    assert_eq!(status, 401);

    let other = create_tenant(&app.state.db).await;
    let t = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let global = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;
    let (status, theirs, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/webhooks", other.slug),
        Some(&global),
        Some(&json!({"name": "theirs", "url": hook, "events": ["*"]})),
    )
    .await;
    assert_eq!(status, 201, "{theirs}");
    let their_id = theirs["id"].as_str().unwrap();
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/webhooks/{their_id}", other.slug),
        Some(&t),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = get_json(&app, &format!("{base}/{their_id}"), Some(&t)).await;
    assert_eq!(status, 404);
    let (status, _, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{}/test", Uuid::new_v4()),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);
}
