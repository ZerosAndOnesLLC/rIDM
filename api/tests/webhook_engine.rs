//! The delivery engine: prompt delivery on the event itself, concurrent
//! attempts, the dead-letter event, bulk redelivery, and target validation.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::http::StatusCode;
use axum::routing::post;
use common::TestApp;
use common::admin::{admin_token, call, get_json};
use reqwest::Method;
use ridm_api::models::NewWebhook;
use ridm_api::services::admin_access::ADMIN_ROLE;
use ridm_api::services::webhooks;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Default)]
struct Received {
    hits: Vec<(String, Instant)>,
}
type Inbox = Arc<Mutex<Received>>;

fn receiver(inbox: Inbox) -> Router<ridm_api::state::AppState> {
    let ok = inbox.clone();
    let slow = inbox.clone();
    Router::new()
        .route(
            "/_test/hook",
            post(move |headers: axum::http::HeaderMap| {
                let inbox = ok.clone();
                async move {
                    let event = headers["x-ridm-event"].to_str().unwrap().to_string();
                    inbox.lock().unwrap().hits.push((event, Instant::now()));
                    StatusCode::OK
                }
            }),
        )
        .route(
            "/_test/slow",
            post(move |headers: axum::http::HeaderMap| {
                let inbox = slow.clone();
                async move {
                    tokio::time::sleep(Duration::from_millis(1500)).await;
                    let event = headers["x-ridm-event"].to_str().unwrap().to_string();
                    inbox
                        .lock()
                        .unwrap()
                        .hits
                        .push((format!("slow:{event}"), Instant::now()));
                    StatusCode::OK
                }
            }),
        )
        .route("/_test/fail", post(|| async { StatusCode::BAD_GATEWAY }))
}

async fn hook(app: &TestApp, url: &str, max_attempts: i32) -> Uuid {
    webhooks::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewWebhook {
            name: "engine".into(),
            url: url.into(),
            events: vec!["webhook.test".into()],
            enabled: Some(true),
            headers: None,
            max_attempts: Some(max_attempts),
        },
    )
    .await
    .unwrap()
    .webhook
    .id
}

fn ping(app: &TestApp, webhook_id: Uuid) {
    app.state.events.publish(Event::new(
        Some(app.tenant.id),
        Actor::System,
        EventKind::WebhookTest { webhook_id },
    ));
}

async fn wait_until(inbox: &Inbox, pred: impl Fn(&[(String, Instant)]) -> bool) {
    for _ in 0..200 {
        if pred(&inbox.lock().unwrap().hits) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "receiver never saw what was expected: {:?}",
        inbox
            .lock()
            .unwrap()
            .hits
            .iter()
            .map(|h| &h.0)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn an_event_is_delivered_promptly_without_the_job() {
    let inbox: Inbox = Arc::default();
    let app = TestApp::spawn_with(receiver(inbox.clone())).await;
    let id = hook(&app, &app.url("/_test/hook"), 3).await;
    let started = Instant::now();
    ping(&app, id);
    wait_until(&inbox, |h| h.iter().any(|(e, _)| e == "webhook.test")).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "delivered in {:?}, not at the job's next tick",
        started.elapsed()
    );
    // The log agrees.
    let t = admin_token(&app, app.tenant.id, ADMIN_ROLE).await;
    let path = format!(
        "/admin/tenants/{}/webhooks/{id}/deliveries?status=delivered",
        app.tenant.slug
    );
    for _ in 0..100 {
        let (_, body, _) = get_json(&app, &path, Some(&t)).await;
        if body.as_array().is_some_and(|a| !a.is_empty()) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("delivery not recorded");
}

#[tokio::test]
async fn attempts_run_concurrently() {
    let inbox: Inbox = Arc::default();
    let app = TestApp::spawn_with(receiver(inbox.clone())).await;
    // Four slow endpoints and one quick one, all fed by one event.
    for _ in 0..4 {
        hook(&app, &app.url("/_test/slow"), 1).await;
    }
    let quick = hook(&app, &app.url("/_test/hook"), 1).await;
    let started = Instant::now();
    ping(&app, quick);
    wait_until(&inbox, |h| h.len() == 5).await;
    let took = started.elapsed();
    assert!(
        took < Duration::from_secs(4),
        "five deliveries with four 1.5 s endpoints took {took:?}: they were serialized"
    );
}

#[tokio::test]
async fn a_dead_letter_raises_an_event_and_can_be_bulk_redelivered() {
    let inbox: Inbox = Arc::default();
    let app = TestApp::spawn_with(receiver(inbox.clone())).await;
    let id = hook(&app, &app.url("/_test/fail"), 1).await;
    let mut bus = app.state.events.subscribe();
    ping(&app, id);
    // The dead-letter event names the delivery.
    let dead = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let env = bus.recv().await.unwrap();
            if let EventKind::WebhookDeliveryDead {
                webhook_id,
                delivery_id,
                event_name,
            } = &env.event.kind
            {
                assert_eq!(*webhook_id, id);
                assert_eq!(event_name, "webhook.test");
                break *delivery_id;
            }
        }
    })
    .await
    .expect("dead-letter event");
    // ... and never itself becomes a delivery (no endless chain).
    tokio::time::sleep(Duration::from_millis(300)).await;
    let t = admin_token(&app, app.tenant.id, ADMIN_ROLE).await;
    let base = format!("/admin/tenants/{}/webhooks/{id}", app.tenant.slug);
    let (_, all, _) = get_json(&app, &format!("{base}/deliveries"), Some(&t)).await;
    assert_eq!(all.as_array().unwrap().len(), 1, "{all}");
    assert_eq!(all[0]["id"], dead.to_string());
    assert_eq!(all[0]["status"], "dead");

    // Fix the endpoint, then send every dead letter again in one go.
    let (status, _, _) = call(
        &app,
        Method::PATCH,
        &base,
        Some(&t),
        Some(&json!({"url": app.url("/_test/hook")})),
    )
    .await;
    assert_eq!(status, 200);
    let (status, body, _) = call(
        &app,
        Method::POST,
        &format!("{base}/deliveries/redeliver-dead"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["requeued"], 1);
    let (_, after, _) = get_json(&app, &format!("{base}/deliveries"), Some(&t)).await;
    assert_eq!(after[0]["status"], "delivered", "{after}");
    let (status, body, _) = call(
        &app,
        Method::POST,
        &format!("{base}/deliveries/redeliver-dead"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["requeued"], 0, "nothing dead any more");
    // Unknown webhook.
    let (status, _, _) = call(
        &app,
        Method::POST,
        &format!(
            "/admin/tenants/{}/webhooks/{}/deliveries/redeliver-dead",
            app.tenant.slug,
            Uuid::new_v4()
        ),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn private_addresses_are_refused_as_targets() {
    let app = TestApp::spawn().await;
    let t = admin_token(&app, app.tenant.id, ADMIN_ROLE).await;
    for url in [
        "https://10.0.0.5/hook",
        "https://169.254.169.254/latest/meta-data",
        "https://[fd12::1]/hook",
    ] {
        let (status, body, _) = call(
            &app,
            Method::POST,
            &format!("/admin/tenants/{}/webhooks", app.tenant.slug),
            Some(&t),
            Some(&json!({"name": "x", "url": url, "events": ["*"]})),
        )
        .await;
        assert_eq!(status, 400, "{url}: {body}");
        assert!(
            body["detail"].as_str().unwrap().contains("not allowed"),
            "{body}"
        );
    }
    let _: Value = json!(null);
}
