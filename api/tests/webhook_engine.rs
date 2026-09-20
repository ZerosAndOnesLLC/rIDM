//! The delivery engine: prompt delivery on the event itself, concurrent
//! attempts, the signature over every body, the retry ladder, the dead-letter
//! event, bulk redelivery, and target validation.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::http::StatusCode;
use axum::routing::post;
use common::TestApp;
use common::admin::{admin_token, call, get_json};
use reqwest::Method;
use ridm_api::jobs::webhook_delivery;
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
    wait_for(inbox, Duration::from_secs(5), pred).await
}

/// Waits up to `budget` for the receiver to see what the caller expects. A
/// test making a claim about *how long* delivery took gives this room well
/// beyond the time it asserts, so a slow runner fails on the claim, with its
/// diagnostic, rather than on a bare "never saw it".
async fn wait_for(inbox: &Inbox, budget: Duration, pred: impl Fn(&[(String, Instant)]) -> bool) {
    let deadline = Instant::now() + budget;
    loop {
        if pred(&inbox.lock().unwrap().hits) {
            return;
        }
        if Instant::now() >= deadline {
            break;
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
    // Four 1.5 s endpoints one after another cannot finish inside 6 s, so 5 s
    // still shows they overlapped, with room for a loaded runner. The wait is
    // longer again, so a slow pass reports the timing, not a bare timeout.
    wait_for(&inbox, Duration::from_secs(30), |h| h.len() == 5).await;
    let took = started.elapsed();
    assert!(
        took < Duration::from_secs(5),
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

// --- signing, retries and dead-lettering -------------------------------------

/// A receiver that keeps the whole request: headers and body, as sent.
#[derive(Clone, Debug)]
struct Delivered {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
type Recorder = Arc<Mutex<Vec<Delivered>>>;

/// Endpoints for the signing and retry tests: one records, one fails with a
/// status worth retrying, one with a status that is not.
fn recorder(seen: Recorder) -> Router<ridm_api::state::AppState> {
    Router::new()
        .route(
            "/_test/signed",
            post(
                move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                    let seen = seen.clone();
                    async move {
                        seen.lock().unwrap().push(Delivered {
                            headers: headers
                                .iter()
                                .map(|(k, v)| {
                                    (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned())
                                })
                                .collect(),
                            body: body.to_vec(),
                        });
                        StatusCode::NO_CONTENT
                    }
                },
            ),
        )
        .route(
            "/_test/unavailable",
            post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        )
        .route("/_test/gone", post(|| async { StatusCode::NOT_FOUND }))
}

impl Delivered {
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("header {name} missing from {:?}", self.headers))
    }
}

async fn recorded(seen: &Recorder, n: usize) -> Vec<Delivered> {
    for _ in 0..200 {
        if seen.lock().unwrap().len() >= n {
            return seen.lock().unwrap().clone();
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "only {} deliveries arrived, wanted {n}",
        seen.lock().unwrap().len()
    );
}

/// The delivery one webhook has in the log, once there is exactly one.
async fn only_delivery(app: &TestApp, token: &str, webhook_id: Uuid) -> Value {
    let path = format!(
        "/admin/tenants/{}/webhooks/{webhook_id}/deliveries",
        app.tenant.slug
    );
    for _ in 0..200 {
        let (_, body, _) = get_json(app, &path, Some(token)).await;
        let rows = body.as_array().cloned().unwrap_or_default();
        if rows.len() == 1 && rows[0]["status"] != "sending" && rows[0]["status"] != "pending" {
            return rows[0].clone();
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no settled delivery recorded");
}

/// Move a delivery's next attempt into the past so the job takes it.
async fn make_due(app: &TestApp, delivery_id: &str) {
    let mut tx = ridm_api::db::bypass_tx(&app.state.db).await.unwrap();
    sqlx::query("UPDATE webhook_deliveries SET next_attempt_at = now() - interval '1 second' WHERE id = $1::uuid")
        .bind(delivery_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// Run the delivery job until it actually gets the leader lock (other tests in
/// this binary and the others share it).
async fn run_delivery_job(app: &TestApp) {
    for _ in 0..60 {
        if webhook_delivery::run_once(&app.state)
            .await
            .unwrap()
            .is_some()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the delivery job never took the leader lock");
}

#[tokio::test]
async fn every_delivery_is_signed_over_its_body_and_the_secret_can_be_rotated() {
    let seen: Recorder = Arc::default();
    let app = TestApp::spawn_with(recorder(seen.clone())).await;
    let t = admin_token(&app, app.tenant.id, ADMIN_ROLE).await;
    let (status, created, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/webhooks", app.tenant.slug),
        Some(&t),
        Some(&json!({
            "name": "signed",
            "url": app.url("/_test/signed"),
            "events": ["webhook.test"],
            "headers": { "x-team": "platform" }
        })),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    let secret = created["secret"].as_str().unwrap().to_string();
    assert!(
        secret.starts_with("whsec_"),
        "secret does not carry the expected prefix"
    );

    ping(&app, id);
    let first = recorded(&seen, 1).await.remove(0);

    // Headers: the event, the delivery, the webhook, and the configured extras.
    assert_eq!(first.header("x-ridm-event"), "webhook.test");
    assert_eq!(first.header("x-ridm-webhook"), id.to_string());
    assert_eq!(first.header("content-type"), "application/json");
    assert_eq!(first.header("x-team"), "platform");
    let delivery_id: Uuid = first
        .header("x-ridm-delivery")
        .parse()
        .expect("delivery id");

    // The signature is an HMAC over "<timestamp>.<body>" under the secret the
    // creating call returned, and the timestamp in it is the one sent.
    let ts: i64 = first.header("x-ridm-timestamp").parse().unwrap();
    let signature = first.header("x-ridm-signature").to_string();
    assert_eq!(signature, webhooks::sign(&secret, ts, &first.body));
    assert!(signature.starts_with(&format!("t={ts},v1=")));
    assert!((ts - chrono::Utc::now().timestamp()).abs() < 300, "t={ts}");
    // Neither another secret nor another body produces it.
    let other_secret = format!("whsec_{}", Uuid::new_v4().simple());
    assert_ne!(signature, webhooks::sign(&other_secret, ts, &first.body));
    let mut tampered = first.body.clone();
    tampered.extend_from_slice(b" ");
    assert_ne!(signature, webhooks::sign(&secret, ts, &tampered));
    assert_ne!(signature, webhooks::sign(&secret, ts + 1, &first.body));

    // The body names the delivery and the attempt.
    let body: Value = serde_json::from_slice(&first.body).unwrap();
    assert_eq!(body["delivery_id"], delivery_id.to_string());
    assert_eq!(body["attempt"], 1);
    assert_eq!(body["event"]["kind"]["type"], "webhook_test");

    // Rotating the secret returns a new one and the next delivery uses it.
    let (status, rotated, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/webhooks/{id}/secret", app.tenant.slug),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 201, "{rotated}");
    let new_secret = rotated["secret"].as_str().unwrap().to_string();
    assert_ne!(new_secret, secret);
    let (status, _, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/webhooks/{id}/test", app.tenant.slug),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200);
    let second = recorded(&seen, 2).await.remove(1);
    let ts: i64 = second.header("x-ridm-timestamp").parse().unwrap();
    assert_eq!(
        second.header("x-ridm-signature"),
        webhooks::sign(&new_secret, ts, &second.body)
    );
    assert_ne!(
        second.header("x-ridm-signature"),
        webhooks::sign(&secret, ts, &second.body)
    );
}

#[tokio::test]
async fn a_retryable_failure_waits_for_the_backoff_and_a_permanent_one_dies_at_once() {
    // The ladder the scheduler follows (30s, 2m, 10m, 30m, 2h, then 6h).
    assert_eq!(webhooks::backoff(1), chrono::Duration::seconds(30));
    assert_eq!(webhooks::backoff(2), chrono::Duration::minutes(2));
    assert_eq!(webhooks::backoff(3), chrono::Duration::minutes(10));
    assert_eq!(webhooks::backoff(4), chrono::Duration::minutes(30));
    assert_eq!(webhooks::backoff(5), chrono::Duration::hours(2));
    assert_eq!(webhooks::backoff(9), chrono::Duration::hours(6));

    let seen: Recorder = Arc::default();
    let app = TestApp::spawn_with(recorder(seen.clone())).await;
    let t = admin_token(&app, app.tenant.id, ADMIN_ROLE).await;

    // 503: worth another attempt. Three are allowed.
    let flaky = hook(&app, &app.url("/_test/unavailable"), 3).await;
    ping(&app, flaky);
    let first = only_delivery(&app, &t, flaky).await;
    assert_eq!(first["status"], "failed", "{first}");
    assert_eq!(first["attempts"], 1);
    assert_eq!(first["last_status"], 503);
    let due: chrono::DateTime<chrono::Utc> =
        first["next_attempt_at"].as_str().unwrap().parse().unwrap();
    let wait = due - chrono::Utc::now();
    assert!(
        wait > chrono::Duration::seconds(20) && wait <= chrono::Duration::seconds(30),
        "next attempt in {wait}, not one backoff step away"
    );

    // The job leaves it alone until then.
    run_delivery_job(&app).await;
    let again = only_delivery(&app, &t, flaky).await;
    assert_eq!(again["attempts"], 1, "attempted before it was due");

    // Due: the job takes it, and the wait grows.
    let delivery_id = first["id"].as_str().unwrap();
    make_due(&app, delivery_id).await;
    run_delivery_job(&app).await;
    let second = only_delivery(&app, &t, flaky).await;
    assert_eq!(second["attempts"], 2, "{second}");
    assert_eq!(second["status"], "failed");
    let due: chrono::DateTime<chrono::Utc> =
        second["next_attempt_at"].as_str().unwrap().parse().unwrap();
    let wait = due - chrono::Utc::now();
    assert!(
        wait > chrono::Duration::seconds(90) && wait <= chrono::Duration::minutes(2),
        "second wait is {wait}, not the second backoff step"
    );

    // The last allowed attempt dead-letters it.
    make_due(&app, delivery_id).await;
    run_delivery_job(&app).await;
    let third = only_delivery(&app, &t, flaky).await;
    assert_eq!(third["attempts"], 3);
    assert_eq!(third["status"], "dead", "{third}");

    // 404: no amount of retrying helps, so the first attempt is the last one
    // even though five were allowed.
    let gone = hook(&app, &app.url("/_test/gone"), 5).await;
    ping(&app, gone);
    let d = only_delivery(&app, &t, gone).await;
    assert_eq!(d["status"], "dead", "{d}");
    assert_eq!(d["attempts"], 1);
    assert_eq!(d["last_status"], 404);
    assert!(
        d["last_error"].as_str().unwrap().contains("404"),
        "{}",
        d["last_error"]
    );
}
