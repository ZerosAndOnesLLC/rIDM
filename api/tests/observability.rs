//! Metrics exposition and the audit export sink.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::post;
use common::TestApp;
use ridm_api::models::NewUser;
use ridm_api::services::audit_sink::AuditSink;
use ridm_api::services::users;
use ridm_api::util::secret::SecretString;
use ridm_core::events::Actor;
use serde_json::Value;

#[tokio::test]
async fn metrics_expose_requests_tokens_and_logins() {
    let app = TestApp::spawn().await;
    // A token request (refused) and a discovery fetch leave their marks.
    app.http
        .post(app.tenant_url("/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "nobody"),
        ])
        .send()
        .await
        .unwrap();
    app.http
        .get(app.tenant_url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap();
    let res = app.http.get(app.url("/metrics")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert!(
        res.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let body = res.text().await.unwrap();
    assert!(body.contains("ridm_http_requests_total{"), "{body}");
    assert!(body.contains("route=\"/t/{slug}/token\""), "{body}");
    assert!(
        body.contains("ridm_http_request_duration_seconds_bucket"),
        "{body}"
    );
    assert!(body.contains("ridm_token_requests_total{"), "{body}");
    assert!(body.contains("outcome=\"invalid_client\""), "{body}");
}

#[tokio::test]
async fn metrics_can_demand_a_token() {
    let app = TestApp::spawn_configured(axum::Router::new(), |state| {
        let mut config = (*state.config).clone();
        config.metrics_token = Some(SecretString::new("scrape-me".into()));
        state.config = Arc::new(config);
    })
    .await;
    let res = app.http.get(app.url("/metrics")).send().await.unwrap();
    assert_eq!(res.status(), 401);
    assert!(
        res.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("metrics")
    );
    let res = app
        .http
        .get(app.url("/metrics"))
        .bearer_auth("wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let res = app
        .http
        .get(app.url("/metrics"))
        .bearer_auth("scrape-me")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

type Inbox = Arc<Mutex<Vec<Value>>>;

/// A standalone HTTP receiver, started before the app so the sink URL is
/// known when the app's audit writer is spawned.
async fn http_receiver(inbox: Inbox) -> String {
    let app = Router::new().route(
        "/audit",
        post(
            move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                let inbox = inbox.clone();
                async move {
                    if headers.get("authorization").map(|v| v.as_bytes())
                        != Some(b"Bearer sink-secret")
                    {
                        return StatusCode::UNAUTHORIZED;
                    }
                    let batch: Vec<Value> = serde_json::from_slice(&body).unwrap();
                    inbox.lock().unwrap().extend(batch);
                    StatusCode::ACCEPTED
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/audit")
}

#[tokio::test]
async fn audit_rows_are_shipped_to_an_http_sink_in_batches() {
    let inbox: Inbox = Arc::default();
    let url: url::Url = http_receiver(inbox.clone()).await.parse().unwrap();
    let app = TestApp::spawn_configured(axum::Router::new(), move |state| {
        state.audit_sink = Some(AuditSink::spawn(&url, Some("sink-secret".into())).unwrap());
    })
    .await;
    let user = users::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewUser {
            username: "shipped".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let got = inbox.lock().unwrap().clone();
        if let Some(row) = got
            .iter()
            .find(|r| r["name"] == "user.created" && r["subject_id"] == user.id.to_string())
        {
            assert_eq!(row["tenant_id"], app.tenant.id.to_string());
            assert!(row["seq"].as_i64().unwrap() >= 1, "{row}");
            assert!(row.get("hash").is_some(), "{row}");
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "row never reached the sink: {got:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn audit_rows_are_shipped_as_syslog_datagrams() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let url: url::Url = format!("syslog://127.0.0.1:{port}").parse().unwrap();
    let app = TestApp::spawn_configured(axum::Router::new(), move |state| {
        state.audit_sink = Some(AuditSink::spawn(&url, None).unwrap());
    })
    .await;
    users::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewUser {
            username: "syslogged".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 65536];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let n = tokio::time::timeout_at(deadline, socket.recv(&mut buf))
            .await
            .expect("a datagram in time")
            .unwrap();
        let line = String::from_utf8_lossy(&buf[..n]).into_owned();
        if line.contains("user.created") {
            assert!(line.starts_with("<134>1 "), "{line}");
            assert!(line.contains(" ridm - user.created - {"), "{line}");
            break;
        }
    }
}

#[tokio::test]
async fn unsupported_sink_schemes_are_refused() {
    let url: url::Url = "ftp://example.com/audit".parse().unwrap();
    assert!(AuditSink::spawn(&url, None).is_err());
}
