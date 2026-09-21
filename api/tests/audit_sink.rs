//! Phase 12.5: the audit export sink ships from the database — signed HTTP
//! batches, syslog over UDP, TCP and TLS — and loses nothing while the
//! receiver is down.
//!
//! Which destination the sink serves, and how far it has shipped each chain,
//! is deployment-wide state, so these tests take turns ([`TURN`]). Every
//! receiver keeps only the rows of its own test's tenant: a pass ships every
//! chain with rows waiting.

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use common::TestApp;
use ridm_api::db;
use ridm_api::jobs::audit_sink::run_pass;
use ridm_api::models::NewUser;
use ridm_api::services::audit_sink::AuditSink;
use ridm_api::services::{users, webhooks};
use ridm_core::events::Actor;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader};
use uuid::Uuid;

static TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

type Inbox = Arc<Mutex<Vec<(HeaderMap, Value)>>>;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/audit-sink-tls")
        .join(name)
}

async fn app_with(sink: AuditSink) -> TestApp {
    TestApp::spawn_configured(Router::new(), move |state| state.audit_sink = Some(sink)).await
}

/// Create a user and wait for the audit writer to record it; returns the
/// user id, which is the row's `subject_id`.
async fn recorded_user(app: &TestApp, name: &str) -> Uuid {
    let user = users::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewUser {
            username: name.into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    for _ in 0..200 {
        let mut tx = db::bypass_tx(&app.state.db).await.unwrap();
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND subject_id = $2",
        )
        .bind(app.tenant.id)
        .bind(user.id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        if n > 0 {
            return user.id;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the audit writer never recorded {name}");
}

/// An HTTP receiver that fails while `down` is set.
async fn http_receiver(inbox: Inbox, down: Arc<AtomicBool>) -> url::Url {
    let app = Router::new().route(
        "/audit",
        post(move |headers: HeaderMap, body: axum::body::Bytes| {
            let inbox = inbox.clone();
            let down = down.clone();
            async move {
                if down.load(Ordering::SeqCst) {
                    return StatusCode::SERVICE_UNAVAILABLE;
                }
                let raw = String::from_utf8(body.to_vec()).unwrap();
                let batch: Vec<Value> = serde_json::from_str(&raw).unwrap();
                let mut h = headers.clone();
                // Keep the raw body next to the rows, for the signature.
                h.insert("x-test-body", raw.parse().unwrap());
                inbox
                    .lock()
                    .unwrap()
                    .extend(batch.into_iter().map(|r| (h.clone(), r)));
                StatusCode::ACCEPTED
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/audit").parse().unwrap()
}

fn mine(inbox: &Inbox, app: &TestApp) -> Vec<(HeaderMap, Value)> {
    inbox
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, r)| r["tenant_id"] == app.tenant.id.to_string())
        .cloned()
        .collect()
}

#[tokio::test]
async fn http_batches_are_signed_and_start_at_the_heads() {
    let _turn = TURN.lock().await;
    let inbox: Inbox = Arc::default();
    let url = http_receiver(inbox.clone(), Arc::default()).await;
    let sink = AuditSink::new(
        &url,
        Some("bearer-token".into()),
        Some("hmac-secret".into()),
        None,
    )
    .unwrap();
    let app = app_with(sink).await;

    // Recorded before this destination was ever served: not replayed.
    let before = recorded_user(&app, "before").await;
    run_pass(&app.state).await.unwrap();
    assert!(mine(&inbox, &app).is_empty());

    let after = recorded_user(&app, "after").await;
    let pass = run_pass(&app.state).await.unwrap();
    assert!(!pass.failed);
    let got = mine(&inbox, &app);
    assert!(
        got.iter()
            .all(|(_, r)| r["subject_id"] != before.to_string())
    );
    let (headers, row) = got
        .iter()
        .find(|(_, r)| r["subject_id"] == after.to_string())
        .expect("the new row was shipped");
    assert_eq!(row["name"], "user.created");
    assert!(row["hash"].as_str().is_some_and(|h| h.len() == 64));
    assert_eq!(headers["authorization"], "Bearer bearer-token");
    let signature = headers["x-ridm-signature"].to_str().unwrap();
    let t: i64 = signature
        .split(',')
        .next()
        .and_then(|p| p.strip_prefix("t="))
        .unwrap()
        .parse()
        .unwrap();
    let body = headers["x-test-body"].to_str().unwrap();
    assert_eq!(
        signature,
        webhooks::sign("hmac-secret", t, body.as_bytes()),
        "the receiver can check the batch came from rIDM"
    );

    // Shipped once: another pass sends nothing more of this tenant's.
    run_pass(&app.state).await.unwrap();
    assert_eq!(mine(&inbox, &app).len(), got.len());
}

#[tokio::test]
async fn nothing_is_lost_while_the_receiver_is_down() {
    let _turn = TURN.lock().await;
    let inbox: Inbox = Arc::default();
    let down = Arc::new(AtomicBool::new(false));
    let url = http_receiver(inbox.clone(), down.clone()).await;
    let app = app_with(AuditSink::new(&url, None, None, None).unwrap()).await;
    run_pass(&app.state).await.unwrap();

    down.store(true, Ordering::SeqCst);
    let first = recorded_user(&app, "during-1").await;
    let pass = run_pass(&app.state).await.unwrap();
    assert!(pass.failed, "the delivery failed");
    let second = recorded_user(&app, "during-2").await;
    assert!(run_pass(&app.state).await.unwrap().failed);
    assert!(mine(&inbox, &app).is_empty());

    // Back up: both rows arrive, in chain order, and only once.
    down.store(false, Ordering::SeqCst);
    for _ in 0..5 {
        if run_pass(&app.state).await.unwrap().shipped == 0 {
            break;
        }
    }
    let got: Vec<Value> = mine(&inbox, &app).into_iter().map(|(_, r)| r).collect();
    let pos = |id: Uuid| {
        got.iter()
            .position(|r| r["subject_id"] == id.to_string())
            .unwrap_or_else(|| panic!("{id} never arrived: {got:?}"))
    };
    assert!(pos(first) < pos(second));
    assert!(
        got.windows(2)
            .all(|w| w[0]["seq"].as_i64() < w[1]["seq"].as_i64())
    );
    let seqs: std::collections::BTreeSet<i64> =
        got.iter().map(|r| r["seq"].as_i64().unwrap()).collect();
    assert_eq!(seqs.len(), got.len(), "no row twice");
}

#[tokio::test]
async fn syslog_over_udp_carries_one_row_per_datagram() {
    let _turn = TURN.lock().await;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let url: url::Url = format!("syslog://127.0.0.1:{port}").parse().unwrap();
    let app = app_with(AuditSink::new(&url, None, None, None).unwrap()).await;
    run_pass(&app.state).await.unwrap();
    let id = recorded_user(&app, "udp").await;
    run_pass(&app.state).await.unwrap();
    let mut buf = vec![0u8; 65536];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .expect("a datagram in time")
            .unwrap();
        let line = String::from_utf8_lossy(&buf[..n]).into_owned();
        if line.contains(&id.to_string()) {
            assert!(line.starts_with("<134>1 "), "{line}");
            assert!(line.contains(" ridm - user.created - {"), "{line}");
            break;
        }
    }
}

#[tokio::test]
async fn syslog_over_tcp_is_one_row_per_line() {
    let _turn = TURN.lock().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink_lines = lines.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                sink_lines.lock().unwrap().push(line);
            }
        }
    });
    let url: url::Url = format!("syslog+tcp://127.0.0.1:{port}").parse().unwrap();
    let app = app_with(AuditSink::new(&url, None, None, None).unwrap()).await;
    run_pass(&app.state).await.unwrap();
    let id = recorded_user(&app, "tcp").await;
    run_pass(&app.state).await.unwrap();
    for _ in 0..100 {
        if lines
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains(&id.to_string()))
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no line for {id}");
}

#[tokio::test]
async fn syslog_over_tls_counts_octets_and_trusts_the_given_ca() {
    let _turn = TURN.lock().await;
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(fixture("server.pem"))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(fixture("server.key")).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink_received = received.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let into = sink_received.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    let mut buf = Vec::new();
                    let _ = tls.read_to_end(&mut buf).await;
                    into.lock().unwrap().extend(buf);
                }
            });
        }
    });

    let url: url::Url = format!("syslog+tls://localhost:{port}").parse().unwrap();
    // Without the CA the collector's certificate is not trusted.
    let untrusted = AuditSink::new(&url, None, None, None).unwrap();
    let app =
        app_with(AuditSink::new(&url, None, None, Some(fixture("ca.pem").as_path())).unwrap())
            .await;
    run_pass(&app.state).await.unwrap();
    let id = recorded_user(&app, "tls").await;
    let pass = run_pass(&app.state).await.unwrap();
    assert!(!pass.failed);

    let mut frames = vec![];
    for _ in 0..100 {
        let data = String::from_utf8(received.lock().unwrap().clone()).unwrap();
        // `<length> <message>` back to back.
        frames.clear();
        let mut rest = data.as_str();
        while let Some((len, tail)) = rest.split_once(' ') {
            let Ok(len) = len.parse::<usize>() else { break };
            if tail.len() < len {
                break;
            }
            frames.push(tail[..len].to_string());
            rest = &tail[len..];
        }
        if frames.iter().any(|f| f.contains(&id.to_string())) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        frames
            .iter()
            .any(|f| f.contains(&id.to_string()) && f.starts_with("<134>1 ")),
        "{frames:?}"
    );

    let row = ridm_api::models::AuditEvent {
        id: Uuid::nil(),
        tenant_id: None,
        seq: 1,
        occurred_at: chrono::Utc::now(),
        recorded_at: chrono::Utc::now(),
        name: "user.created".into(),
        actor_type: "system".into(),
        actor_id: None,
        subject_id: None,
        impersonator_id: None,
        ip: None,
        user_agent: None,
        payload: serde_json::json!({}),
        prev_hash: None,
        hash: vec![1],
    };
    assert!(untrusted.deliver(&[row]).await.is_err());
}

#[tokio::test]
async fn unsupported_schemes_and_empty_ca_files_are_refused() {
    let url: url::Url = "ftp://example.com/audit".parse().unwrap();
    assert!(AuditSink::new(&url, None, None, None).is_err());
    let empty = std::env::temp_dir().join(format!("ridm-empty-ca-{}.pem", Uuid::now_v7()));
    std::fs::write(&empty, "").unwrap();
    let url: url::Url = "syslog+tls://localhost:6514".parse().unwrap();
    assert!(AuditSink::new(&url, None, None, Some(empty.as_path())).is_err());
    let _ = std::fs::remove_file(empty);
}
