//! Review finding (Phase 10): webhook targets (and other URLs a tenant admin
//! or a client registration chooses) were checked for private IP literals
//! only, when saved. A hostname that resolves to this server's own network —
//! at save time or later, by DNS rebinding — was delivered to. Names are now
//! resolved through a filter at connect time; `localhost` alone keeps the
//! development allowance for loopback.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use reqwest::Method;
use ridm_api::services::admin_access::ADMIN_ROLE;
use serde_json::{Value, json};

use crate::common::TestApp;
use crate::common::admin::{admin_token, call};

/// A name other than `localhost` that resolves, offline, to loopback only
/// (from `/etc/hosts` or systemd-resolved, depending on the machine).
async fn loopback_alias() -> (String, SocketAddr) {
    for name in [
        "ip6-localhost",
        "ip6-loopback",
        "foo.localhost",
        "localhost.localdomain",
    ] {
        if let Ok(addrs) = tokio::net::lookup_host((name, 0)).await {
            let addrs: Vec<SocketAddr> = addrs.collect();
            if !addrs.is_empty() && addrs.iter().all(|a| a.ip().is_loopback()) {
                return (name.to_string(), addrs[0]);
            }
        }
    }
    panic!("no offline name resolves to loopback on this machine; add one to the list");
}

async fn webhook(app: &TestApp, bearer: &str, url: &str) -> Value {
    let base = format!("/admin/tenants/{}/webhooks", app.tenant.slug);
    let (status, created, _) = call(
        app,
        Method::POST,
        &base,
        Some(bearer),
        Some(&json!({"name": "hook", "url": url, "events": ["webhook.test"]})),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_str().unwrap();
    let (status, ping, _) = call(
        app,
        Method::POST,
        &format!("{base}/{id}/test"),
        Some(bearer),
        None,
    )
    .await;
    assert_eq!(status, 200, "{ping}");
    ping
}

#[tokio::test]
async fn a_webhook_name_resolving_to_loopback_is_refused_at_delivery() {
    let app = TestApp::spawn().await;
    let admin = admin_token(&app, app.tenant.id, ADMIN_ROLE).await;

    // Something listening where the name points, counting connections.
    let (name, addr) = loopback_alias().await;
    let listener = tokio::net::TcpListener::bind(SocketAddr::new(addr.ip(), 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });

    // Saved fine (it is not a literal), refused when it resolves.
    let ping = webhook(&app, &admin, &format!("https://{name}:{port}/hook")).await;
    assert_ne!(ping["status"], "delivered", "{ping}");
    let error = ping["last_error"].as_str().unwrap_or_default();
    assert!(
        error.contains("resolves only to private, loopback or reserved addresses"),
        "{ping}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0, "no connection was made");

    // Plain-http `localhost` keeps working for development, as before.
    let dev = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dev_port = dev.local_addr().unwrap().port();
    tokio::spawn(async move {
        let app = axum::Router::new().route("/hook", axum::routing::post(|| async { "ok" }));
        axum::serve(dev, app).await.unwrap();
    });
    let ping = webhook(&app, &admin, &format!("http://localhost:{dev_port}/hook")).await;
    assert_eq!(ping["status"], "delivered", "{ping}");
}

/// Review finding (Phase 10): a tenant's SMTP host is chosen by the tenant's
/// administrator but was connected to wherever it pointed, private networks
/// included. A private IP literal is now refused when saved, and a name is
/// resolved under the outbound policy right before each connection, which
/// then goes to the vetted address (TLS still verifies the configured name).
#[tokio::test]
async fn a_tenant_smtp_host_is_held_to_the_outbound_policy() {
    use ridm_api::messaging::SmtpEmailSender;
    use ridm_api::models::SmtpConfig;
    use ridm_core::providers::{EmailAddress, EmailMessage, EmailSender as _};

    let app = TestApp::spawn().await;
    let admin = admin_token(&app, app.tenant.id, ADMIN_ROLE).await;
    let (status, body, _) = call(
        &app,
        Method::PUT,
        &format!("/admin/tenants/{}/messaging/email", app.tenant.slug),
        Some(&admin),
        Some(&json!({
            "type": "smtp", "host": "10.0.0.5", "port": 25,
            "from": "noreply@example.com", "security": "none"
        })),
    )
    .await;
    assert_eq!(status, 400, "{body}");

    let counting_listener = |ip: std::net::IpAddr| async move {
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(ip, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            // Accept and hang up: enough to tell whether a connection came.
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        (port, hits)
    };
    let smtp = |host: &str, port: u16| SmtpConfig {
        host: host.into(),
        port,
        username: None,
        password: None,
        from: "noreply@example.com".into(),
        security: "none".into(),
    };
    let message = EmailMessage {
        to: vec![EmailAddress {
            email: "alice@example.com".into(),
            name: None,
        }],
        from: None,
        reply_to: None,
        subject: "hi".into(),
        text: "hi".into(),
        html: None,
        headers: vec![],
    };

    // A name other than `localhost` that resolves to loopback: refused
    // before any connection is made.
    let (name, addr) = loopback_alias().await;
    let (port, hits) = counting_listener(addr.ip()).await;
    let sender = SmtpEmailSender::for_tenant(&smtp(&name, port)).unwrap();
    let err = sender.send(&message).await.unwrap_err().to_string();
    assert!(
        err.contains("resolves only to private, loopback or reserved addresses"),
        "{err}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0, "no connection was made");

    // Private literals are refused outright, loopback literals and
    // `localhost` keep the development allowance.
    assert!(SmtpEmailSender::for_tenant(&smtp("192.168.1.10", 25)).is_err());
    assert!(SmtpEmailSender::for_tenant(&smtp("[fd00::1]", 25)).is_err());
    // The connection goes to the first address `localhost` resolves to.
    let first = tokio::net::lookup_host(("localhost", 0))
        .await
        .unwrap()
        .find(|a| a.ip().is_loopback())
        .unwrap()
        .ip();
    for (host, ip) in [("localhost".to_string(), first), (first.to_string(), first)] {
        let (port, hits) = counting_listener(ip).await;
        let sender = SmtpEmailSender::for_tenant(&smtp(&host, port)).unwrap();
        let err = sender.send(&message).await.unwrap_err().to_string();
        assert!(!err.contains("resolves only"), "{host}: {err}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "{host} was dialled");
    }

    // The operator's own relay (`SMTP_*`) is not held to the policy.
    assert!(SmtpEmailSender::new(&smtp("10.0.0.5", 25)).is_ok());
}
