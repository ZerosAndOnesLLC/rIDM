mod common;

use common::TestApp;
use ridm_api::util::security_txt::SecurityTxt;

#[tokio::test]
async fn healthz_reports_version() {
    let app = TestApp::spawn().await;
    let res = app.http.get(app.url("/healthz")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn readyz_checks_database_and_cache() {
    let app = TestApp::spawn().await;
    let res = app.http.get(app.url("/readyz")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["checks"]["database"], "ok");
    assert_eq!(body["checks"]["cache"], "ok");
}

/// A deployment answers for its own security, so there is no document until
/// the operator names a contact.
#[tokio::test]
async fn security_txt_is_absent_until_configured() {
    let app = TestApp::spawn().await;
    let res = app
        .http
        .get(app.url("/.well-known/security.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test]
async fn security_txt_serves_the_configured_contacts() {
    let app = TestApp::spawn_configured(axum::Router::new(), |state| {
        let mut config = (*state.config).clone();
        config.security_txt = SecurityTxt::from_settings(
            None,
            Some("mailto:security@acme.example".into()),
            Some("https://acme.example/disclosure".into()),
        )
        .unwrap();
        state.config = std::sync::Arc::new(config);
    })
    .await;
    let res = app
        .http
        .get(app.url("/.well-known/security.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["content-type"], "text/plain; charset=utf-8");
    let text = res.text().await.unwrap();
    assert!(text.starts_with("Contact: mailto:security@acme.example\nExpires: "));
    assert!(text.ends_with("Policy: https://acme.example/disclosure\n"));
}

#[tokio::test]
async fn each_test_app_gets_its_own_tenant() {
    let a = TestApp::spawn().await;
    let b = TestApp::spawn().await;
    assert_ne!(a.tenant.id, b.tenant.id);
    assert_ne!(a.tenant.slug, b.tenant.slug);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM tenants WHERE slug = $1")
        .bind(&a.tenant.slug)
        .fetch_one(&a.state.db)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

/// `ridm-api --healthcheck` dials the server's own bind address.
#[tokio::test]
async fn the_healthcheck_probe_reaches_the_server() {
    use ridm_api::healthcheck::{Target, probe};
    let app = TestApp::spawn().await;
    let addr: std::net::SocketAddr = url::Url::parse(&app.base_url)
        .unwrap()
        .socket_addrs(|| None)
        .unwrap()[0];
    let target = Target {
        addr,
        tls_cert: None,
    };
    probe(&target).await.unwrap();
    // Nothing listening there: unhealthy.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = closed.local_addr().unwrap();
    drop(closed);
    assert!(
        probe(&Target {
            addr: dead,
            tls_cert: None
        })
        .await
        .is_err()
    );
}
