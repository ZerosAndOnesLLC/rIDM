//! Download tickets (`POST /admin/download-tickets`) let a browser fetch an
//! export without the `Authorization` header, so they are a way in: each
//! must work once, for the one export `GET` it names, within a minute, and
//! only for someone who could make that request with their token.

use reqwest::Method;
use ridm_api::services::admin_access::{CLIENT_MANAGER_ROLE, USER_MANAGER_ROLE};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::common::TestApp;
use crate::common::admin::{admin_token, call};

async fn ticket(app: &TestApp, token: &str, path: &str) -> (reqwest::StatusCode, String) {
    let (status, body, _) = call(
        app,
        Method::POST,
        "/admin/download-tickets",
        Some(token),
        Some(&json!({ "path": path })),
    )
    .await;
    (status, body["url"].as_str().unwrap_or_default().to_string())
}

/// `GET url` with no credentials but the ticket in it.
async fn fetch(app: &TestApp, url: &str) -> reqwest::StatusCode {
    app.http.get(url).send().await.unwrap().status()
}

#[tokio::test]
async fn a_download_ticket_works_once_for_its_export() {
    let app = TestApp::spawn().await;
    let t = admin_token(&app, app.tenant.id, USER_MANAGER_ROLE).await;
    let path = format!("/admin/tenants/{}/users/export?format=csv", app.tenant.slug);
    let (status, url) = ticket(&app, &t, &path).await;
    assert_eq!(status, 201);
    assert!(url.contains("download_ticket="), "{url}");

    let res = app.http.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert!(
        res.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .contains(&format!("{}-users.csv", app.tenant.slug))
    );
    assert_eq!(fetch(&app, &url).await, 401, "a ticket works once");
}

#[tokio::test]
async fn a_download_ticket_opens_nothing_but_its_own_request() {
    let app = TestApp::spawn().await;
    let slug = app.tenant.slug.clone();
    let t = admin_token(&app, app.tenant.id, USER_MANAGER_ROLE).await;
    let path = format!("/admin/tenants/{slug}/users/export?format=csv");
    let ticket_of = |url: &str| url.split("download_ticket=").nth(1).unwrap().to_string();

    // Another query on the same export.
    let (_, url) = ticket(&app, &t, &path).await;
    let other = format!(
        "{}?format=json&download_ticket={}",
        app.url(&format!("/admin/tenants/{slug}/users/export")),
        ticket_of(&url)
    );
    assert_eq!(fetch(&app, &other).await, 401);
    // Tried once, it is gone even for the right request.
    assert_eq!(fetch(&app, &url).await, 401);

    // Another admin route altogether.
    let (_, url) = ticket(&app, &t, &path).await;
    let listing = format!(
        "{}?download_ticket={}",
        app.url(&format!("/admin/tenants/{slug}/users")),
        ticket_of(&url)
    );
    assert_eq!(fetch(&app, &listing).await, 401);

    // Anything but a GET.
    let (_, url) = ticket(&app, &t, &path).await;
    let res = app.http.post(&url).send().await.unwrap();
    assert!(
        res.status() == 401 || res.status() == 405,
        "{}",
        res.status()
    );
}

#[tokio::test]
async fn download_tickets_are_for_exports_the_caller_may_make() {
    let app = TestApp::spawn().await;
    let slug = app.tenant.slug.clone();
    let manager = admin_token(&app, app.tenant.id, USER_MANAGER_ROLE).await;
    for path in [
        format!("/admin/tenants/{slug}/users"),
        format!("/admin/tenants/{slug}/users/export/../../clients"),
        "https://evil.example/admin/audit/export".to_string(),
        format!("/admin/tenants/{slug}/users/export?download_ticket=x"),
    ] {
        let (status, _) = ticket(&app, &manager, &path).await;
        assert_eq!(status, 400, "{path}");
    }
    // A client manager reads the audit log but not the users.
    let clients = admin_token(&app, app.tenant.id, CLIENT_MANAGER_ROLE).await;
    let (status, _) = ticket(
        &app,
        &clients,
        &format!("/admin/tenants/{slug}/users/export"),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = ticket(
        &app,
        &clients,
        &format!("/admin/tenants/{slug}/audit/export"),
    )
    .await;
    assert_eq!(status, 201);
    // And only an administrator asks for one.
    let (status, _, _) = call(
        &app,
        Method::POST,
        "/admin/download-tickets",
        None,
        Some(&json!({ "path": format!("/admin/tenants/{slug}/audit/export") })),
    )
    .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn a_download_ticket_lives_a_minute_and_is_stored_only_by_its_hash() {
    let app = TestApp::spawn().await;
    let t = admin_token(&app, app.tenant.id, USER_MANAGER_ROLE).await;
    let path = format!("/admin/tenants/{}/audit/export", app.tenant.slug);
    let (_, url) = ticket(&app, &t, &path).await;
    let raw = url.split("download_ticket=").nth(1).unwrap();
    let mut conn = app.state.redis.get().await.unwrap();
    let key = format!("ridm:dlt:{}", hex::encode(Sha256::digest(raw.as_bytes())));
    let ttl: i64 = redis::cmd("TTL")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!((1..=60).contains(&ttl), "ttl {ttl}");
    let plain: bool = redis::cmd("EXISTS")
        .arg(format!("ridm:dlt:{raw}"))
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(!plain, "the ticket itself is never a key");
}
