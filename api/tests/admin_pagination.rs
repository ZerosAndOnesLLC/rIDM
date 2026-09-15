//! Phase 5.13: cursor pagination is stable — walking every page yields each
//! item exactly once, even while rows are inserted in the middle of the walk.

mod common;

use std::collections::BTreeSet;

use common::TestApp;
use common::admin::{admin_token, call, get_json};
use reqwest::Method;
use ridm_api::services::admin_access::ADMIN_ROLE;
use serde_json::{Value, json};

async fn walk(
    app: &TestApp,
    base: &str,
    key: &str,
    t: &str,
    insert_midway: impl Fn(usize) -> Option<Value>,
) -> Vec<String> {
    let mut seen = vec![];
    let mut cursor: Option<String> = None;
    let mut page_no = 0;
    loop {
        let path = match &cursor {
            Some(c) => format!("{base}?limit=3&cursor={c}"),
            None => format!("{base}?limit=3"),
        };
        let (status, page, _) = get_json(app, &path, Some(t)).await;
        assert_eq!(status, 200, "{page}");
        for item in page["items"].as_array().unwrap() {
            seen.push(item[key].as_str().unwrap().to_string());
        }
        if let Some(body) = insert_midway(page_no) {
            let (status, created, _) = call(app, Method::POST, base, Some(t), Some(&body)).await;
            assert_eq!(status, 201, "{created}");
        }
        page_no += 1;
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
        assert!(page_no < 100, "runaway pagination");
    }
    seen
}

#[tokio::test]
async fn user_and_client_listings_page_without_gaps_or_repeats() {
    let app = TestApp::spawn().await;
    let t = admin_token(&app, app.tenant.id, ADMIN_ROLE).await;
    let users = format!("/admin/tenants/{}/users", app.tenant.slug);
    let clients = format!("/admin/tenants/{}/clients", app.tenant.slug);
    for i in 0..10 {
        call(
            &app,
            Method::POST,
            &users,
            Some(&t),
            Some(&json!({"username": format!("pg-{i}")})),
        )
        .await;
        call(
            &app,
            Method::POST,
            &clients,
            Some(&t),
            Some(&json!({"name": format!("pg-{i}"), "client_type": "machine"})),
        )
        .await;
    }

    // A row inserted while paging shows up at the end, never twice, never lost.
    let seen = walk(&app, &users, "username", &t, |page| {
        (page == 1).then(|| json!({"username": "pg-late"}))
    })
    .await;
    let unique: BTreeSet<&String> = seen.iter().collect();
    assert_eq!(unique.len(), seen.len(), "duplicates: {seen:?}");
    for i in 0..10 {
        assert!(seen.contains(&format!("pg-{i}")), "pg-{i} missing");
    }
    assert_eq!(seen.last().map(String::as_str), Some("pg-late"));
    assert!(seen.len() >= 12, "{seen:?}");

    let seen = walk(&app, &clients, "name", &t, |page| {
        (page == 2).then(|| json!({"name": "pg-late", "client_type": "machine"}))
    })
    .await;
    let unique: BTreeSet<&String> = seen.iter().collect();
    assert_eq!(unique.len(), seen.len(), "duplicates: {seen:?}");
    assert!(seen.iter().filter(|n| n.starts_with("pg-")).count() >= 11);

    // Cursors are opaque and validated.
    let (status, err, _) = get_json(&app, &format!("{users}?cursor=not-a-cursor"), Some(&t)).await;
    assert_eq!(status, 400, "{err}");
    // A page size above the maximum is clamped, not rejected.
    let (status, page, _) = get_json(&app, &format!("{users}?limit=100000"), Some(&t)).await;
    assert_eq!(status, 200, "{page}");
}
