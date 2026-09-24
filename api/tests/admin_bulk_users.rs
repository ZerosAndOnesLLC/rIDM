//! Phase 5.7: bulk user import (JSON and CSV, legacy hashes) and export.

mod common;

use common::TestApp;
use common::admin::{admin_token, get_json, user_with_role};
use ridm_api::models::{NewGroup, NewRole};
use ridm_api::services::admin_access::{
    ADMIN_ROLE, CLIENT_MANAGER_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE,
};
use ridm_api::services::password::{self, VerifyOutcome};
use ridm_api::services::{groups, roles, tenants, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use zeroize::Zeroizing;

async fn post_raw(
    app: &TestApp,
    path: &str,
    bearer: &str,
    content_type: &str,
    body: impl Into<reqwest::Body>,
) -> (u16, Value) {
    let res = app
        .http
        .post(app.url(path))
        .bearer_auth(bearer)
        .header("content-type", content_type)
        .body(body)
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn import_reports_per_row_and_export_round_trips() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    let base = format!("/admin/tenants/{}/users", app.tenant.slug);
    let t = admin_token(&app, tid, USER_MANAGER_ROLE).await;
    roles::create(
        &app.state,
        tid,
        Actor::System,
        NewRole {
            name: "editor".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let staff = groups::create(
        &app.state,
        tid,
        Actor::System,
        NewGroup {
            name: "staff".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    users::create(
        &app.state,
        tid,
        Actor::System,
        ridm_api::models::NewUser {
            username: "taken".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let legacy = bcrypt::hash("Legacy-Pass-123!", 4).unwrap();

    let rows = json!([
        {"username": "alice", "email": "alice@example.com", "email_verified": true, "password_hash": legacy, "roles": ["editor"], "groups": ["staff"]},
        {"username": "bob", "password": "Correct-Horse-Battery-9x!", "must_change_password": true},
        {"username": "taken"},
        {"username": "carol", "password": "short"},
        {"username": "dave", "roles": ["nope"]},
        {"username": "erin", "password_hash": "plain-text-no-format"},
        {"username": "has space"},
        {"username": "frank", "status": "locked"}
    ]);

    // Dry run: only validation, nothing written.
    let (status, dry) = post_raw(
        &app,
        &format!("{base}/import?dry_run=true"),
        &t,
        "application/json",
        rows.to_string(),
    )
    .await;
    assert_eq!(status, 200, "{dry}");
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["total"], 8);
    assert_eq!(dry["created"], 2, "{dry}");
    assert_eq!(dry["failed"], 6);
    assert!(
        users::find_by_identifier(&app.state, tid, "alice")
            .await
            .unwrap()
            .is_none()
    );

    // Real import.
    let (status, report) = post_raw(
        &app,
        &format!("{base}/import"),
        &t,
        "application/json",
        rows.to_string(),
    )
    .await;
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["created"], 2);
    assert_eq!(report["failed"], 6);
    let errors = report["errors"].as_array().unwrap();
    let error_for = |name: &str| -> String {
        errors
            .iter()
            .find(|e| e["username"] == name)
            .map(|e| e["error"].as_str().unwrap().to_string())
            .unwrap_or_else(|| panic!("no error for {name}: {report}"))
    };
    assert!(error_for("taken").contains("already in use"));
    assert!(error_for("carol").contains("password"));
    assert!(error_for("dave").contains("unknown role"));
    assert!(error_for("erin").contains("hash"));
    assert!(error_for("has space").contains("whitespace"));
    assert!(error_for("frank").contains("status"));
    assert_eq!(
        errors.iter().find(|e| e["username"] == "taken").unwrap()["row"],
        3
    );

    // Alice: legacy hash verifies (and upgrades), role and group applied.
    let alice = users::find_by_identifier(&app.state, tid, "alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alice.password_algo.as_deref(), Some("bcrypt"));
    assert!(matches!(
        password::verify_and_upgrade(
            &app.state,
            tid,
            &tenant.settings.password,
            &alice,
            Zeroizing::new("Legacy-Pass-123!".into())
        )
        .await
        .unwrap(),
        VerifyOutcome::Valid { .. }
    ));
    let (_, detail, _) = get_json(&app, &format!("{base}/{}", alice.id), Some(&t)).await;
    assert_eq!(detail["roles"][0]["name"], "editor");
    assert_eq!(detail["groups"][0]["id"], staff.id.to_string());
    let bob = users::find_by_identifier(&app.state, tid, "bob")
        .await
        .unwrap()
        .unwrap();
    assert!(bob.must_change_password && bob.has_password());

    // Re-import: everything now collides.
    let (_, again) = post_raw(
        &app,
        &format!("{base}/import"),
        &t,
        "application/json",
        json!([{"username": "alice"}, {"username": "bob"}]).to_string(),
    )
    .await;
    assert_eq!(again["created"], 0);
    assert_eq!(again["failed"], 2);

    // CSV.
    let csv = "username,email,email_verified,roles,groups,password_hash,must_change_password\n\
               grace,grace@example.com,true,editor,staff,,\n\
               heidi,,,,,$2b$04$invalidhashvalue,true\n";
    let (status, report) = post_raw(&app, &format!("{base}/import"), &t, "text/csv", csv).await;
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["created"], 2, "{report}");
    let grace = users::find_by_identifier(&app.state, tid, "grace")
        .await
        .unwrap()
        .unwrap();
    assert!(grace.email_verified);
    let (_, detail, _) = get_json(&app, &format!("{base}/{}", grace.id), Some(&t)).await;
    assert_eq!(detail["roles"][0]["name"], "editor");
    let (status, err) = post_raw(
        &app,
        &format!("{base}/import"),
        &t,
        "text/csv",
        "email,colour\nx@y.z,red\n",
    )
    .await;
    assert_eq!(status, 400, "{err}");
    let (status, err) = post_raw(&app, &format!("{base}/import"), &t, "text/plain", "x").await;
    assert_eq!(status, 400, "{err}");

    // Export: JSON and CSV carry every live user and no credentials.
    let res = app
        .http
        .get(app.url(&format!("{base}/export")))
        .bearer_auth(&t)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert!(
        res.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .contains("users.json")
    );
    let exported: Value = res.json().await.unwrap();
    let names: Vec<&str> = exported
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["username"].as_str().unwrap())
        .collect();
    for n in ["alice", "bob", "grace", "heidi", "taken"] {
        assert!(names.contains(&n), "{n} missing from {names:?}");
    }
    assert!(
        exported
            .as_array()
            .unwrap()
            .iter()
            .all(|u| u.get("password_hash").is_none())
    );
    let res = app
        .http
        .get(app.url(&format!("{base}/export?format=csv")))
        .bearer_auth(&t)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert!(
        res.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/csv")
    );
    let text = res.text().await.unwrap();
    let mut lines = text.lines();
    assert!(lines.next().unwrap().starts_with("id,username,email,"));
    let body: Vec<&str> = lines.collect();
    assert_eq!(body.len(), exported.as_array().unwrap().len());
    assert!(
        body.iter()
            .any(|l| l.contains(",alice,alice@example.com,true,"))
    );
}

#[tokio::test]
async fn import_and_export_follow_the_permission_model() {
    let app = TestApp::spawn().await;
    let base = format!("/admin/tenants/{}/users", app.tenant.slug);
    user_with_role(&app, app.tenant.id, None).await;
    for (role, import, export) in [
        (ADMIN_ROLE, 200, 200),
        (USER_MANAGER_ROLE, 200, 200),
        (CLIENT_MANAGER_ROLE, 403, 403),
        (VIEWER_ROLE, 403, 200),
    ] {
        let t = admin_token(&app, app.tenant.id, role).await;
        let (status, body) = post_raw(
            &app,
            &format!("{base}/import?dry_run=true"),
            &t,
            "application/json",
            "[]",
        )
        .await;
        assert_eq!(status, import, "{role} import: {body}");
        let (status, _, _) = get_json(&app, &format!("{base}/export"), Some(&t)).await;
        assert_eq!(status, export, "{role} export");
    }
}

/// An `editable_by: none` attribute is "set by imports or mappers": a bulk
/// import may set it, the interactive admin API (create and PATCH) may not.
#[tokio::test]
async fn an_import_sets_attributes_nobody_edits_interactively() {
    use ridm_api::models::{AttributeDef, EditableBy, ProfileSchema};
    use ridm_api::services::profile_schema;

    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    profile_schema::set(
        &app.state,
        tid,
        Actor::System,
        ProfileSchema {
            attributes: vec![AttributeDef {
                name: "employee_id".into(),
                editable_by: EditableBy::None,
                ..Default::default()
            }],
            allow_undeclared: false,
        },
    )
    .await
    .unwrap();
    let base = format!("/admin/tenants/{}/users", app.tenant.slug);
    let t = admin_token(&app, tid, USER_MANAGER_ROLE).await;

    let rows = json!([{"username": "imported", "attributes": {"employee_id": "E-1"}}]);
    let (status, report) = post_raw(
        &app,
        &format!("{base}/import"),
        &t,
        "application/json",
        rows.to_string(),
    )
    .await;
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    let user = users::find_by_identifier(&app.state, tid, "imported")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.attributes["employee_id"], "E-1");

    // The admin API itself still cannot set or change it.
    let (status, body) = post_raw(
        &app,
        &base,
        &t,
        "application/json",
        json!({"username": "direct", "attributes": {"employee_id": "E-2"}}).to_string(),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    let res = app
        .http
        .patch(app.url(&format!("{base}/{}", user.id)))
        .bearer_auth(&t)
        .json(&json!({"attributes": {"employee_id": "E-3"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn a_repeated_username_or_email_fails_the_later_row_whatever_the_timing() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let base = format!("/admin/tenants/{}/users", app.tenant.slug);
    let t = admin_token(&app, tid, USER_MANAGER_ROLE).await;
    let mut rows: Vec<serde_json::Value> = (0..12)
        .map(|i| json!({"username": format!("user{i}"), "email": format!("user{i}@example.com")}))
        .collect();
    rows.push(json!({"username": "User3"}));
    rows.push(json!({"username": "other", "email": "USER5@example.com"}));
    rows.push(json!({"username": "bad name"}));
    rows.push(json!({"username": "bad name2", "email": "user7@example.com"}));
    let body = serde_json::Value::Array(rows).to_string();

    for dry_run in [true, false] {
        let url = if dry_run {
            format!("{base}/import?dry_run=true")
        } else {
            format!("{base}/import")
        };
        let (status, report) = post_raw(&app, &url, &t, "application/json", body.clone()).await;
        assert_eq!(status, 200, "{report}");
        assert_eq!(report["created"], 12, "{report}");
        let errors: Vec<(u64, String)> = report["errors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["row"].as_u64().unwrap(),
                    e["error"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(errors.len(), 4, "{report}");
        assert_eq!(
            errors[0],
            (13, "username or email already used by row 4".into())
        );
        assert_eq!(
            errors[1],
            (14, "username or email already used by row 6".into())
        );
        // Invalid rows fail on their own errors, not as duplicates.
        assert_eq!(errors[2].0, 15);
        assert_eq!(errors[3].0, 16);
        assert_ne!(errors[3].1, "username or email already used by row 8");
    }
    assert!(
        users::find_by_identifier(&app.state, tid, "user11")
            .await
            .unwrap()
            .is_some()
    );
}
