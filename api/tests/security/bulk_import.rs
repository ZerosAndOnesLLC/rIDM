//! Review finding (Phase 10): `POST .../users/import` assigned the roles and
//! groups named in each row without the no-escalation check the
//! single-assignment routes make, so a user manager could import an account
//! holding `ridm:owner` (or a member of a group that grants it). Rows that
//! would grant permissions the importer lacks are now refused, dry run too.

use ridm_api::models::{NewGroup, Principal};
use ridm_api::services::admin_access::{OWNER_ROLE, USER_MANAGER_ROLE};
use ridm_api::services::{groups, roles, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};

use crate::common::TestApp;
use crate::common::admin::{admin_token, role_id};

async fn import(app: &TestApp, bearer: &str, rows: &Value, dry_run: bool) -> (u16, Value) {
    let res = app
        .http
        .post(app.url(&format!(
            "/admin/tenants/{}/users/import?dry_run={dry_run}",
            app.tenant.slug
        )))
        .bearer_auth(bearer)
        .json(rows)
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

fn failed_rows(report: &Value) -> Vec<u64> {
    report["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["row"].as_u64().unwrap())
        .collect()
}

#[tokio::test]
async fn a_user_manager_cannot_import_an_owner() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let owners = groups::create(
        &app.state,
        tid,
        Actor::System,
        NewGroup {
            name: "owners".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    roles::assign(
        &app.state,
        tid,
        Actor::System,
        role_id(&app, tid, OWNER_ROLE).await,
        Principal::Group { id: owners.id },
    )
    .await
    .unwrap();
    let manager = admin_token(&app, tid, USER_MANAGER_ROLE).await;
    let rows = json!([
        {"username": "eve", "roles": [OWNER_ROLE]},
        {"username": "mallory", "groups": ["owners"]},
        {"username": "plain"},
    ]);

    // The dry run already reports the escalation.
    let (status, report) = import(&app, &manager, &rows, true).await;
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["failed"], 2, "{report}");
    assert_eq!(failed_rows(&report), vec![1, 2]);
    for e in report["errors"].as_array().unwrap() {
        assert!(
            e["error"]
                .as_str()
                .unwrap()
                .contains("cannot grant permissions you do not hold"),
            "{e}"
        );
    }

    let (status, report) = import(&app, &manager, &rows, false).await;
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["created"], 1, "{report}");
    assert_eq!(failed_rows(&report), vec![1, 2]);
    for name in ["eve", "mallory"] {
        assert!(
            users::find_by_identifier(&app.state, tid, name)
                .await
                .unwrap()
                .is_none(),
            "{name} must not exist"
        );
    }
    assert!(
        users::find_by_identifier(&app.state, tid, "plain")
            .await
            .unwrap()
            .is_some()
    );

    // An owner may grant what they hold.
    let owner = admin_token(&app, tid, OWNER_ROLE).await;
    let (status, report) = import(
        &app,
        &owner,
        &json!([{"username": "eve", "roles": [OWNER_ROLE]}, {"username": "mallory", "groups": ["owners"]}]),
        false,
    )
    .await;
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["created"], 2, "{report}");
}
