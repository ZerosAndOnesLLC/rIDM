//! Phase 5.9: audit log — hash-chained rows, list/filter/export, verification,
//! the global chain and retention.

mod common;

use std::time::Duration;

use common::admin::{TokenOpts, admin_token, call, get_json, token, user_with_role};
use common::{TestApp, create_tenant};
use reqwest::Method;
use ridm_api::db;
use ridm_api::models::MASTER_TENANT_ID;
use ridm_api::services::admin_access::{
    ADMIN_ROLE, CLIENT_MANAGER_ROLE, OWNER_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE,
};
use ridm_api::services::{audit, tenants};
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde_json::{Value, json};
use uuid::Uuid;

/// The writer is asynchronous: poll until `pred` holds for the listed page.
async fn wait_for(app: &TestApp, path: &str, bearer: &str, pred: impl Fn(&Value) -> bool) -> Value {
    for _ in 0..100 {
        let (status, body, _) = get_json(app, path, Some(bearer)).await;
        assert_eq!(status, 200, "{body}");
        if pred(&body) {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("audit rows did not appear in time at {path}");
}

fn has_event(page: &Value, name: &str, subject: &str) -> bool {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["name"] == name && e["subject_id"] == subject)
}

#[tokio::test]
async fn admin_actions_are_chained_listed_filtered_exported_and_verified() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    let admin_id = user_with_role(&app, tid, Some(ADMIN_ROLE)).await;
    let t = token(&app, &tenant, admin_id, TokenOpts::default()).await;
    let users = format!("/admin/tenants/{}/users", app.tenant.slug);
    let base = format!("/admin/tenants/{}/audit", app.tenant.slug);

    // Two admin actions on one user.
    let (status, created, _) = call(
        &app,
        Method::POST,
        &users,
        Some(&t),
        Some(&json!({"username": "audited"})),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let uid = created["id"].as_str().unwrap().to_string();
    let (status, _, _) = call(
        &app,
        Method::PATCH,
        &format!("{users}/{uid}"),
        Some(&t),
        Some(&json!({"locale": "fr"})),
    )
    .await;
    assert_eq!(status, 200);

    let page = wait_for(&app, &base, &t, |p| {
        has_event(p, "user.created", &uid) && has_event(p, "user.updated", &uid)
    })
    .await;
    let created_row = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "user.created" && e["subject_id"] == uid)
        .unwrap()
        .clone();
    assert_eq!(created_row["actor_type"], "admin");
    assert_eq!(created_row["actor_id"], admin_id.to_string());
    assert_eq!(created_row["tenant_id"], tid.to_string());
    assert_eq!(created_row["payload"]["type"], "user_created");
    assert_eq!(
        created_row["hash"].as_str().unwrap().len(),
        64,
        "sha-256 hex"
    );
    let seq = created_row["seq"].as_i64().unwrap();
    assert!(seq >= 1);
    // Newest first.
    let seqs: Vec<i64> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["seq"].as_i64().unwrap())
        .collect();
    assert!(seqs.windows(2).all(|w| w[0] > w[1]), "{seqs:?}");

    // Filters.
    let (_, exact, _) = get_json(&app, &format!("{base}?name=user.created"), Some(&t)).await;
    assert!(
        exact["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["name"] == "user.created")
    );
    let (_, prefix, _) = get_json(&app, &format!("{base}?name=user."), Some(&t)).await;
    assert!(
        prefix["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["name"].as_str().unwrap().starts_with("user."))
    );
    assert!(prefix["items"].as_array().unwrap().len() >= 2);
    let (_, by_actor, _) = get_json(&app, &format!("{base}?actor_id={admin_id}"), Some(&t)).await;
    assert!(by_actor["items"].as_array().unwrap().len() >= 2);
    assert!(
        by_actor["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["actor_id"] == admin_id.to_string())
    );
    let (_, by_subject, _) = get_json(&app, &format!("{base}?subject_id={uid}"), Some(&t)).await;
    assert_eq!(by_subject["items"].as_array().unwrap().len(), 2);
    let (_, none, _) = get_json(
        &app,
        &format!(
            "{base}?to={}",
            (chrono::Utc::now() - chrono::Duration::hours(1))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ),
        Some(&t),
    )
    .await;
    assert!(none["items"].as_array().unwrap().is_empty());
    // Per-user route: as actor or as subject.
    let (status, per_user, _) = get_json(&app, &format!("{users}/{uid}/audit"), Some(&t)).await;
    assert_eq!(status, 200, "{per_user}");
    assert_eq!(per_user["items"].as_array().unwrap().len(), 2);
    let (_, as_actor, _) = get_json(&app, &format!("{users}/{admin_id}/audit"), Some(&t)).await;
    assert!(as_actor["items"].as_array().unwrap().len() >= 2);

    // Pagination.
    let (_, first, _) = get_json(&app, &format!("{base}?limit=1"), Some(&t)).await;
    assert_eq!(first["items"].as_array().unwrap().len(), 1);
    let cursor = first["next_cursor"].as_str().unwrap();
    let (_, second, _) = get_json(&app, &format!("{base}?limit=1&cursor={cursor}"), Some(&t)).await;
    assert_ne!(second["items"][0]["id"], first["items"][0]["id"]);
    assert!(second["items"][0]["seq"].as_i64() < first["items"][0]["seq"].as_i64());

    // Verification and export.
    let (status, ok, _) = get_json(&app, &format!("{base}/verify"), Some(&t)).await;
    assert_eq!(status, 200, "{ok}");
    assert_eq!(ok["valid"], true);
    assert!(ok["checked"].as_u64().unwrap() >= 2);
    assert_eq!(ok["first_seq"], 1);
    let res = app
        .http
        .get(app.url(&format!("{base}/export?name=user.")))
        .bearer_auth(&t)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let exported: Value = res.json().await.unwrap();
    let rows = exported.as_array().unwrap();
    assert!(rows.len() >= 2);
    assert!(
        rows.windows(2)
            .all(|w| w[0]["seq"].as_i64() < w[1]["seq"].as_i64()),
        "oldest first"
    );
    let res = app
        .http
        .get(app.url(&format!("{base}/export?format=csv")))
        .bearer_auth(&t)
        .send()
        .await
        .unwrap();
    let csv = res.text().await.unwrap();
    assert!(csv.starts_with("seq,id,occurred_at,name,"));
    assert!(csv.contains("user.created"));

    // Tampering with a stored row breaks verification at that position.
    let mut tx = db::bypass_tx(&app.state.db).await.unwrap();
    sqlx::query(
        "UPDATE audit_events SET payload = payload || '{\"tampered\": true}' WHERE id = $1",
    )
    .bind(Uuid::parse_str(created_row["id"].as_str().unwrap()).unwrap())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (_, broken, _) = get_json(&app, &format!("{base}/verify"), Some(&t)).await;
    assert_eq!(broken["valid"], false, "{broken}");
    assert_eq!(broken["broken_at_seq"], seq);
    assert!(broken["reason"].as_str().unwrap().contains("hash"));
}

#[tokio::test]
async fn global_chain_is_for_global_admins_only() {
    let app = TestApp::spawn().await;
    let tenant_owner = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let global = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;
    app.state.events.publish(Event::new(
        None,
        Actor::System,
        EventKind::MasterKeyRotated { new_version: 7 },
    ));
    let (status, _, _) = get_json(&app, "/admin/audit", Some(&tenant_owner)).await;
    assert_eq!(status, 403);
    let page = wait_for(&app, "/admin/audit?name=master_key.rotated", &global, |p| {
        p["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["payload"]["new_version"] == 7)
    })
    .await;
    let row = &page["items"][0];
    assert!(row["tenant_id"].is_null());
    assert_eq!(row["actor_type"], "system");
    let (status, ok, _) = get_json(&app, "/admin/audit/verify", Some(&global)).await;
    assert_eq!(status, 200, "{ok}");
    assert_eq!(ok["valid"], true);
    // Global rows never show up in a tenant's log.
    let (_, tenant_page, _) = get_json(
        &app,
        &format!(
            "/admin/tenants/{}/audit?name=master_key.rotated",
            app.tenant.slug
        ),
        Some(&tenant_owner),
    )
    .await;
    assert!(tenant_page["items"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn retention_purges_old_rows_and_the_chain_still_verifies() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let t = admin_token(&app, tid, OWNER_ROLE).await;
    let slug = app.tenant.slug.clone();
    let base = format!("/admin/tenants/{slug}/audit");

    // Retention is a tenant setting.
    let (status, patched, _) = call(
        &app,
        Method::PATCH,
        &format!("/admin/tenants/{slug}"),
        Some(&t),
        Some(&json!({"settings": {"audit": {"retention_days": 1}}})),
    )
    .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["settings"]["audit"]["retention_days"], 1);

    // Three events; the oldest two are pushed back in time (into the
    // default partition) and purged; the chain from the survivor still verifies.
    for i in 0..3 {
        app.state.events.publish(Event::new(
            Some(tid),
            Actor::System,
            EventKind::CacheInvalidate {
                entity: "test".into(),
                id: i.to_string(),
            },
        ));
    }
    let page = wait_for(&app, &format!("{base}?name=cache.invalidate"), &t, |p| {
        p["items"].as_array().unwrap().len() >= 3
    })
    .await;
    let survivor = page["items"][0]["id"].as_str().unwrap().to_string();
    let mut tx = db::bypass_tx(&app.state.db).await.unwrap();
    sqlx::query(
        "UPDATE audit_events SET occurred_at = now() - interval '3 days' \
         WHERE tenant_id = $1 AND name = 'cache.invalidate' AND id <> $2",
    )
    .bind(tid)
    .bind(Uuid::parse_str(&survivor).unwrap())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let tenant = tenants::get(&app.state, tid).await.unwrap();
    let purged = audit::purge(&app.state, Some(tid), tenant.settings.audit.retention_days)
        .await
        .unwrap();
    assert!(purged >= 2, "{purged}");
    let (_, after, _) = get_json(&app, &format!("{base}?name=cache.invalidate"), Some(&t)).await;
    let ids: Vec<&str> = after["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![survivor.as_str()]);
    let (_, ok, _) = get_json(&app, &format!("{base}/verify"), Some(&t)).await;
    assert_eq!(ok["valid"], true, "{ok}");
    assert!(
        ok["first_seq"].as_i64().unwrap() > 1,
        "oldest rows are gone"
    );
    // Retention 0 keeps everything; the job itself runs under its lock.
    assert_eq!(audit::purge(&app.state, Some(tid), 0).await.unwrap(), 0);
    assert!(
        ridm_api::jobs::audit_retention::run_once(&app.state)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn every_built_in_role_reads_the_audit_log_of_its_own_tenant() {
    let app = TestApp::spawn().await;
    let other = create_tenant(&app.state.db).await;
    let base = format!("/admin/tenants/{}/audit", app.tenant.slug);
    for role in [
        OWNER_ROLE,
        ADMIN_ROLE,
        USER_MANAGER_ROLE,
        CLIENT_MANAGER_ROLE,
        VIEWER_ROLE,
    ] {
        let t = admin_token(&app, app.tenant.id, role).await;
        let (status, body, _) = get_json(&app, &base, Some(&t)).await;
        assert_eq!(status, 200, "{role}: {body}");
        let (status, _, _) = get_json(&app, &format!("{base}/verify"), Some(&t)).await;
        assert_eq!(status, 200, "{role} verify");
        let (status, _, _) = get_json(
            &app,
            &format!("/admin/tenants/{}/audit", other.slug),
            Some(&t),
        )
        .await;
        assert_eq!(status, 403, "{role} other tenant");
        let (status, _, _) = get_json(&app, "/admin/audit", Some(&t)).await;
        assert_eq!(status, 403, "{role} global");
    }
    let (status, _, _) = get_json(&app, &base, None).await;
    assert_eq!(status, 401);
    let global = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/audit", other.slug),
        Some(&global),
    )
    .await;
    assert_eq!(status, 200);
}
