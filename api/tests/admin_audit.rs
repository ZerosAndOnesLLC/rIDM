//! Phase 5.9: audit log — hash-chained rows, list/filter/export, verification,
//! the global chain and retention.

mod common;

use ridm_api::repos::audit_chains::Oldest;
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
    let mut tx = db::bypass_tx(app.state.db.home()).await.unwrap();
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

/// A burst far past the old 1,024-event bus buffer is recorded in full, in
/// one unbroken chain.
#[tokio::test]
async fn a_burst_of_events_is_recorded_without_gaps() {
    const BURST: u128 = 3_000;
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let t = admin_token(&app, tid, OWNER_ROLE).await;
    let base = format!("/admin/tenants/{}/audit", app.tenant.slug);
    for i in 0..BURST {
        app.state.events.publish(Event::new(
            Some(tid),
            Actor::System,
            EventKind::PersonalTokenRevoked {
                user_id: Uuid::nil(),
                token_id: Uuid::from_u128(i),
            },
        ));
    }
    let mut recorded = 0;
    for _ in 0..600 {
        let mut tx = db::bypass_tx(app.state.db.home()).await.unwrap();
        recorded = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM audit_events \
             WHERE tenant_id = $1 AND name = 'personal_token.revoked'",
        )
        .bind(tid)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        if recorded as u128 >= BURST {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(recorded as u128, BURST, "every event of the burst recorded");
    let (_, ok, _) = get_json(&app, &format!("{base}/verify"), Some(&t)).await;
    assert_eq!(ok["valid"], true, "{ok}");
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
            EventKind::PersonalTokenRevoked {
                user_id: Uuid::nil(),
                token_id: Uuid::from_u128(i),
            },
        ));
    }
    let page = wait_for(
        &app,
        &format!("{base}?name=personal_token.revoked"),
        &t,
        |p| p["items"].as_array().unwrap().len() >= 3,
    )
    .await;
    let survivor = page["items"][0]["id"].as_str().unwrap().to_string();
    let mut tx = db::bypass_tx(app.state.db.home()).await.unwrap();
    sqlx::query(
        "UPDATE audit_events SET occurred_at = now() - interval '3 days' \
         WHERE tenant_id = $1 AND name = 'personal_token.revoked' AND id <> $2",
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
    let (_, after, _) = get_json(
        &app,
        &format!("{base}?name=personal_token.revoked"),
        Some(&t),
    )
    .await;
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
    // The purge recorded where the chain now starts, so the job leaves it
    // alone until that row expires too.
    let chain = ridm_api::repos::audit::chain_id(Some(tid));
    let oldest = || async {
        let mut tx = db::bypass_tx(app.state.db.home()).await.unwrap();
        let all = ridm_api::repos::audit_chains::oldest_all(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        all.into_iter().find(|(c, _)| *c == chain).map(|(_, o)| o)
    };
    let day_ago = chrono::Utc::now() - chrono::Duration::days(1);
    assert!(
        matches!(oldest().await, Some(Oldest::At(at)) if at > day_ago),
        "{:?}",
        oldest().await
    );
    ridm_api::jobs::audit_retention::run_once(&app.state)
        .await
        .unwrap()
        .expect("ran");
    let (_, kept, _) = get_json(
        &app,
        &format!("{base}?name=personal_token.revoked"),
        Some(&t),
    )
    .await;
    assert_eq!(
        kept["items"].as_array().unwrap().len(),
        1,
        "nothing expired yet"
    );

    // Three days pass (for the rows and the chain's record alike): the job
    // purges the lot and records the chain as emptied.
    let mut tx = db::bypass_tx(app.state.db.home()).await.unwrap();
    sqlx::query(
        "UPDATE audit_events SET occurred_at = occurred_at - interval '3 days' WHERE tenant_id = $1",
    )
    .bind(tid)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE audit_chains SET oldest_at = oldest_at - interval '3 days' WHERE chain_id = $1",
    )
    .bind(chain)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let purged = ridm_api::jobs::audit_retention::run_once(&app.state)
        .await
        .unwrap()
        .expect("ran");
    assert!(purged >= 1, "{purged}");
    let (_, gone, _) = get_json(
        &app,
        &format!("{base}?name=personal_token.revoked"),
        Some(&t),
    )
    .await;
    assert!(gone["items"].as_array().unwrap().is_empty(), "{gone}");
    assert!(
        !matches!(oldest().await, Some(Oldest::At(at)) if at < day_ago),
        "{:?}",
        oldest().await
    );

    // Retention 0 keeps everything.
    assert_eq!(audit::purge(&app.state, Some(tid), 0).await.unwrap(), 0);
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

/// A one-shot command (`ridm bootstrap`, `ridm-api rotate-master-key`) runs no
/// background writer: what it publishes is recorded only because it flushes a
/// `CommandRecorder` before exiting.
#[tokio::test]
async fn a_command_records_what_it_published_before_it_exits() {
    let app = TestApp::spawn().await;
    // The state a command builds: a bus nothing else listens to.
    let mut state = app.state.clone();
    state.events = ridm_core::events::EventBus::default();

    let recorder = audit::CommandRecorder::start(&state);
    let token_id = Uuid::now_v7();
    state.events.publish(Event::new(
        Some(app.tenant.id),
        Actor::System,
        EventKind::PersonalTokenCreated {
            user_id: Uuid::now_v7(),
            token_id,
            scopes: vec!["ridm:users:read".into()],
        },
    ));
    let recorded = || async {
        let mut tx = db::bypass_tx(state.db.home()).await.unwrap();
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events \
             WHERE tenant_id = $1 AND name = 'personal_token.created' \
               AND payload->>'token_id' = $2",
        )
        .bind(app.tenant.id)
        .bind(token_id.to_string())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        n
    };
    assert_eq!(recorded().await, 0, "nothing writes before the flush");

    assert_eq!(recorder.flush(&state).await, 0);
    assert_eq!(recorded().await, 1);
}

/// Rows of the app's tenant chain, once the writer has caught up to `n`.
async fn chain_rows(app: &TestApp, n: i64) -> Vec<(i64, Uuid)> {
    for _ in 0..200 {
        let mut tx = db::bypass_tx(app.state.db.home()).await.unwrap();
        let rows: Vec<(i64, Uuid)> =
            sqlx::query_as("SELECT seq, id FROM audit_events WHERE tenant_id = $1 ORDER BY seq")
                .bind(app.tenant.id)
                .fetch_all(&mut *tx)
                .await
                .unwrap();
        tx.commit().await.unwrap();
        if rows.len() as i64 >= n {
            return rows;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the audit writer did not reach {n} rows");
}

fn tamper(id: Uuid) -> sqlx::query::Query<'static, sqlx::Postgres, sqlx::postgres::PgArguments> {
    sqlx::query("UPDATE audit_events SET payload = payload || '{\"tampered\": true}' WHERE id = $1")
        .bind(id)
}

#[tokio::test]
async fn the_scheduled_check_resumes_from_its_checkpoint_and_reports_a_break_once() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let t = admin_token(&app, tid, OWNER_ROLE).await;
    let base = format!("/admin/tenants/{}/audit", app.tenant.slug);
    // Wait until the writer has recorded everything the setup published.
    let mut rows = chain_rows(&app, 2).await;
    loop {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let now = chain_rows(&app, 2).await;
        if now.len() == rows.len() {
            break;
        }
        rows = now;
    }

    // First pass walks the whole chain and leaves a checkpoint.
    let first = audit::verify_chain(&app.state, Some(tid)).await.unwrap();
    assert!(first.checked >= rows.len() as u64, "{first:?}");
    assert_eq!(first.broken_at_seq, None);
    let (_, report, _) = get_json(&app, &format!("{base}/verify"), Some(&t)).await;
    assert_eq!(
        report["scheduled"]["verified_seq"].as_i64(),
        report["last_seq"].as_i64(),
        "{report}"
    );

    // Nothing new: the next pass only rechecks the checkpoint row.
    let again = audit::verify_chain(&app.state, Some(tid)).await.unwrap();
    assert_eq!(again.checked, 0, "{again:?}");

    // New rows are walked from the checkpoint on.
    user_with_role(&app, tid, None).await;
    let grown = chain_rows(&app, rows.len() as i64 + 1).await;
    let next = audit::verify_chain(&app.state, Some(tid)).await.unwrap();
    assert_eq!(next.checked, (grown.len() - rows.len()) as u64, "{next:?}");

    // A rewrite behind the checkpoint that reaches the checkpoint row is
    // caught, reported once, and shows on the verify endpoint.
    let (last_seq, last_id) = *grown.last().unwrap();
    let mut tx = db::bypass_tx(app.state.db.home()).await.unwrap();
    tamper(last_id).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let broken = audit::verify_chain(&app.state, Some(tid)).await.unwrap();
    assert_eq!(broken.broken_at_seq, Some(last_seq));
    let announced = wait_for(&app, &format!("{base}?name=audit.chain_broken"), &t, |p| {
        !p["items"].as_array().unwrap().is_empty()
    })
    .await;
    assert_eq!(announced["items"][0]["payload"]["seq"], last_seq);
    assert_eq!(announced["items"][0]["actor_type"], "system");
    let (_, report, _) = get_json(&app, &format!("{base}/verify"), Some(&t)).await;
    assert_eq!(report["valid"], false);
    assert_eq!(report["scheduled"]["broken_at_seq"], last_seq, "{report}");

    // Still broken on the next pass, but not announced again.
    let still = audit::verify_chain(&app.state, Some(tid)).await.unwrap();
    assert_eq!(still.broken_at_seq, Some(last_seq));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (_, page, _) = get_json(&app, &format!("{base}?name=audit.chain_broken"), Some(&t)).await;
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
}
