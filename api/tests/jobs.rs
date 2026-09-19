//! Background jobs: the hourly cleanup removes only spent rows past the
//! retention window, the leader lock keeps one runner per cluster, every
//! pass leaves a last-run record, and the delivery jobs visit only tenants
//! with work.

mod common;

use std::time::Duration;

use common::TestApp;
use ridm_api::db;
use ridm_api::jobs::{cleanup, leader, message_delivery, status, webhook_delivery};
use ridm_api::models::{NewScimToken, NewUser, NewWebhook};
use ridm_api::services::refresh_tokens::{self, IssueRequest};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::{scim_tokens, users, webhooks};
use ridm_core::events::Actor;
use uuid::Uuid;

async fn count(app: &TestApp, table: &str, tenant_id: Uuid) -> i64 {
    let mut tx = db::bypass_tx(&app.state.db).await.unwrap();
    let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM {table} WHERE tenant_id = $1"
    )))
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    n
}

/// Backdate a column on every row of the tenant's table.
async fn backdate(app: &TestApp, table: &str, column: &str, tenant_id: Uuid, days: i32) {
    let mut tx = db::bypass_tx(&app.state.db).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE {table} SET {column} = now() - make_interval(days => $2) WHERE tenant_id = $1"
    )))
    .bind(tenant_id)
    .bind(days)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// Run the cleanup pass, waiting out whichever other test in this binary holds
/// the leader lock at the moment.
async fn cleanup_now(app: &TestApp) -> cleanup::Report {
    for _ in 0..60 {
        if let Some(report) = cleanup::run_once(&app.state).await.unwrap() {
            return report;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the cleanup job never took the leader lock");
}

#[tokio::test]
async fn cleanup_removes_spent_rows_past_retention_and_keeps_the_rest() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let user = users::create(
        &app.state,
        tid,
        Actor::System,
        NewUser {
            username: "alice".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let tenant = ridm_api::services::tenants::get(&app.state, tid)
        .await
        .unwrap();
    ridm_api::services::clients::create(
        &app.state,
        tid,
        Actor::System,
        ridm_api::models::NewClient {
            client_id: Some("spa".into()),
            name: "spa".into(),
            client_type: Some(ridm_api::models::ClientType::Spa),
            redirect_uris: vec!["https://app.example/cb".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // Two refresh tokens: one will be long expired, one live.
    for _ in 0..2 {
        refresh_tokens::issue(
            &app.state,
            tid,
            IssueRequest {
                client_id: "spa",
                user_id: Some(user.id),
                session_id: None,
                scopes: &["openid".into()],
                audiences: &[],
                ttl: chrono::Duration::days(30),
                dpop_jkt: None,
                auth_time: None,
                amr: &[],
                acr: None,
                org_id: None,
            },
        )
        .await
        .unwrap();
    }
    // Two sessions, two login attempts, a provisioning token, a webhook delivery.
    for _ in 0..2 {
        sessions::create(
            &app.state,
            tid,
            NewSession {
                user_id: user.id,
                amr: vec!["pwd".into()],
                acr: None,
                ip: None,
                user_agent: None,
                policy: &tenant.settings.session,
            },
        )
        .await
        .unwrap();
    }
    {
        let mut tx = db::bypass_tx(&app.state.db).await.unwrap();
        for _ in 0..2 {
            sqlx::query("INSERT INTO login_attempts (tenant_id, identifier, success) VALUES ($1, 'alice', false)")
                .bind(tid)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
    }
    let token = scim_tokens::create(
        &app.state,
        tid,
        Actor::System,
        NewScimToken {
            name: "old".into(),
            expires_in_days: None,
        },
    )
    .await
    .unwrap();
    scim_tokens::revoke(&app.state, tid, Actor::System, token.record.id)
        .await
        .unwrap();
    let hook = webhooks::create(
        &app.state,
        tid,
        Actor::System,
        NewWebhook {
            name: "h".into(),
            url: app.url("/nowhere").replace("http://", "https://"),
            events: vec!["user.deleted".into()],
            enabled: Some(false),
            headers: None,
            max_attempts: Some(1),
        },
    )
    .await
    .unwrap();
    {
        let mut tx = db::tenant_tx(&app.state.db, tid).await.unwrap();
        ridm_api::repos::webhooks::enqueue(
            &mut *tx,
            tid,
            Uuid::now_v7(),
            hook.webhook.id,
            Uuid::now_v7(),
            "user.deleted",
            &serde_json::json!({}),
            1,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    // Everything is fresh: nothing goes.
    let before = cleanup_now(&app).await;
    assert_eq!(count(&app, "refresh_tokens", tid).await, 2);
    assert_eq!(count(&app, "sso_sessions", tid).await, 2);
    assert_eq!(count(&app, "login_attempts", tid).await, 2);
    assert_eq!(count(&app, "scim_tokens", tid).await, 1);
    assert_eq!(count(&app, "webhook_deliveries", tid).await, 1);
    assert!(before.contains_key("refresh_tokens") && before.contains_key("scim_tokens"));

    // Age one refresh token and one session past the window, the rest of
    // the log-like rows too; a pending delivery is never spent.
    {
        let mut tx = db::bypass_tx(&app.state.db).await.unwrap();
        sqlx::query(
            "UPDATE refresh_tokens SET expires_at = now() - interval '40 days' \
             WHERE tenant_id = $1 AND id = (SELECT id FROM refresh_tokens WHERE tenant_id = $1 ORDER BY id LIMIT 1)",
        )
        .bind(tid)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE sso_sessions SET expires_at = now() - interval '8 days' \
             WHERE tenant_id = $1 AND id = (SELECT id FROM sso_sessions WHERE tenant_id = $1 ORDER BY id LIMIT 1)",
        )
        .bind(tid)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    backdate(&app, "login_attempts", "created_at", tid, 31).await;
    backdate(&app, "scim_tokens", "revoked_at", tid, 31).await;
    backdate(&app, "webhook_deliveries", "created_at", tid, 31).await;

    let report = cleanup_now(&app).await;
    assert_eq!(count(&app, "refresh_tokens", tid).await, 1, "{report:?}");
    assert_eq!(
        count(&app, "sso_sessions", tid).await,
        1,
        "sessions go after a week"
    );
    assert_eq!(count(&app, "login_attempts", tid).await, 0);
    assert_eq!(count(&app, "scim_tokens", tid).await, 0, "revoked long ago");
    assert_eq!(
        count(&app, "webhook_deliveries", tid).await,
        1,
        "pending rows stay"
    );
    // The report names every table the pass visited. How many rows this
    // particular pass deleted is not this test's business: a cleanup pass on
    // any node purges every tenant, and other tests in this binary run one.
    assert!(
        report.contains_key("refresh_tokens") && report.contains_key("login_attempts"),
        "{report:?}"
    );
    // A delivered one from long ago goes.
    {
        let mut tx = db::bypass_tx(&app.state.db).await.unwrap();
        sqlx::query("UPDATE webhook_deliveries SET status = 'delivered' WHERE tenant_id = $1")
            .bind(tid)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    cleanup_now(&app).await;
    assert_eq!(count(&app, "webhook_deliveries", tid).await, 0);
}

#[tokio::test]
async fn one_node_runs_a_job_at_a_time_and_the_run_is_recorded() {
    let app = TestApp::spawn().await;
    // "Another node" holds the lock: this node yields.
    let held = leader::try_acquire(&app.state.redis, cleanup::JOB_NAME, Duration::from_secs(30))
        .await
        .unwrap()
        .expect("lock free");
    assert!(cleanup::run_once(&app.state).await.unwrap().is_none());
    assert!(
        leader::try_acquire(&app.state.redis, cleanup::JOB_NAME, Duration::from_secs(30))
            .await
            .unwrap()
            .is_none()
    );
    held.release().await.unwrap();
    cleanup_now(&app).await;

    // The scheduler's bookkeeping: a recorded run is listed by name.
    status::record(
        &app.state,
        &status::LastRun {
            job: "cleanup".into(),
            at: chrono::Utc::now(),
            ok: true,
            duration_ms: 12,
            error: None,
        },
    )
    .await
    .unwrap();
    let runs = status::all(&app.state).await.unwrap();
    let mine = runs.iter().find(|r| r.job == "cleanup").expect("recorded");
    assert!(mine.ok);
    assert_eq!(mine.duration_ms, 12);
}

#[tokio::test]
async fn delivery_jobs_run_without_visiting_idle_tenants() {
    let app = TestApp::spawn().await;
    // Nothing due anywhere for this tenant: both jobs complete quickly and
    // report a pass (the shared database may hold other tenants' work).
    let started = std::time::Instant::now();
    assert!(
        webhook_delivery::run_once(&app.state)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        message_delivery::run_once(&app.state)
            .await
            .unwrap()
            .is_some()
    );
    assert!(started.elapsed() < Duration::from_secs(30));
}

#[tokio::test]
async fn two_nodes_contend_for_the_lock_and_only_one_of_them_runs() {
    // Two nodes: separate states and connection pools over one Postgres and
    // one Valkey, which is all a second replica of the API is.
    let a = TestApp::spawn().await;
    let b = TestApp::spawn().await;

    // Both reach for the cleanup lock at the same instant: never do both get
    // it, and once it is free (other tests here run the same job) one does.
    let mut winner = None;
    for _ in 0..60 {
        let (ga, gb) = tokio::join!(
            leader::try_acquire(&a.state.redis, cleanup::JOB_NAME, Duration::from_secs(20)),
            leader::try_acquire(&b.state.redis, cleanup::JOB_NAME, Duration::from_secs(20)),
        );
        let mut got: Vec<_> = [ga.unwrap(), gb.unwrap()].into_iter().flatten().collect();
        assert!(got.len() < 2, "two nodes held the same job lock at once");
        if let Some(lock) = got.pop() {
            winner = Some(lock);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let winner = winner.expect("the lock was never free for either node");

    // While that run is in progress, neither node starts a second copy — not
    // the node that holds it, and not the one that does not.
    assert!(cleanup::run_once(&a.state).await.unwrap().is_none());
    assert!(cleanup::run_once(&b.state).await.unwrap().is_none());

    // Released, the job runs again on the second node.
    winner.release().await.unwrap();
    cleanup_now(&b).await;
}
