//! Dashboard statistics: sign-ins and failures per day, live sessions,
//! second-factor adoption and the most authorized clients.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::TestApp;
use common::admin::{admin_token, call, user_with_role};
use reqwest::Method;
use ridm_api::db;
use ridm_api::models::{ClientType, MASTER_TENANT_ID, NewClient};
use ridm_api::repos;
use ridm_api::services::admin_access::{ADMIN_ROLE, VIEWER_ROLE};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::{clients, tenants};
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde_json::Value;

#[tokio::test]
async fn stats_reflect_attempts_sessions_and_authorizations() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let slug = app.tenant.slug.clone();
    let t = admin_token(&app, MASTER_TENANT_ID, ADMIN_ROLE).await;
    let user = user_with_role(&app, tid, None).await;

    let mut tx = db::tenant_tx(&app.state.db, tid).await.unwrap();
    for (ok, reason) in [
        (true, None),
        (true, None),
        (false, Some("invalid_credentials")),
    ] {
        repos::login_attempts::record(&mut *tx, tid, "someone", Some("127.0.0.1"), ok, reason)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    sessions::create(
        &app.state,
        tid,
        NewSession {
            user_id: user,
            amr: vec!["pwd".into()],
            acr: None,
            ip: None,
            user_agent: None,
            policy: &tenant.settings.session,
        },
    )
    .await
    .unwrap();
    let rp = clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("stats-rp".into()),
            name: "Stats RP".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://rp.example/cb".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .client;
    for _ in 0..2 {
        app.state.events.publish(Event::new(
            Some(tid),
            Actor::User { id: user },
            EventKind::AuthorizationGranted {
                user_id: user,
                client_id: rp.id,
                scopes: vec!["openid".into()],
            },
        ));
    }

    // The audit writer records asynchronously; wait for the authorizations.
    let mut body = Value::Null;
    for _ in 0..100 {
        let (status, b, _) = call(
            &app,
            Method::GET,
            &format!("/admin/tenants/{slug}/stats?days=7"),
            Some(&t),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{b}");
        body = b;
        if body["top_clients"][0]["authorizations"] == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(body["window_days"], 7);
    assert_eq!(body["days"].as_array().unwrap().len(), 7);
    assert_eq!(body["logins_total"], 2, "{body}");
    assert_eq!(body["failed_total"], 1);
    let today = body["days"].as_array().unwrap().last().unwrap();
    assert_eq!(today["logins"], 2);
    assert_eq!(today["failed"], 1);
    assert_eq!(body["active_sessions"], 1);
    assert_eq!(body["users"]["total"], 1);
    assert_eq!(body["users"]["active"], 1);
    assert_eq!(body["users"]["mfa_enrolled"], 0);
    assert_eq!(body["top_clients"][0]["client_id"], "stats-rp");
    assert_eq!(body["top_clients"][0]["authorizations"], 2, "{body}");

    // Window bounds and read access.
    let (status, _, _) = call(
        &app,
        Method::GET,
        &format!("/admin/tenants/{slug}/stats?days=0"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = call(
        &app,
        Method::GET,
        &format!("/admin/tenants/{slug}/stats?days=400"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let viewer = admin_token(&app, MASTER_TENANT_ID, VIEWER_ROLE).await;
    let (status, _, _) = call(
        &app,
        Method::GET,
        &format!("/admin/tenants/{slug}/stats"),
        Some(&viewer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
