mod common;

use common::TestApp;
use ridm_api::models::{NewUser, SessionPolicy, TenantSettings};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::{trusted_devices, users};
use ridm_core::events::Actor;
use uuid::Uuid;

async fn fixture(policy: SessionPolicy) -> (TestApp, ridm_api::models::Tenant, Uuid) {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let tenant = tenants::update(
        &app.state,
        Actor::System,
        tid,
        TenantUpdate {
            settings: Some(TenantSettings {
                session: policy,
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
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
    (app, tenant, user.id)
}

/// Polls until the session is gone (true) or 5 s pass (false): the
/// timeouts are whole seconds, so a fixed sleep would only guess.
async fn gone_within<F, Fut>(lookup: F) -> bool
where
    F: Fn() -> Fut,
    Fut: std::future::Future<
            Output = ridm_api::error::AppResult<Option<ridm_api::services::sessions::SsoSession>>,
        >,
{
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if lookup().await.unwrap().is_none() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    false
}

fn new_session<'a>(uid: Uuid, policy: &'a SessionPolicy) -> NewSession<'a> {
    NewSession {
        user_id: uid,
        amr: vec!["pwd".into()],
        acr: None,
        ip: Some("10.0.0.1".into()),
        user_agent: Some("UA".into()),
        device_id: None,
        policy,
    }
}

#[tokio::test]
async fn max_concurrent_sessions_revokes_the_oldest() {
    let (app, tenant, uid) = fixture(SessionPolicy {
        max_concurrent: 2,
        ..Default::default()
    })
    .await;
    let p = &tenant.settings.session;
    let s1 = sessions::create(&app.state, tenant.id, new_session(uid, p))
        .await
        .unwrap();
    let s2 = sessions::create(&app.state, tenant.id, new_session(uid, p))
        .await
        .unwrap();
    assert_eq!(
        sessions::list_live_for_user(&app.state, tenant.id, uid)
            .await
            .unwrap()
            .len(),
        2
    );
    let s3 = sessions::create(&app.state, tenant.id, new_session(uid, p))
        .await
        .unwrap();
    let live: Vec<Uuid> = sessions::list_live_for_user(&app.state, tenant.id, uid)
        .await
        .unwrap()
        .iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(live, vec![s2.id, s3.id], "oldest revoked, order preserved");
    assert!(
        sessions::get(&app.state, tenant.id, s1.id, p)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        sessions::get(&app.state, tenant.id, s2.id, p)
            .await
            .unwrap()
            .is_some()
    );
    // Mirror rows carry the revocation and metadata.
    let mut tx = ridm_api::db::tenant_tx(&app.state.db, tenant.id)
        .await
        .unwrap();
    let (revoked, ip): (Option<chrono::DateTime<chrono::Utc>>, Option<String>) =
        sqlx::query_as("SELECT revoked_at, ip FROM sso_sessions WHERE id = $1")
            .bind(s1.id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert!(revoked.is_some());
    assert_eq!(ip.as_deref(), Some("10.0.0.1"));
    // Sign out everywhere.
    assert_eq!(
        ridm_api::services::logout::end_sessions_for_user(&app.state, &tenant, uid, None)
            .await
            .unwrap(),
        2
    );
    assert!(
        sessions::list_live_for_user(&app.state, tenant.id, uid)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        sessions::get(&app.state, tenant.id, s3.id, p)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn idle_and_absolute_timeouts_end_sessions() {
    let (app, tenant, uid) = fixture(SessionPolicy {
        idle_timeout_secs: 1,
        absolute_timeout_secs: 3600,
        ..Default::default()
    })
    .await;
    let p = &tenant.settings.session;
    let s = sessions::create(&app.state, tenant.id, new_session(uid, p))
        .await
        .unwrap();
    assert!((s.idle_expires_at - s.created_at).num_seconds() <= 1);
    assert!(
        sessions::get(&app.state, tenant.id, s.id, p)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        gone_within(|| sessions::get(&app.state, tenant.id, s.id, p)).await,
        "idle timeout"
    );
    assert!(
        sessions::list_live_for_user(&app.state, tenant.id, uid)
            .await
            .unwrap()
            .is_empty()
    );

    // Absolute timeout shorter than idle: expires regardless of activity.
    let (app2, tenant2, uid2) = fixture(SessionPolicy {
        idle_timeout_secs: 3600,
        absolute_timeout_secs: 1,
        ..Default::default()
    })
    .await;
    let p2 = &tenant2.settings.session;
    let s = sessions::create(&app2.state, tenant2.id, new_session(uid2, p2))
        .await
        .unwrap();
    assert!(
        sessions::get(&app2.state, tenant2.id, s.id, p2)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        gone_within(|| sessions::get(&app2.state, tenant2.id, s.id, p2)).await,
        "absolute timeout"
    );
}

#[tokio::test]
async fn trusted_devices_round_trip() {
    let (app, tenant, uid) = fixture(SessionPolicy {
        remember_device_days: 30,
        ..Default::default()
    })
    .await;
    let other = users::create(
        &app.state,
        tenant.id,
        Actor::System,
        NewUser {
            username: "bob".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (device, secret) = trusted_devices::trust(
        &app.state,
        &tenant,
        uid,
        Some("Laptop"),
        Some("UA"),
        Some("10.0.0.1"),
    )
    .await
    .unwrap();
    assert!(device.is_live(chrono::Utc::now()));
    assert!((device.expires_at - chrono::Utc::now()).num_days() >= 29);
    let cookie = trusted_devices::set_cookie_header(&app.state, &tenant, &secret, 30);
    assert!(
        cookie.starts_with(&format!("ridm_device_{}=", tenant.slug)) && cookie.contains("HttpOnly")
    );

    let mut headers = axum::http::HeaderMap::new();
    headers.insert("cookie", cookie.split(';').next().unwrap().parse().unwrap());
    assert!(
        trusted_devices::is_trusted(&app.state, &tenant, uid, &headers, Some("10.0.0.2"))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        trusted_devices::is_trusted(&app.state, &tenant, other.id, &headers, None)
            .await
            .unwrap()
            .is_none(),
        "bound to the user"
    );
    let mut bogus = axum::http::HeaderMap::new();
    bogus.insert(
        "cookie",
        format!("ridm_device_{}=nope", tenant.slug).parse().unwrap(),
    );
    assert!(
        trusted_devices::is_trusted(&app.state, &tenant, uid, &bogus, None)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        trusted_devices::is_trusted(
            &app.state,
            &tenant,
            uid,
            &axum::http::HeaderMap::new(),
            None
        )
        .await
        .unwrap()
        .is_none()
    );

    let listed = trusted_devices::list(&app.state, tenant.id, uid)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0].ip.as_deref(),
        Some("10.0.0.2"),
        "last seen ip updated"
    );
    assert!(
        trusted_devices::revoke(&app.state, tenant.id, Actor::System, uid, device.id)
            .await
            .unwrap()
    );
    assert!(
        trusted_devices::is_trusted(&app.state, &tenant, uid, &headers, None)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        trusted_devices::list(&app.state, tenant.id, uid)
            .await
            .unwrap()
            .is_empty()
    );
    // Serialized devices never expose the hash.
    assert!(
        serde_json::to_value(&device)
            .unwrap()
            .get("device_hash")
            .is_none()
    );
}
