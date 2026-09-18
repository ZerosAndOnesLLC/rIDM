//! Review findings (Phase 10):
//!
//! * Revoking one session (an administrator's revocation, and the password
//!   paths) left the refresh tokens issued in it usable, and the refresh grant
//!   never looked at the session. Revoking a session now revokes its tokens,
//!   and a refresh (or a code exchange) on a signed-out session is refused.
//!   A session that merely expired ends the refresh tokens issued without
//!   `offline_access` too; those with it outlive it (OIDC Core §11).
//! * Only RP-initiated logout sent back-channel logout tokens. Every way a
//!   session is ended on purpose now tells the relying parties, including a
//!   session evicted by the tenant's concurrent-session cap.

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use redis::AsyncCommands as _;
use reqwest::Method;
use ridm_api::cache::keys;
use ridm_api::models::NewClient;
use ridm_api::services::admin_access::USER_MANAGER_ROLE;
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::common::TestApp;
use crate::common::admin::{admin_token, call};
use crate::support::{self, param};

/// Sign `user_id` in, authorize `spa` on the session and exchange the code.
/// Returns the session id and the token response.
async fn signed_in(app: &TestApp, user_id: Uuid) -> (Uuid, Value) {
    signed_in_with(app, user_id, "openid").await
}

/// [`signed_in`] asking for `scope`.
async fn signed_in_with(app: &TestApp, user_id: Uuid, scope: &str) -> (Uuid, Value) {
    let slug = app.tenant.slug.clone();
    let (sid, cookie) = support::session(app, app.tenant.id, &slug, user_id).await;
    let loc = support::authorize(&app.http, app, &slug, Some(&cookie), &[("scope", scope)]).await;
    let code = param(&loc, "code").expect("a code");
    let (status, tokens) = support::exchange(app, &slug, &code).await;
    assert_eq!(status, 200, "{tokens}");
    (sid, tokens)
}

#[tokio::test]
async fn revoking_one_session_revokes_its_refresh_tokens() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let slug = app.tenant.slug.clone();
    support::spa(&app, tid, NewClient::default()).await;
    let alice = support::user_with_password(&app, tid, "alice").await;
    let manager = admin_token(&app, tid, USER_MANAGER_ROLE).await;

    let (sid, tokens) = signed_in(&app, alice).await;
    let rt = tokens["refresh_token"].as_str().unwrap();
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("/admin/tenants/{slug}/users/{alice}/sessions/{sid}"),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, body) = support::refresh(&app, &slug, rt, &[]).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_grant");

    // A code issued before the sign-out and exchanged after it is refused.
    let (sid, cookie) = support::session(&app, tid, &slug, alice).await;
    let loc = support::authorize(&app.http, &app, &slug, Some(&cookie), &[]).await;
    let code = param(&loc, "code").unwrap();
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("/admin/tenants/{slug}/users/{alice}/sessions/{sid}"),
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, body) = support::exchange(&app, &slug, &code).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_grant");

    // A session that merely went idle (its entry expired) takes the tokens
    // issued without `offline_access` with it ...
    let (sid, tokens) = signed_in(&app, alice).await;
    let mut conn = app.state.redis.get().await.unwrap();
    let _: () = conn.del(keys::sso_session(tid, sid)).await.unwrap();
    drop(conn);
    let (status, body) =
        support::refresh(&app, &slug, tokens["refresh_token"].as_str().unwrap(), &[]).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_grant");

    // ... but not the offline ones, which outlive the sign-in.
    let (sid, tokens) = signed_in_with(&app, alice, "openid offline_access").await;
    assert_eq!(tokens["scope"], "openid offline_access", "{tokens}");
    let mut conn = app.state.redis.get().await.unwrap();
    let _: () = conn.del(keys::sso_session(tid, sid)).await.unwrap();
    drop(conn);
    let (status, body) =
        support::refresh(&app, &slug, tokens["refresh_token"].as_str().unwrap(), &[]).await;
    assert_eq!(status, 200, "{body}");
}

/// A local receiver for back-channel logout tokens; returns its URL and the
/// `sid` of every token it received.
async fn logout_receiver() -> (String, Arc<Mutex<Vec<String>>>) {
    let received: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let sink = received.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/bc",
            axum::routing::post(move |axum::Form(form): axum::Form<Vec<(String, String)>>| {
                let sink = sink.clone();
                async move {
                    if let Some((_, token)) = form.iter().find(|(k, _)| k == "logout_token") {
                        let claims: Value = serde_json::from_slice(
                            &URL_SAFE_NO_PAD
                                .decode(token.split('.').nth(1).unwrap_or_default())
                                .unwrap_or_default(),
                        )
                        .unwrap_or_default();
                        if let Some(sid) = claims["sid"].as_str() {
                            sink.lock().unwrap().push(sid.to_string());
                        }
                    }
                    axum::http::StatusCode::OK
                }
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://127.0.0.1:{port}/bc"), received)
}

async fn wait_for(received: &Arc<Mutex<Vec<String>>>, sid: Uuid) {
    for _ in 0..50 {
        if received.lock().unwrap().contains(&sid.to_string()) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("no back-channel logout token for session {sid}");
}

#[tokio::test]
async fn every_sign_out_path_sends_back_channel_logout() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let slug = app.tenant.slug.clone();
    let (uri, received) = logout_receiver().await;
    support::spa(
        &app,
        tid,
        NewClient {
            backchannel_logout_uri: Some(uri),
            ..Default::default()
        },
    )
    .await;
    let manager = admin_token(&app, tid, USER_MANAGER_ROLE).await;
    let alice = support::user_with_password(&app, tid, "alice").await;
    let admin_call = |method: Method, path: String, body: Option<Value>| {
        let app = &app;
        let manager = manager.clone();
        async move {
            let (status, body, _) = call(app, method, &path, Some(&manager), body.as_ref()).await;
            assert!(status.is_success(), "{path}: {status} {body}");
        }
    };

    // An administrator ends one session.
    let (sid, _) = signed_in(&app, alice).await;
    admin_call(
        Method::DELETE,
        format!("/admin/tenants/{slug}/users/{alice}/sessions/{sid}"),
        None,
    )
    .await;
    wait_for(&received, sid).await;

    // ... or all of them.
    let (s1, _) = signed_in(&app, alice).await;
    let (s2, _) = signed_in(&app, alice).await;
    admin_call(
        Method::DELETE,
        format!("/admin/tenants/{slug}/users/{alice}/sessions"),
        None,
    )
    .await;
    wait_for(&received, s1).await;
    wait_for(&received, s2).await;

    // A password set by an administrator with sign-out.
    let (sid, _) = signed_in(&app, alice).await;
    admin_call(
        Method::PUT,
        format!("/admin/tenants/{slug}/users/{alice}/password"),
        Some(json!({"password": "An0ther-long-passphrase!", "revoke_sessions": true})),
    )
    .await;
    wait_for(&received, sid).await;

    // Disabling the user.
    let (sid, _) = signed_in(&app, alice).await;
    admin_call(
        Method::PATCH,
        format!("/admin/tenants/{slug}/users/{alice}"),
        Some(json!({"status": "disabled"})),
    )
    .await;
    wait_for(&received, sid).await;

    // Deleting the user (the token still names them).
    let bob = support::user_with_password(&app, tid, "bob").await;
    let (sid, _) = signed_in(&app, bob).await;
    admin_call(
        Method::DELETE,
        format!("/admin/tenants/{slug}/users/{bob}"),
        None,
    )
    .await;
    wait_for(&received, sid).await;
}

/// Review finding: a session pushed out by the tenant's concurrent-session
/// cap was revoked quietly, so its refresh tokens kept working and its
/// relying parties never heard. Eviction now ends it like any sign-out.
#[tokio::test]
async fn a_session_evicted_by_the_concurrency_cap_is_logged_out_everywhere() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let slug = app.tenant.slug.clone();
    let mut settings = tenants::get(&app.state, tid).await.unwrap().settings;
    settings.session.max_concurrent = 1;
    tenants::update(
        &app.state,
        Actor::System,
        tid,
        TenantUpdate {
            display_name: None,
            status: None,
            settings: Some(settings.0),
        },
    )
    .await
    .unwrap();
    let (uri, received) = logout_receiver().await;
    support::spa(
        &app,
        tid,
        NewClient {
            backchannel_logout_uri: Some(uri),
            ..Default::default()
        },
    )
    .await;
    let alice = support::user_with_password(&app, tid, "alice").await;

    let (first, tokens) = signed_in(&app, alice).await;
    // The second sign-in evicts the first session.
    let (second, _) = signed_in(&app, alice).await;
    assert_ne!(first, second);
    wait_for(&received, first).await;
    assert!(!received.lock().unwrap().contains(&second.to_string()));
    let (status, body) =
        support::refresh(&app, &slug, tokens["refresh_token"].as_str().unwrap(), &[]).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_grant");
}
