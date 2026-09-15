mod common;

use chrono::Duration;
use common::TestApp;
use ridm_api::error::{AppError, OAuthErrorCode};
use ridm_api::models::NewUser;
use ridm_api::services::refresh_tokens::{self, IssueRequest};
use ridm_api::services::tokens::{self, AccessTokenRequest, TokenClient, VerifyOptions};
use ridm_api::services::{denylist, tenants, users};
use ridm_core::events::Actor;
use uuid::Uuid;

/// Refresh tokens reference a registered client; create a machine client per id.
async fn client(app: &TestApp, client_id: &str) {
    ridm_api::services::clients::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        ridm_api::models::NewClient {
            client_id: Some(client_id.into()),
            name: client_id.into(),
            client_type: Some(ridm_api::models::ClientType::Machine),
            ..Default::default()
        },
    )
    .await
    .unwrap();
}

async fn user(app: &TestApp) -> Uuid {
    users::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewUser {
            username: "alice".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .id
}

fn req<'a>(
    client: &'a str,
    user_id: Option<Uuid>,
    session: Option<Uuid>,
    scopes: &'a [String],
    ttl: Duration,
) -> IssueRequest<'a> {
    IssueRequest {
        client_id: client,
        user_id,
        session_id: session,
        scopes,
        audiences: &[],
        ttl,
    }
}

#[tokio::test]
async fn rotation_chain_and_reuse_detection() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let uid = user(&app).await;
    client(&app, "app").await;
    let scopes = vec!["openid".to_string(), "offline_access".to_string()];

    let first = refresh_tokens::issue(
        &app.state,
        tid,
        req("app", Some(uid), None, &scopes, Duration::days(30)),
    )
    .await
    .unwrap();
    assert!(first.token.starts_with("rt_"));
    assert_eq!(first.record.scopes, scopes);
    let family = first.record.family_id;

    // Rotate: new secret, same family, same absolute expiry, old one consumed.
    let second = refresh_tokens::rotate(&app.state, tid, "app", &first.token)
        .await
        .unwrap();
    assert_ne!(*second.token, *first.token);
    assert_eq!(second.record.family_id, family);
    assert_eq!(second.record.expires_at, first.record.expires_at);
    assert_eq!(second.record.user_id, Some(uid));
    let third = refresh_tokens::rotate(&app.state, tid, "app", &second.token)
        .await
        .unwrap();
    assert_eq!(
        refresh_tokens::list_live_for_user(&app.state, tid, uid)
            .await
            .unwrap()
            .len(),
        1
    );

    // Replaying an already-consumed token: whole family revoked, including the live one.
    let replay = refresh_tokens::rotate(&app.state, tid, "app", &first.token)
        .await
        .unwrap_err();
    assert_eq!(replay.error, OAuthErrorCode::InvalidGrant);
    assert!(replay.error_description.unwrap().contains("reuse"));
    let after = refresh_tokens::rotate(&app.state, tid, "app", &third.token)
        .await
        .unwrap_err();
    assert_eq!(after.error, OAuthErrorCode::InvalidGrant);
    assert!(
        refresh_tokens::list_live_for_user(&app.state, tid, uid)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn client_binding_expiry_and_garbage() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    client(&app, "app-a").await;
    let scopes = vec![];
    let t = refresh_tokens::issue(
        &app.state,
        tid,
        req("app-a", None, None, &scopes, Duration::days(1)),
    )
    .await
    .unwrap();
    let wrong = refresh_tokens::rotate(&app.state, tid, "app-b", &t.token)
        .await
        .unwrap_err();
    assert_eq!(wrong.error, OAuthErrorCode::InvalidGrant);
    // Not consumed by the failed attempt: the right client can still use it.
    assert!(
        refresh_tokens::rotate(&app.state, tid, "app-a", &t.token)
            .await
            .is_ok()
    );

    let expired = refresh_tokens::issue(
        &app.state,
        tid,
        req("app-a", None, None, &scopes, Duration::seconds(-1)),
    )
    .await
    .unwrap();
    assert_eq!(
        refresh_tokens::rotate(&app.state, tid, "app-a", &expired.token)
            .await
            .unwrap_err()
            .error,
        OAuthErrorCode::InvalidGrant
    );

    for garbage in ["", "rt_", "nope", &"rt_x".repeat(100)] {
        assert_eq!(
            refresh_tokens::rotate(&app.state, tid, "app-a", garbage)
                .await
                .unwrap_err()
                .error,
            OAuthErrorCode::InvalidGrant
        );
    }

    // Tokens are scoped to the tenant they were issued in.
    let other = common::create_tenant(&app.state.db).await;
    let mut other_app = TestApp::spawn().await;
    other_app.tenant = other.clone();
    client(&other_app, "app-a").await;
    let t2 = refresh_tokens::issue(
        &app.state,
        tid,
        req("app-a", None, None, &scopes, Duration::days(1)),
    )
    .await
    .unwrap();
    assert_eq!(
        refresh_tokens::rotate(&app.state, other.id, "app-a", &t2.token)
            .await
            .unwrap_err()
            .error,
        OAuthErrorCode::InvalidGrant
    );
    assert!(
        refresh_tokens::rotate(&app.state, tid, "app-a", &t2.token)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn revocation_by_token_user_session_and_purge() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let uid = user(&app).await;
    client(&app, "app").await;
    client(&app, "other").await;
    let scopes = vec![];
    let sid = Uuid::now_v7();
    let a = refresh_tokens::issue(
        &app.state,
        tid,
        req("app", Some(uid), Some(sid), &scopes, Duration::days(1)),
    )
    .await
    .unwrap();
    let b = refresh_tokens::issue(
        &app.state,
        tid,
        req("app", Some(uid), None, &scopes, Duration::days(1)),
    )
    .await
    .unwrap();
    let c = refresh_tokens::issue(
        &app.state,
        tid,
        req("other", Some(uid), None, &scopes, Duration::days(1)),
    )
    .await
    .unwrap();
    assert_eq!(
        refresh_tokens::list_live_for_user(&app.state, tid, uid)
            .await
            .unwrap()
            .len(),
        3
    );

    // RFC 7009 style revoke: unknown tokens and wrong client are silently ignored.
    refresh_tokens::revoke(&app.state, tid, "app", "rt_unknown")
        .await
        .unwrap();
    refresh_tokens::revoke(&app.state, tid, "other", &a.token)
        .await
        .unwrap();
    assert!(
        refresh_tokens::rotate(&app.state, tid, "app", &a.token)
            .await
            .is_ok()
    );

    assert_eq!(
        refresh_tokens::revoke_for_session(&app.state, tid, Actor::System, sid)
            .await
            .unwrap(),
        2,
        "original + rotated descendant"
    );
    assert_eq!(
        refresh_tokens::revoke_for_user(&app.state, tid, Actor::System, uid, Some("app"))
            .await
            .unwrap(),
        1
    );
    assert!(
        refresh_tokens::rotate(&app.state, tid, "app", &b.token)
            .await
            .is_err()
    );
    assert!(
        refresh_tokens::rotate(&app.state, tid, "other", &c.token)
            .await
            .is_ok(),
        "other client untouched"
    );
    // `c` was rotated: its consumed original and the live descendant both get revoked_at.
    assert_eq!(
        refresh_tokens::revoke_for_user(&app.state, tid, Actor::System, uid, None)
            .await
            .unwrap(),
        2
    );
    assert!(
        refresh_tokens::list_live_for_user(&app.state, tid, uid)
            .await
            .unwrap()
            .is_empty()
    );

    // Purge removes dead rows older than the retention window.
    assert_eq!(
        refresh_tokens::purge(&app.state, tid, Duration::days(1))
            .await
            .unwrap(),
        0
    );
    let purged = refresh_tokens::purge(&app.state, tid, Duration::seconds(-1))
        .await
        .unwrap();
    assert!(purged >= 5, "purged {purged}");
}

#[tokio::test]
async fn jti_denylist_revokes_access_tokens_before_expiry() {
    let app = TestApp::spawn().await;
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let client = TokenClient::public("cli");
    let at = tokens::issue_access_token(
        &app.state,
        AccessTokenRequest {
            tenant: &tenant,
            client: &client,
            user: None,
            scopes: &[],
            audiences: &[],
            roles: &[],
            groups: &[],
            session_id: None,
            auth_time: None,
            amr: &[],
            acr: None,
        },
    )
    .await
    .unwrap();
    let opts = VerifyOptions::default();
    let claims = tokens::verify(&app.state, &tenant, &at.token, &opts)
        .await
        .unwrap();
    let jti = claims["jti"].as_str().unwrap().to_string();

    denylist::deny(&app.state, tenant.id, &jti, at.expires_at)
        .await
        .unwrap();
    assert!(
        denylist::is_denied(&app.state, tenant.id, &jti)
            .await
            .unwrap()
    );
    assert!(matches!(
        tokens::verify(&app.state, &tenant, &at.token, &opts).await,
        Err(AppError::Unauthorized)
    ));
    let no_check = VerifyOptions {
        check_denylist: false,
        ..Default::default()
    };
    assert!(
        tokens::verify(&app.state, &tenant, &at.token, &no_check)
            .await
            .is_ok(),
        "signature itself is still valid"
    );
    // Denylist is per tenant.
    assert!(
        !denylist::is_denied(&app.state, Uuid::now_v7(), &jti)
            .await
            .unwrap()
    );
}
