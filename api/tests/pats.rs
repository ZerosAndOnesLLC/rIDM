//! Phase 8.5: personal access tokens — minted and revoked from the account
//! API (with a recent sign-in), usable as bearer tokens on the account API
//! (`account` scope) and the admin API (permission scopes, narrowed to what
//! the user still holds), listed and revoked by administrators, and
//! introspectable.

mod common;

use std::time::Duration;

use chrono::Utc;
use common::TestApp;
use common::admin::{admin_token, assign, call};
use reqwest::Method;
use ridm_api::models::{AccountPolicy, NewUser, TenantSettings};
use ridm_api::services::account_console::{ACCOUNT_AUDIENCE, ACCOUNT_CLIENT_ID};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::tokens::{self, AccessTokenRequest, TokenClient};
use ridm_api::services::{personal_access_tokens as pats, roles, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

struct Fx {
    app: TestApp,
    user_id: Uuid,
}

async fn fixture() -> Fx {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let user = users::create(
        &app.state,
        tid,
        Actor::System,
        NewUser {
            username: "alice".into(),
            email: Some("alice@example.com".into()),
            email_verified: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // Alice manages users but nothing else.
    assign(&app, tid, user.id, "ridm:user-manager").await;
    Fx {
        app,
        user_id: user.id,
    }
}

/// An account-console token; `recent` sign-ins may mint and revoke tokens.
async fn account_token(fx: &Fx, user_id: Uuid, recent: bool) -> String {
    let tenant = tenants::get(&fx.app.state, fx.app.tenant.id).await.unwrap();
    let user = users::get(&fx.app.state, tenant.id, user_id).await.unwrap();
    let session = sessions::create(
        &fx.app.state,
        tenant.id,
        NewSession {
            user_id,
            amr: vec!["pwd".into()],
            acr: None,
            ip: None,
            user_agent: None,
            policy: &tenant.settings.session,
        },
    )
    .await
    .unwrap();
    let mut client = TokenClient::public(ACCOUNT_CLIENT_ID);
    client.access_token_ttl = Duration::from_secs(300);
    let auth_time = Utc::now() - chrono::Duration::seconds(if recent { 0 } else { 30 * 60 });
    tokens::issue_access_token(
        &fx.app.state,
        AccessTokenRequest {
            tenant: &tenant,
            client: &client,
            user: Some(&user),
            scopes: &["openid".into()],
            audiences: &[ACCOUNT_AUDIENCE.to_string()],
            roles: &[],
            groups: &[],
            session_id: Some(session.id),
            auth_time: Some(auth_time),
            amr: &["pwd".into()],
            acr: None,
            cnf_jkt: None,
            act: None,
        },
    )
    .await
    .unwrap()
    .token
}

fn tokens_path(fx: &Fx) -> String {
    format!("/t/{}/account/tokens", fx.app.tenant.slug)
}

async fn mint(fx: &Fx, bearer: &str, body: Value) -> (u16, Value) {
    let (status, body, _) = call(
        &fx.app,
        Method::POST,
        &tokens_path(fx),
        Some(bearer),
        Some(&body),
    )
    .await;
    (status.as_u16(), body)
}

#[tokio::test]
async fn a_user_mints_uses_and_revokes_tokens() {
    let fx = fixture().await;
    let slug = fx.app.tenant.slug.clone();
    let t = account_token(&fx, fx.user_id, true).await;

    let (status, body, _) = call(&fx.app, Method::GET, &tokens_path(&fx), Some(&t), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["tokens"], json!([]));
    assert_eq!(body["enabled"], true);
    assert_eq!(body["max_days"], 365);
    let available: Vec<&str> = body["available_scopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    assert!(
        available.contains(&"account") && available.contains(&"ridm:users:read"),
        "{available:?}"
    );
    assert!(
        !available.contains(&"ridm:tenants:write"),
        "only what the user holds: {available:?}"
    );

    // Refusals: scopes not held, none at all, too long an expiry, a stale sign-in.
    let (status, body) = mint(
        &fx,
        &t,
        json!({"name": "ci", "scopes": ["ridm:tenants:write"]}),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["errors"][0]["field"], "scopes");
    let (status, _) = mint(&fx, &t, json!({"name": "ci", "scopes": []})).await;
    assert_eq!(status, 400);
    let (status, body) = mint(
        &fx,
        &t,
        json!({"name": "ci", "scopes": ["account"], "expires_in_days": 400}),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["errors"][0]["field"], "expires_in_days");
    let old = account_token(&fx, fx.user_id, false).await;
    let (status, body) = mint(&fx, &old, json!({"name": "ci", "scopes": ["account"]})).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["type"], "urn:ridm:error:reauthentication-required");

    // Minted once: the token is in the answer and nowhere else.
    let (status, created) = mint(&fx, &t, json!({"name": "CI script", "scopes": ["account", "ridm:users:read"], "expires_in_days": 30})).await;
    assert_eq!(status, 201, "{created}");
    let secret = created["token"].as_str().unwrap().to_string();
    assert!(secret.starts_with("rpat_"), "{secret}");
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["scopes"], json!(["account", "ridm:users:read"]));
    assert!(created["expires_at"].is_string());
    assert!(created.get("token_hash").is_none());
    let (_, body, _) = call(&fx.app, Method::GET, &tokens_path(&fx), Some(&t), None).await;
    assert_eq!(body["tokens"][0]["name"], "CI script");
    assert!(
        body["tokens"][0].get("token").is_none() && body["tokens"][0].get("token_hash").is_none()
    );
    assert!(body["tokens"][0]["last_used_at"].is_null());

    // As a bearer on the account API: acts as the user, but nothing that
    // needs a recent sign-in (so a token can never mint another).
    let me = format!("/t/{slug}/account/me");
    let (status, body, _) = call(&fx.app, Method::GET, &me, Some(&secret), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["username"], "alice");
    assert_eq!(body["amr"], json!(["pat"]));
    assert!(body["auth_time"].is_null());
    let (status, body) = mint(
        &fx,
        &secret,
        json!({"name": "nested", "scopes": ["account"]}),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    let (status, body, _) =
        call(&fx.app, Method::GET, &tokens_path(&fx), Some(&secret), None).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body["tokens"][0]["last_used_at"].is_string(),
        "use is recorded"
    );

    // As a bearer on the admin API: the token's permissions, no more.
    let users_url = format!("/admin/tenants/{slug}/users");
    let (status, body, _) = call(&fx.app, Method::GET, &users_url, Some(&secret), None).await;
    assert_eq!(status, 200, "{body}");
    let (status, _, _) = call(
        &fx.app,
        Method::POST,
        &users_url,
        Some(&secret),
        Some(&json!({"username": "bob"})),
    )
    .await;
    assert_eq!(status, 403, "ridm:users:write was not granted to the token");
    let other = common::create_tenant(&fx.app.state.db).await;
    let (status, _, _) = call(
        &fx.app,
        Method::GET,
        &format!("/admin/tenants/{}/users", other.slug),
        Some(&secret),
        None,
    )
    .await;
    assert_eq!(status, 403, "a tenant token reaches its own tenant only");
    let (status, _, _) = call(
        &fx.app,
        Method::GET,
        &format!("/t/{}/account/me", other.slug),
        Some(&secret),
        None,
    )
    .await;
    assert_eq!(status, 403);

    // Losing the role narrows the token at once.
    let rid = common::admin::role_id(&fx.app, fx.app.tenant.id, "ridm:user-manager").await;
    roles::unassign(
        &fx.app.state,
        fx.app.tenant.id,
        Actor::System,
        rid,
        ridm_api::models::Principal::User { id: fx.user_id },
    )
    .await
    .unwrap();
    let (status, body, _) = call(&fx.app, Method::GET, &users_url, Some(&secret), None).await;
    assert_eq!(status, 403, "{body}");
    let (status, _, _) = call(&fx.app, Method::GET, &me, Some(&secret), None).await;
    assert_eq!(status, 200, "the account scope stays");

    // Revoked: gone from use, still listed as revoked.
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("{}/{id}", tokens_path(&fx)),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = call(&fx.app, Method::GET, &me, Some(&secret), None).await;
    assert_eq!(status, 401);
    let (_, body, _) = call(&fx.app, Method::GET, &tokens_path(&fx), Some(&t), None).await;
    assert!(body["tokens"][0]["revoked_at"].is_string());
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("{}/{id}", tokens_path(&fx)),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404, "revoking twice");
}

#[tokio::test]
async fn tokens_without_the_account_scope_stay_off_the_account_api_and_expire() {
    let fx = fixture().await;
    let t = account_token(&fx, fx.user_id, true).await;
    let (status, created) = mint(
        &fx,
        &t,
        json!({"name": "admin-only", "scopes": ["ridm:users:read"]}),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let secret = created["token"].as_str().unwrap();
    let (status, body, _) = call(
        &fx.app,
        Method::GET,
        &format!("/t/{}/account/me", fx.app.tenant.slug),
        Some(secret),
        None,
    )
    .await;
    assert_eq!(status, 403, "{body}");
    let (status, _, _) = call(
        &fx.app,
        Method::GET,
        &format!("/admin/tenants/{}/users", fx.app.tenant.slug),
        Some(secret),
        None,
    )
    .await;
    assert_eq!(status, 200);

    // Expired tokens are refused; the default expiry is the tenant's maximum.
    let (_, created) = mint(
        &fx,
        &t,
        json!({"name": "default expiry", "scopes": ["account"]}),
    )
    .await;
    let expires =
        chrono::DateTime::parse_from_rfc3339(created["expires_at"].as_str().unwrap()).unwrap();
    let days = (expires.with_timezone(&Utc) - Utc::now()).num_days();
    assert!((364..=365).contains(&days), "{days}");
    let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    let mut tx = ridm_api::db::tenant_tx(&fx.app.state.db, fx.app.tenant.id)
        .await
        .unwrap();
    sqlx::query("UPDATE personal_access_tokens SET expires_at = now() - interval '1 minute' WHERE tenant_id = $1 AND id = $2")
        .bind(fx.app.tenant.id)
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let (status, _, _) = call(
        &fx.app,
        Method::GET,
        &format!("/t/{}/account/me", fx.app.tenant.slug),
        Some(created["token"].as_str().unwrap()),
        None,
    )
    .await;
    assert_eq!(status, 401);

    // Nonsense is refused without a lookup.
    let (status, _, _) = call(
        &fx.app,
        Method::GET,
        &format!("/t/{}/account/me", fx.app.tenant.slug),
        Some("rpat_nope"),
        None,
    )
    .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn administrators_list_and_revoke_a_users_tokens_and_a_tenant_may_forbid_them() {
    let fx = fixture().await;
    let tid = fx.app.tenant.id;
    let t = account_token(&fx, fx.user_id, true).await;
    let (_, created) = mint(&fx, &t, json!({"name": "laptop", "scopes": ["account"]})).await;
    let secret = created["token"].as_str().unwrap().to_string();
    let id = created["id"].as_str().unwrap().to_string();

    let admin = admin_token(&fx.app, tid, "ridm:owner").await;
    let base = format!(
        "/admin/tenants/{}/users/{}/pats",
        fx.app.tenant.slug, fx.user_id
    );
    let (status, body, _) = call(&fx.app, Method::GET, &base, Some(&admin), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body[0]["name"], "laptop");
    assert!(body[0].get("token_hash").is_none());
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("{base}/{id}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = call(
        &fx.app,
        Method::GET,
        &format!("/t/{}/account/me", fx.app.tenant.slug),
        Some(&secret),
        None,
    )
    .await;
    assert_eq!(status, 401);
    let viewer = admin_token(&fx.app, tid, "ridm:user-manager").await;
    let (status, _, _) = call(&fx.app, Method::GET, &base, Some(&viewer), None).await;
    assert_eq!(status, 200, "user managers read tokens");

    // Deleting the account revokes what is left.
    let (_, created) = mint(
        &fx,
        &t,
        json!({"name": "left behind", "scopes": ["account"]}),
    )
    .await;
    let secret2 = created["token"].as_str().unwrap().to_string();
    let bob = users::create(
        &fx.app.state,
        tid,
        Actor::System,
        NewUser {
            username: "bob".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let tb = account_token(&fx, bob.id, true).await;
    let (_, created_b) = mint(&fx, &tb, json!({"name": "bob's", "scopes": ["account"]})).await;
    let (status, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("/t/{}/account/me", fx.app.tenant.slug),
        Some(&tb),
        Some(&json!({"confirm": "bob"})),
    )
    .await;
    assert_eq!(status, 204);
    let (status, _, _) = call(
        &fx.app,
        Method::GET,
        &format!("/t/{}/account/me", fx.app.tenant.slug),
        Some(created_b["token"].as_str().unwrap()),
        None,
    )
    .await;
    assert_eq!(status, 401);
    let (status, _, _) = call(
        &fx.app,
        Method::GET,
        &format!("/t/{}/account/me", fx.app.tenant.slug),
        Some(&secret2),
        None,
    )
    .await;
    assert_eq!(status, 200, "alice's token is untouched");

    // The tenant switches tokens off: none can be minted; existing ones keep working.
    tenants::update(
        &fx.app.state,
        Actor::System,
        tid,
        TenantUpdate {
            settings: Some(TenantSettings {
                account: AccountPolicy {
                    personal_tokens: false,
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let t = account_token(&fx, fx.user_id, true).await;
    let (status, body) = mint(&fx, &t, json!({"name": "no", "scopes": ["account"]})).await;
    assert_eq!(status, 403, "{body}");
    let (status, body, _) = call(&fx.app, Method::GET, &tokens_path(&fx), Some(&t), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["enabled"], false);
}

#[tokio::test]
async fn introspection_knows_personal_tokens() {
    let fx = fixture().await;
    let tid = fx.app.tenant.id;
    let t = account_token(&fx, fx.user_id, true).await;
    let (_, created) = mint(
        &fx,
        &t,
        json!({"name": "api", "scopes": ["account", "ridm:users:read"]}),
    )
    .await;
    let secret = created["token"].as_str().unwrap().to_string();
    let rs = ridm_api::services::clients::create(
        &fx.app.state,
        tid,
        Actor::System,
        ridm_api::models::NewClient {
            client_id: Some("backend".into()),
            name: "Backend".into(),
            client_type: Some(ridm_api::models::ClientType::Machine),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let cs = rs.client_secret.unwrap();
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/introspect"))
        .basic_auth("backend", Some(cs.as_str()))
        .form(&[("token", secret.as_str())])
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["active"], true, "{body}");
    assert_eq!(body["token_type"], "personal_access_token");
    assert_eq!(body["sub"], fx.user_id.to_string());
    assert_eq!(body["username"], "alice");
    assert_eq!(body["scope"], "account ridm:users:read");
    assert!(body["exp"].is_number());
    pats::revoke(
        &fx.app.state,
        tid,
        Actor::System,
        fx.user_id,
        created["id"].as_str().unwrap().parse().unwrap(),
    )
    .await
    .unwrap();
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/introspect"))
        .basic_auth("backend", Some(cs.as_str()))
        .form(&[("token", secret.as_str())])
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body, json!({"active": false}));
}
