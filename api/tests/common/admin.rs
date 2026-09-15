//! Helpers for admin API tests: users holding built-in roles and admin-audience
//! access tokens issued directly (the token endpoint has its own coverage).

use std::time::Duration;

use axum::http::StatusCode;
use reqwest::Method;
use ridm_api::db;
use ridm_api::models::{NewUser, Principal, Tenant};
use ridm_api::repos;
use ridm_api::services::admin_access::ADMIN_AUDIENCE;
use ridm_api::services::tokens::{self, AccessTokenRequest, TokenClient};
use ridm_api::services::{roles, tenants, users};
use ridm_core::events::Actor;
use serde_json::Value;
use uuid::Uuid;

use super::TestApp;

/// Create a user in `tenant_id`, optionally holding a role by name.
pub async fn user_with_role(app: &TestApp, tenant_id: Uuid, role: Option<&str>) -> Uuid {
    let suffix = &Uuid::new_v4().simple().to_string()[..8];
    let user = users::create(
        &app.state,
        tenant_id,
        Actor::System,
        NewUser {
            username: format!("adm-{suffix}"),
            email: Some(format!("adm-{suffix}@example.com")),
            email_verified: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    if let Some(name) = role {
        assign(app, tenant_id, user.id, name).await;
    }
    user.id
}

pub async fn role_id(app: &TestApp, tenant_id: Uuid, name: &str) -> Uuid {
    let mut tx = db::tenant_tx(&app.state.db, tenant_id).await.unwrap();
    let r = repos::roles::find_by_name(&mut *tx, tenant_id, None, name)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("role {name} missing in {tenant_id}"));
    tx.commit().await.unwrap();
    r.id
}

pub async fn assign(app: &TestApp, tenant_id: Uuid, user_id: Uuid, name: &str) {
    let rid = role_id(app, tenant_id, name).await;
    roles::assign(
        &app.state,
        tenant_id,
        Actor::System,
        rid,
        Principal::User { id: user_id },
    )
    .await
    .unwrap();
}

pub struct TokenOpts<'a> {
    pub audiences: &'a [&'a str],
    pub session_id: Option<Uuid>,
    pub ttl: Duration,
}

impl Default for TokenOpts<'_> {
    fn default() -> Self {
        Self {
            audiences: &[ADMIN_AUDIENCE],
            session_id: None,
            ttl: Duration::from_secs(300),
        }
    }
}

/// Issue an admin-audience access token for `user_id` from `tenant`'s keys.
pub async fn token(app: &TestApp, tenant: &Tenant, user_id: Uuid, opts: TokenOpts<'_>) -> String {
    let user = users::get(&app.state, tenant.id, user_id).await.unwrap();
    let role_list = roles::effective_roles(&app.state, tenant.id, user_id)
        .await
        .unwrap();
    let mut client = TokenClient::public("admin-ui");
    client.access_token_ttl = opts.ttl;
    let audiences: Vec<String> = opts.audiences.iter().map(|s| s.to_string()).collect();
    tokens::issue_access_token(
        &app.state,
        AccessTokenRequest {
            tenant,
            client: &client,
            user: Some(&user),
            scopes: &["openid".into()],
            audiences: &audiences,
            roles: &role_list,
            groups: &[],
            session_id: opts.session_id,
            auth_time: None,
            amr: &["pwd".into()],
            acr: None,
        },
    )
    .await
    .unwrap()
    .token
}

/// A user in `tenant_id` holding `role`, plus a token for them.
pub async fn admin_token(app: &TestApp, tenant_id: Uuid, role: &str) -> String {
    let tenant = tenants::get(&app.state, tenant_id).await.unwrap();
    let user = user_with_role(app, tenant_id, Some(role)).await;
    token(app, &tenant, user, TokenOpts::default()).await
}

/// One admin API call. Returns status, parsed JSON body (`Null` when empty)
/// and the `WWW-Authenticate` header.
pub async fn call(
    app: &TestApp,
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: Option<&Value>,
) -> (StatusCode, Value, String) {
    let mut req = app.http.request(method, app.url(path));
    if let Some(t) = bearer {
        req = req.bearer_auth(t);
    }
    if let Some(b) = body {
        req = req.json(b);
    }
    let res = req.send().await.unwrap();
    let status = res.status();
    let www = res
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body: Value = res.json().await.unwrap_or(Value::Null);
    (status, body, www)
}

pub async fn get_json(
    app: &TestApp,
    path: &str,
    bearer: Option<&str>,
) -> (StatusCode, Value, String) {
    call(app, Method::GET, path, bearer, None).await
}
