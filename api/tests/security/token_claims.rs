//! Review findings (Phase 10, stored-but-unused configuration):
//!
//! * Opaque access tokens are looked up by hash, not verified against a
//!   tenant's keys, so nothing in the token itself ties it to a tenant: the
//!   lookup must. A token of one tenant is refused at every other tenant's
//!   userinfo, introspection, account and admin endpoints.
//! * Claim mappers could write `cnf` and `act` (not in the protected list),
//!   binding a token to a key or naming an actor that never took part, and
//!   any mapper kind could write `roles`, `groups` or `permissions`, which a
//!   resource server authorizes on. They are refused when a mapper is saved,
//!   and a stored row that predates the rule is skipped when tokens are
//!   built.

use reqwest::Method;
use ridm_api::models::{
    AccessTokenFormat, ClaimMapper, ClientType, MapperKind, NewClient, TokenKind,
};
use ridm_api::services::account_console::ACCOUNT_AUDIENCE;
use ridm_api::services::admin_access::{ADMIN_AUDIENCE, CLIENT_MANAGER_ROLE, OWNER_ROLE};
use ridm_api::services::tokens::{self, AccessTokenRequest, TokenClient};
use ridm_api::services::{clients, roles, tenants, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::common::TestApp;
use crate::common::admin::{admin_token, call, user_with_role};

/// An opaque access token for `user_id` of `tenant_id` aimed at `audience`.
async fn opaque(app: &TestApp, tenant_id: Uuid, user_id: Uuid, audience: &str) -> String {
    let tenant = tenants::get(&app.state, tenant_id).await.unwrap();
    let user = users::get(&app.state, tenant_id, user_id).await.unwrap();
    let role_list = roles::effective_roles(&app.state, tenant_id, user_id, None)
        .await
        .unwrap();
    let client = TokenClient {
        access_token_format: AccessTokenFormat::Opaque,
        ..TokenClient::public("app")
    };
    tokens::issue_access_token(
        &app.state,
        AccessTokenRequest {
            tenant: &tenant,
            client: &client,
            user: Some(&user),
            scopes: &["openid".into()],
            audiences: &[audience.to_string()],
            roles: &role_list,
            groups: &[],
            session_id: None,
            org_id: None,
            auth_time: None,
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

#[tokio::test]
async fn an_opaque_token_is_bound_to_its_tenant() {
    let app = TestApp::spawn().await;
    let other = crate::common::create_tenant(&app.state.db).await;
    let owner = user_with_role(&app, app.tenant.id, Some(OWNER_ROLE)).await;
    // The same public client id in both tenants.
    let app_client = |tenant_id: Uuid| {
        let app = &app;
        async move {
            clients::create(
                &app.state,
                tenant_id,
                Actor::System,
                NewClient {
                    client_id: Some("app".into()),
                    name: "app".into(),
                    client_type: Some(ClientType::Machine),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .client_secret
            .unwrap()
            .to_string()
        }
    };
    app_client(app.tenant.id).await;
    let secret = app_client(other.id).await;

    // Userinfo of another tenant.
    let at = opaque(&app, app.tenant.id, owner, "app").await;
    let res = app
        .http
        .get(app.url(&format!("/t/{}/userinfo", other.slug)))
        .bearer_auth(&at)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    // ... while its own accepts it.
    let res = app
        .http
        .get(app.tenant_url("/userinfo"))
        .bearer_auth(&at)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // Introspection by the same-named client of another tenant.
    let answer: Value = app
        .http
        .post(app.url(&format!("/t/{}/introspect", other.slug)))
        .basic_auth("app", Some(&secret))
        .form(&[("token", at.as_str())])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(answer["active"], false, "{answer}");

    // The account and admin APIs of another tenant.
    let account = opaque(&app, app.tenant.id, owner, ACCOUNT_AUDIENCE).await;
    let res = app
        .http
        .get(app.url(&format!("/t/{}/account/me", other.slug)))
        .bearer_auth(&account)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let admin = opaque(&app, app.tenant.id, owner, ADMIN_AUDIENCE).await;
    let (status, _, _) = call(
        &app,
        Method::GET,
        &format!("/admin/tenants/{}/clients", other.slug),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = call(
        &app,
        Method::GET,
        &format!("/admin/tenants/{}/clients", app.tenant.slug),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn mappers_cannot_forge_bindings_actors_or_authorization_claims() {
    let app = TestApp::spawn().await;
    let manager = admin_token(&app, app.tenant.id, CLIENT_MANAGER_ROLE).await;
    let path = format!("/admin/tenants/{}/claim-mappers", app.tenant.slug);
    for (claim, value) in [
        ("cnf", json!({"jkt": "attacker-key"})),
        ("act", json!({"sub": "someone"})),
        ("roles", json!(["ridm:owner"])),
        ("groups", json!(["admins"])),
        ("permissions", json!(["orders:write"])),
    ] {
        let (status, body, _) = call(
            &app,
            Method::POST,
            &path,
            Some(&manager),
            Some(&json!({"name": format!("forge-{claim}"), "config": {
                "type": "hardcoded", "claim": claim, "value": value, "include_in": ["access"]
            }})),
        )
        .await;
        assert_eq!(status, 400, "{claim}: {body}");
    }
    // A template or attribute mapper cannot either.
    let (status, body, _) = call(
        &app,
        Method::POST,
        &path,
        Some(&manager),
        Some(&json!({"name": "tpl", "config": {
            "type": "template", "claim": "roles", "template": "admin", "include_in": ["access"]
        }})),
    )
    .await;
    assert_eq!(status, 400, "{body}");

    // A stored mapper that predates the rule is skipped when tokens are built.
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let user = user_with_role(&app, app.tenant.id, None).await;
    let user = users::get(&app.state, app.tenant.id, user).await.unwrap();
    let forged = |claim: &str, value: Value| ClaimMapper {
        name: format!("old-{claim}"),
        kind: MapperKind::Hardcoded {
            claim: claim.into(),
            value,
        },
        include_in: vec![TokenKind::Access],
    };
    let client = TokenClient {
        mappers: vec![
            forged("cnf", json!({"jkt": "attacker-key"})),
            forged("act", json!({"sub": "someone"})),
            forged("roles", json!(["ridm:owner"])),
            forged("permissions", json!(["orders:write"])),
        ],
        ..TokenClient::public("app")
    };
    let issued = tokens::issue_access_token(
        &app.state,
        AccessTokenRequest {
            tenant: &tenant,
            client: &client,
            user: Some(&user),
            scopes: &["openid".into()],
            audiences: &["app".into()],
            roles: &[],
            groups: &[],
            session_id: None,
            org_id: None,
            auth_time: None,
            amr: &["pwd".into()],
            acr: None,
            cnf_jkt: None,
            act: None,
        },
    )
    .await
    .unwrap();
    assert!(issued.claims.get("cnf").is_none(), "{:?}", issued.claims);
    assert!(issued.claims.get("act").is_none());
    assert!(issued.claims.get("permissions").is_none());
    assert_eq!(issued.claims["roles"], json!([]), "the real (empty) roles");
}
