//! IP allow/deny rules in force: tenant-wide rules on every guarded family,
//! client-scoped rules at `/authorize` and the client-authenticated
//! endpoints, allow-list and longest-prefix semantics, immediate effect of
//! changes, and untouched endpoints.

mod common;

use std::sync::Arc;

use common::TestApp;
use ridm_api::models::{ClientType, IpRuleAction, IpRuleUpdate, NewClient, NewIpRule};
use ridm_api::services::{clients, ip_rules};
use ridm_core::events::Actor;
use serde_json::Value;
use uuid::Uuid;

/// Loopback is a trusted proxy, so tests choose the client address with `X-Forwarded-For`.
async fn app() -> TestApp {
    TestApp::spawn_configured(axum::Router::new(), |state| {
        let mut config = (*state.config).clone();
        config.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()];
        state.config = Arc::new(config);
    })
    .await
}

async fn rule(app: &TestApp, client_id: Option<Uuid>, action: IpRuleAction, cidr: &str) -> Uuid {
    ip_rules::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewIpRule {
            client_id,
            action: Some(action),
            cidr: cidr.into(),
            description: None,
        },
    )
    .await
    .unwrap()
    .id
}

async fn spa(app: &TestApp, id: &str) -> Uuid {
    clients::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some(id.into()),
            name: id.into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://app.example/cb".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .client
    .id
}

async fn token_from(app: &TestApp, ip: &str, client_id: &str) -> reqwest::Response {
    app.http
        .post(app.tenant_url("/token"))
        .header("x-forwarded-for", ip)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("refresh_token", "nope"),
        ])
        .send()
        .await
        .unwrap()
}

async fn flow_from(app: &TestApp, ip: &str) -> reqwest::Response {
    app.http
        .get(app.tenant_url(&format!("/flows/{}", Uuid::new_v4())))
        .header("x-forwarded-for", ip)
        .send()
        .await
        .unwrap()
}

async fn authorize_from(app: &TestApp, ip: &str, client_id: &str) -> reqwest::Response {
    app.http
        .get(app.tenant_url(&format!(
            "/authorize?client_id={client_id}&response_type=code&redirect_uri=https://app.example/cb&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
        )))
        .header("x-forwarded-for", ip)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn tenant_deny_rule_refuses_every_guarded_family_in_its_own_format() {
    let app = app().await;
    spa(&app, "spa").await;
    rule(&app, None, IpRuleAction::Deny, "203.0.113.0/24").await;

    let res = token_from(&app, "203.0.113.5", "spa").await;
    assert_eq!(res.status(), 400, "OAuth access_denied");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "access_denied");

    let res = flow_from(&app, "203.0.113.5").await;
    assert_eq!(res.status(), 403);
    assert_eq!(
        res.headers()["content-type"].to_str().unwrap(),
        "application/problem+json"
    );
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["type"], "urn:ridm:error:forbidden");

    let res = authorize_from(&app, "203.0.113.5", "spa").await;
    assert_eq!(res.status(), 403);
    assert!(
        res.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    assert!(res.text().await.unwrap().contains("access_denied"));

    // Other addresses are untouched, and so is the unguarded discovery document.
    assert_eq!(token_from(&app, "198.51.100.1", "spa").await.status(), 400);
    let body: Value = token_from(&app, "198.51.100.1", "spa")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(flow_from(&app, "198.51.100.1").await.status(), 404);
    let res = app
        .http
        .get(app.tenant_url("/.well-known/openid-configuration"))
        .header("x-forwarded-for", "203.0.113.5")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn allow_rules_turn_the_scope_into_an_allow_list_with_longest_prefix() {
    let app = app().await;
    rule(&app, None, IpRuleAction::Allow, "10.0.0.0/8").await;
    rule(&app, None, IpRuleAction::Deny, "10.1.0.0/16").await;
    rule(&app, None, IpRuleAction::Allow, "10.1.2.0/24").await;
    assert_eq!(flow_from(&app, "10.9.9.9").await.status(), 404);
    assert_eq!(flow_from(&app, "10.1.5.5").await.status(), 403);
    assert_eq!(flow_from(&app, "10.1.2.3").await.status(), 404);
    assert_eq!(
        flow_from(&app, "192.0.2.1").await.status(),
        403,
        "not on the list"
    );
    assert_eq!(flow_from(&app, "2001:db8::1").await.status(), 403);
}

#[tokio::test]
async fn client_rules_bind_one_client_only() {
    let app = app().await;
    let a = spa(&app, "a").await;
    spa(&app, "b").await;
    rule(&app, Some(a), IpRuleAction::Deny, "203.0.113.0/24").await;

    let res = token_from(&app, "203.0.113.7", "a").await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "access_denied");
    let res = token_from(&app, "203.0.113.7", "b").await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");

    assert_eq!(authorize_from(&app, "203.0.113.7", "a").await.status(), 403);
    let res = authorize_from(&app, "203.0.113.7", "b").await;
    assert_eq!(res.status(), 303, "sent to the login page");

    // A confidential client is refused before its secret is examined.
    let conf = clients::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("conf".into()),
            name: "conf".into(),
            client_type: Some(ClientType::Web),
            redirect_uris: vec!["https://app.example/cb".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    rule(
        &app,
        Some(conf.client.id),
        IpRuleAction::Allow,
        "192.0.2.0/24",
    )
    .await;
    let res = app
        .http
        .post(app.tenant_url("/introspect"))
        .header("x-forwarded-for", "198.51.100.9")
        .basic_auth(
            "conf",
            Some(conf.client_secret.as_deref().map(|s| s.as_str()).unwrap()),
        )
        .form(&[("token", "x")])
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "access_denied");
    let res = app
        .http
        .post(app.tenant_url("/introspect"))
        .header("x-forwarded-for", "192.0.2.9")
        .basic_auth(
            "conf",
            Some(conf.client_secret.as_deref().map(|s| s.as_str()).unwrap()),
        )
        .form(&[("token", "x")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["active"], false);
}

#[tokio::test]
async fn rule_changes_take_effect_at_once() {
    let app = app().await;
    let id = rule(&app, None, IpRuleAction::Deny, "203.0.113.0/24").await;
    assert_eq!(flow_from(&app, "203.0.113.1").await.status(), 403);
    ip_rules::update(
        &app.state,
        app.tenant.id,
        Actor::System,
        id,
        IpRuleUpdate {
            cidr: Some("203.0.113.128/25".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(flow_from(&app, "203.0.113.1").await.status(), 404);
    assert_eq!(flow_from(&app, "203.0.113.200").await.status(), 403);
    ip_rules::delete(&app.state, app.tenant.id, Actor::System, id)
        .await
        .unwrap();
    assert_eq!(flow_from(&app, "203.0.113.200").await.status(), 404);
}

#[tokio::test]
async fn rules_of_another_tenant_do_not_apply() {
    let app = app().await;
    rule(&app, None, IpRuleAction::Deny, "203.0.113.0/24").await;
    let other = common::create_tenant(&app.state.db).await;
    let res = app
        .http
        .get(app.url(&format!("/t/{}/flows/{}", other.slug, Uuid::new_v4())))
        .header("x-forwarded-for", "203.0.113.1")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test]
async fn untrusted_forwarding_headers_cannot_dodge_a_rule() {
    // No trusted proxies: the peer (loopback) is the client, whatever the header says.
    let app = TestApp::spawn().await;
    rule(&app, None, IpRuleAction::Deny, "127.0.0.0/8").await;
    assert_eq!(flow_from(&app, "198.51.100.1").await.status(), 403);
}
