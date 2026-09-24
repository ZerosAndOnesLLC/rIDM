//! Custom domains: a tenant served on its own host, with the issuer and every
//! endpoint following, the primary paths still working, validation and
//! uniqueness of the domain, cache eviction on change, forwarded hosts only
//! from trusted proxies, and the custom origin admitted by CORS.

mod common;

use std::sync::Arc;

use common::TestApp;
use ridm_api::models::{ClientType, NewClient, TenantSettings};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_api::services::{clients, tenants as tenant_svc};
use ridm_core::events::Actor;
use serde_json::Value;
use uuid::Uuid;

async fn set_domain(app: &TestApp, tenant_id: Uuid, domain: Option<&str>) -> Result<(), String> {
    let current = tenant_svc::get(&app.state, tenant_id).await.unwrap();
    let settings = TenantSettings {
        custom_domain: domain.map(str::to_string),
        ..current.settings.0.clone()
    };
    tenants::update(
        &app.state,
        Actor::System,
        tenant_id,
        TenantUpdate {
            display_name: None,
            status: None,
            settings: Some(settings),
        },
    )
    .await
    .map(|_| ())
    .map_err(|e| e.to_string())
}

fn domain_for(app: &TestApp) -> String {
    format!("login-{}.acme.test", &app.tenant.slug[2..])
}

async fn on_host(app: &TestApp, host: &str, path: &str) -> reqwest::Response {
    app.http
        .get(app.url(path))
        .header("host", host)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn a_custom_host_serves_the_tenant_without_the_prefix() {
    let app = TestApp::spawn().await;
    let host = domain_for(&app);
    set_domain(&app, app.tenant.id, Some(&host)).await.unwrap();

    let res = on_host(&app, &host, "/.well-known/openid-configuration").await;
    assert_eq!(res.status(), 200);
    let doc: Value = res.json().await.unwrap();
    assert_eq!(doc["issuer"], format!("https://{host}"));
    assert_eq!(doc["token_endpoint"], format!("https://{host}/token"));
    assert_eq!(
        doc["jwks_uri"],
        format!("https://{host}/.well-known/jwks.json")
    );

    let res = on_host(&app, &host, "/.well-known/jwks.json").await;
    assert_eq!(res.status(), 200);
    let res = on_host(&app, &host, "/branding").await;
    assert_eq!(res.status(), 200);
    let res = on_host(&app, &host, &format!("/flows/{}", Uuid::new_v4())).await;
    assert_eq!(res.status(), 404, "a tenant route answered (unknown flow)");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["type"], "urn:ridm:error:not-found");

    // The primary path still works and carries the custom issuer.
    let res = app
        .http
        .get(app.tenant_url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap();
    let doc: Value = res.json().await.unwrap();
    assert_eq!(doc["issuer"], format!("https://{host}"));

    // Uppercase hosts and the same path on an unknown host.
    let res = on_host(
        &app,
        &host.to_uppercase(),
        "/.well-known/openid-configuration",
    )
    .await;
    assert_eq!(res.status(), 200);
    let res = on_host(
        &app,
        "nobody.acme.test",
        "/.well-known/openid-configuration",
    )
    .await;
    assert_eq!(res.status(), 404);
    // Global routes stay global on any host.
    assert_eq!(on_host(&app, &host, "/healthz").await.status(), 200);
}

#[tokio::test]
async fn tokens_issued_on_the_custom_host_carry_its_issuer() {
    let app = TestApp::spawn().await;
    let host = domain_for(&app);
    set_domain(&app, app.tenant.id, Some(&host)).await.unwrap();
    let created = clients::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("svc".into()),
            name: "svc".into(),
            client_type: Some(ClientType::Machine),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let secret = created
        .client_secret
        .as_deref()
        .map(|s| s.as_str())
        .unwrap();
    let res = app
        .http
        .post(app.url("/token"))
        .header("host", &host)
        .basic_auth("svc", Some(secret))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    let body: Value = res.json().await.unwrap();
    let jwt = body["access_token"].as_str().unwrap();
    let payload = jwt.split('.').nth(1).unwrap();
    use base64::Engine as _;
    let claims: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["iss"], format!("https://{host}"));
}

#[tokio::test]
async fn changing_or_clearing_the_domain_takes_effect_at_once() {
    let app = TestApp::spawn().await;
    let first = domain_for(&app);
    let second = format!("sso-{}.acme.test", &app.tenant.slug[2..]);
    set_domain(&app, app.tenant.id, Some(&first)).await.unwrap();
    assert_eq!(
        on_host(&app, &first, "/.well-known/jwks.json")
            .await
            .status(),
        200
    );
    set_domain(&app, app.tenant.id, Some(&second))
        .await
        .unwrap();
    assert_eq!(
        on_host(&app, &first, "/.well-known/jwks.json")
            .await
            .status(),
        404
    );
    assert_eq!(
        on_host(&app, &second, "/.well-known/jwks.json")
            .await
            .status(),
        200
    );
    set_domain(&app, app.tenant.id, None).await.unwrap();
    assert_eq!(
        on_host(&app, &second, "/.well-known/jwks.json")
            .await
            .status(),
        404
    );
}

#[tokio::test]
async fn domains_are_validated_and_unique() {
    let app = TestApp::spawn().await;
    for bad in [
        "not a host",
        "-x.example.com",
        "a..b",
        "host:0",
        "http://x.example.com",
    ] {
        let err = set_domain(&app, app.tenant.id, Some(bad))
            .await
            .unwrap_err();
        assert!(err.contains("custom_domain"), "{bad}: {err}");
    }
    let own = app.state.config.public_url.clone();
    let own_host = format!("{}:{}", own.host_str().unwrap(), own.port().unwrap());
    let err = set_domain(&app, app.tenant.id, Some(&own_host))
        .await
        .unwrap_err();
    assert!(err.contains("own host"), "{err}");
    // The same name on another port is another host.
    let other_port = own.port().unwrap().wrapping_add(1).max(1);
    let elsewhere = format!("{}:{other_port}", own.host_str().unwrap());
    let err = set_domain(&app, app.tenant.id, Some(&elsewhere)).await;
    assert!(
        !err.as_ref().is_err_and(|e| e.contains("own host")),
        "{err:?}"
    );

    let host = domain_for(&app);
    set_domain(
        &app,
        app.tenant.id,
        Some(&format!("  {}  ", host.to_uppercase())),
    )
    .await
    .unwrap();
    let stored = tenant_svc::get(&app.state, app.tenant.id).await.unwrap();
    assert_eq!(
        stored.settings.custom_domain.as_deref(),
        Some(host.as_str())
    );

    let other = common::create_tenant(&app.state.db).await;
    let err = set_domain(&app, other.id, Some(&host)).await.unwrap_err();
    assert!(err.contains("already used"), "{err}");
    // A port is allowed (dev setups).
    set_domain(&app, other.id, Some(&format!("{}:8443", domain_for(&app))))
        .await
        .unwrap();
}

#[tokio::test]
async fn forwarded_host_counts_only_behind_a_trusted_proxy() {
    let app = TestApp::spawn().await;
    let host = domain_for(&app);
    set_domain(&app, app.tenant.id, Some(&host)).await.unwrap();
    let res = app
        .http
        .get(app.url("/.well-known/jwks.json"))
        .header("x-forwarded-host", &host)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404, "loopback is not trusted here");

    let trusted = TestApp::spawn_configured(axum::Router::new(), |state| {
        let mut config = (*state.config).clone();
        config.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()];
        state.config = Arc::new(config);
    })
    .await;
    let host = domain_for(&trusted);
    set_domain(&trusted, trusted.tenant.id, Some(&host))
        .await
        .unwrap();
    let res = trusted
        .http
        .get(trusted.url("/.well-known/jwks.json"))
        .header("x-forwarded-host", format!("{host}, other.example"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn the_custom_origin_is_admitted_by_cors() {
    let app = TestApp::spawn().await;
    let host = domain_for(&app);
    set_domain(&app, app.tenant.id, Some(&host)).await.unwrap();
    let origin = format!("https://{host}");
    let res = app
        .http
        .request(reqwest::Method::OPTIONS, app.tenant_url("/token"))
        .header("origin", &origin)
        .header("access-control-request-method", "POST")
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some(origin.as_str())
    );
    // Another tenant does not admit it.
    let other = common::create_tenant(&app.state.db).await;
    let res = app
        .http
        .request(
            reqwest::Method::OPTIONS,
            app.url(&format!("/t/{}/token", other.slug)),
        )
        .header("origin", &origin)
        .header("access-control-request-method", "POST")
        .send()
        .await
        .unwrap();
    assert!(res.headers().get("access-control-allow-origin").is_none());
}
