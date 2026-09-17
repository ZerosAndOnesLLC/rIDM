//! Request ceilings: thresholds, headers, per-family error formats, the
//! per-client bucket, proxies and the deployment-wide address ceiling.

mod common;

use std::sync::Arc;

use common::TestApp;
use ridm_api::config::RateLimitConfig;
use ridm_api::models::{ClientType, NewClient, RateLimitPolicy, TenantSettings};
use ridm_api::services::clients;
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_core::events::Actor;
use serde_json::Value;
use uuid::Uuid;

/// An app with the limiter switched on (the harness default is off).
async fn limited_app(ip_per_minute: u32) -> TestApp {
    TestApp::spawn_configured(axum::Router::new(), move |state| {
        let mut config = (*state.config).clone();
        config.rate_limits = RateLimitConfig {
            enabled: true,
            ip_per_minute,
        };
        state.config = Arc::new(config);
    })
    .await
}

async fn set_policy(app: &TestApp, tenant_id: Uuid, policy: RateLimitPolicy) {
    let current = tenants::get(&app.state, tenant_id).await.unwrap();
    let settings = TenantSettings {
        rate_limits: policy,
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
    .unwrap();
}

fn policy(f: impl FnOnce(&mut RateLimitPolicy)) -> RateLimitPolicy {
    let mut p = RateLimitPolicy::default();
    f(&mut p);
    p
}

fn header(res: &reqwest::Response, name: &str) -> Option<String> {
    res.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
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

async fn token_call(app: &TestApp, client_id: &str) -> reqwest::Response {
    app.http
        .post(app.tenant_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", "nope"),
            ("redirect_uri", "https://app.example/cb"),
            (
                "code_verifier",
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            ),
        ])
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn token_endpoint_per_address_threshold_and_headers() {
    let app = limited_app(0).await;
    set_policy(&app, app.tenant.id, policy(|p| p.token_per_ip = 3)).await;

    for n in 1..=3u64 {
        let res = token_call(&app, "missing").await;
        assert_eq!(res.status(), 401, "request {n} is an ordinary refusal");
        assert_eq!(header(&res, "ratelimit-limit").as_deref(), Some("3"));
        assert_eq!(
            header(&res, "ratelimit-remaining"),
            Some((3 - n).to_string())
        );
        let reset: u64 = header(&res, "ratelimit-reset").unwrap().parse().unwrap();
        assert!((1..=60).contains(&reset));
    }
    let res = token_call(&app, "missing").await;
    assert_eq!(res.status(), 429);
    let retry: u64 = header(&res, "retry-after").unwrap().parse().unwrap();
    assert!((1..=60).contains(&retry));
    assert_eq!(header(&res, "ratelimit-remaining").as_deref(), Some("0"));
    assert_eq!(
        header(&res, "cache-control").as_deref(),
        Some("no-store"),
        "OAuth refusals are never cached"
    );
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "slow_down");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("retry after")
    );
}

#[tokio::test]
async fn flow_endpoints_refuse_with_problem_json() {
    let app = limited_app(0).await;
    set_policy(&app, app.tenant.id, policy(|p| p.flows_per_ip = 2)).await;
    let url = app.tenant_url(&format!("/flows/{}", Uuid::new_v4()));
    for _ in 0..2 {
        let res = app.http.get(&url).send().await.unwrap();
        assert_eq!(res.status(), 404);
    }
    let res = app.http.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 429);
    assert_eq!(
        header(&res, "content-type").as_deref(),
        Some("application/problem+json")
    );
    assert!(header(&res, "retry-after").is_some());
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["type"], "urn:ridm:error:rate-limited");
    assert_eq!(body["status"], 429);
}

#[tokio::test]
async fn authorize_refuses_with_an_html_page() {
    let app = limited_app(0).await;
    set_policy(&app, app.tenant.id, policy(|p| p.authorize_per_ip = 1)).await;
    let url = app.tenant_url("/authorize?client_id=x&response_type=code");
    let first = app.http.get(&url).send().await.unwrap();
    assert_ne!(first.status(), 429);
    let res = app.http.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 429);
    assert!(
        header(&res, "content-type")
            .unwrap()
            .starts_with("text/html")
    );
    assert!(header(&res, "retry-after").is_some());
    assert_eq!(
        header(&res, "content-security-policy").as_deref(),
        Some(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
    );
    let html = res.text().await.unwrap();
    assert!(html.contains("slow_down"));
    assert!(html.contains("Too many requests"));
}

#[tokio::test]
async fn families_and_tenants_have_separate_buckets() {
    let app = limited_app(0).await;
    set_policy(
        &app,
        app.tenant.id,
        policy(|p| {
            p.token_per_ip = 1;
            p.flows_per_ip = 1;
        }),
    )
    .await;
    // Token family exhausted ...
    token_call(&app, "missing").await;
    assert_eq!(token_call(&app, "missing").await.status(), 429);
    // ... the flow family still has its own request.
    let flow = app.tenant_url(&format!("/flows/{}", Uuid::new_v4()));
    assert_eq!(app.http.get(&flow).send().await.unwrap().status(), 404);
    assert_eq!(app.http.get(&flow).send().await.unwrap().status(), 429);
    // Another tenant is untouched (default policy).
    let other = common::create_tenant(&app.state.db).await;
    let res = app
        .http
        .post(app.url(&format!("/t/{}/token", other.slug)))
        .form(&[("grant_type", "client_credentials"), ("client_id", "x")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    assert_eq!(header(&res, "ratelimit-limit").as_deref(), Some("600"));
}

#[tokio::test]
async fn per_client_bucket_is_counted_before_credentials() {
    let app = limited_app(0).await;
    set_policy(&app, app.tenant.id, policy(|p| p.token_per_client = 2)).await;
    spa(&app, "one").await;
    spa(&app, "two").await;
    for _ in 0..2 {
        let res = token_call(&app, "one").await;
        assert_eq!(res.status(), 400, "invalid_grant, not yet limited");
    }
    let res = token_call(&app, "one").await;
    assert_eq!(res.status(), 429);
    assert!(header(&res, "retry-after").is_some());
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "slow_down");
    // A different client of the same tenant from the same address is fine.
    assert_eq!(token_call(&app, "two").await.status(), 400);
    // A wrong secret for a confidential client is counted the same way.
    let confidential = clients::create(
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
    let cid = confidential.client.client_id.clone();
    let guess = |n: u32| {
        app.http
            .post(app.tenant_url("/token"))
            .basic_auth(&cid, Some(format!("guess{n}")))
            .form(&[("grant_type", "client_credentials")])
            .send()
    };
    assert_eq!(guess(1).await.unwrap().status(), 401);
    assert_eq!(guess(2).await.unwrap().status(), 401);
    assert_eq!(guess(3).await.unwrap().status(), 429);
}

#[tokio::test]
async fn tenant_total_caps_every_family_together() {
    let app = limited_app(0).await;
    set_policy(&app, app.tenant.id, policy(|p| p.tenant_total = 3)).await;
    spa(&app, "counted-once").await;
    // A client-authenticated call is charged once, not again in client auth.
    assert_eq!(token_call(&app, "counted-once").await.status(), 400);
    let flow = app.tenant_url(&format!("/flows/{}", Uuid::new_v4()));
    assert_eq!(app.http.get(&flow).send().await.unwrap().status(), 404);
    assert_eq!(app.http.get(&flow).send().await.unwrap().status(), 404);
    assert_eq!(app.http.get(&flow).send().await.unwrap().status(), 429);
}

#[tokio::test]
async fn switching_the_policy_off_lifts_every_tenant_limit() {
    let app = limited_app(0).await;
    set_policy(
        &app,
        app.tenant.id,
        policy(|p| {
            p.enabled = false;
            p.token_per_ip = 1;
            p.tenant_total = 1;
        }),
    )
    .await;
    for _ in 0..3 {
        let res = token_call(&app, "missing").await;
        assert_eq!(res.status(), 401);
        assert!(header(&res, "ratelimit-limit").is_none());
    }
}

#[tokio::test]
async fn deployment_wide_address_ceiling_spans_tenants() {
    // The bucket is keyed by address and outlives the test (60 s window), so
    // a forwarded address unique to this run stands in for the loopback peer.
    let app = TestApp::spawn_configured(axum::Router::new(), |state| {
        let mut config = (*state.config).clone();
        config.rate_limits = RateLimitConfig {
            enabled: true,
            ip_per_minute: 2,
        };
        config.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()];
        state.config = Arc::new(config);
    })
    .await;
    let bytes = Uuid::new_v4().into_bytes();
    let ip = format!("198.51.{}.{}", bytes[0], bytes[1]);
    let other = common::create_tenant(&app.state.db).await;
    let post = |slug: &str| {
        app.http
            .post(app.url(&format!("/t/{slug}/token")))
            .header("x-forwarded-for", ip.as_str())
            .form(&[("grant_type", "client_credentials"), ("client_id", "x")])
            .send()
    };
    assert_eq!(post(&app.tenant.slug).await.unwrap().status(), 401);
    let res = post(&other.slug).await.unwrap();
    assert_eq!(res.status(), 401);
    assert_eq!(header(&res, "ratelimit-limit").as_deref(), Some("2"));
    assert_eq!(post(&app.tenant.slug).await.unwrap().status(), 429);
    // Unlimited endpoints are not counted.
    let disc = app.tenant_url("/.well-known/openid-configuration");
    let res = app
        .http
        .get(&disc)
        .header("x-forwarded-for", ip.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert!(header(&res, "ratelimit-limit").is_none());
}

#[tokio::test]
async fn forwarded_addresses_count_only_behind_a_trusted_proxy() {
    // Peer 127.0.0.1 is not trusted: every X-Forwarded-For shares one bucket.
    let app = limited_app(0).await;
    set_policy(&app, app.tenant.id, policy(|p| p.flows_per_ip = 1)).await;
    let flow = app.tenant_url(&format!("/flows/{}", Uuid::new_v4()));
    let with_xff = |ip: &str| app.http.get(&flow).header("x-forwarded-for", ip).send();
    assert_eq!(with_xff("203.0.113.1").await.unwrap().status(), 404);
    assert_eq!(with_xff("203.0.113.2").await.unwrap().status(), 429);

    // Trusted: each forwarded address has its own bucket.
    let trusted = TestApp::spawn_configured(axum::Router::new(), |state| {
        let mut config = (*state.config).clone();
        config.rate_limits = RateLimitConfig {
            enabled: true,
            ip_per_minute: 0,
        };
        config.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()];
        state.config = Arc::new(config);
    })
    .await;
    set_policy(&trusted, trusted.tenant.id, policy(|p| p.flows_per_ip = 1)).await;
    let flow = trusted.tenant_url(&format!("/flows/{}", Uuid::new_v4()));
    let with = |name: &'static str, value: &str| trusted.http.get(&flow).header(name, value).send();
    // Our own hop at the end is walked back over: the bucket is the client's.
    assert_eq!(
        with("x-forwarded-for", "203.0.113.1, 127.0.0.1")
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        with("x-forwarded-for", "203.0.113.1")
            .await
            .unwrap()
            .status(),
        429
    );
    // Prepending an address of their choosing does not buy a fresh bucket:
    // the rightmost entry that is not one of ours is what counts.
    assert_eq!(
        with("x-forwarded-for", "198.51.100.5, 203.0.113.1")
            .await
            .unwrap()
            .status(),
        429
    );
    assert_eq!(
        with("x-forwarded-for", "203.0.113.2")
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        with("forwarded", "for=\"[2001:db8::7]\";proto=https")
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        with("forwarded", "for=[2001:db8::7]:4000")
            .await
            .unwrap()
            .status(),
        429
    );
}

#[tokio::test]
async fn admin_settings_reject_a_bad_window() {
    let app = limited_app(0).await;
    let err = tenants::update(
        &app.state,
        Actor::System,
        app.tenant.id,
        TenantUpdate {
            display_name: None,
            status: None,
            settings: Some(TenantSettings {
                rate_limits: policy(|p| p.window_secs = 0),
                ..Default::default()
            }),
        },
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("window_secs"));
}

#[tokio::test]
async fn limiter_is_inert_when_disabled_for_the_deployment() {
    let app = TestApp::spawn().await;
    set_policy(&app, app.tenant.id, policy(|p| p.token_per_ip = 1)).await;
    for _ in 0..3 {
        let res = token_call(&app, "missing").await;
        assert_eq!(res.status(), 401);
        assert!(header(&res, "ratelimit-limit").is_none());
    }
}
