//! Security headers on every response and the cross-origin policy: the UI's
//! own origin everywhere, public documents for anyone, registered client
//! origins per tenant, and the per-client check at the token endpoint.

mod common;

use std::sync::Arc;

use common::TestApp;
use common::admin::{admin_token, call};
use ridm_api::models::{ClientType, NewClient};
use ridm_api::services::clients;
use ridm_core::events::Actor;
use serde_json::json;

fn header(res: &reqwest::Response, name: &str) -> Option<String> {
    res.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

async fn preflight(app: &TestApp, path: &str, origin: &str, method: &str) -> reqwest::Response {
    app.http
        .request(reqwest::Method::OPTIONS, app.url(path))
        .header("origin", origin)
        .header("access-control-request-method", method)
        .header(
            "access-control-request-headers",
            "authorization,content-type",
        )
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn api_responses_carry_hardening_headers() {
    let app = TestApp::spawn().await;
    for path in ["/healthz", "/openapi.json", "/t/nope/token"] {
        let res = app.http.get(app.url(path)).send().await.unwrap();
        assert_eq!(
            header(&res, "x-content-type-options").as_deref(),
            Some("nosniff"),
            "{path}"
        );
        assert_eq!(
            header(&res, "x-frame-options").as_deref(),
            Some("DENY"),
            "{path}"
        );
        assert_eq!(
            header(&res, "referrer-policy").as_deref(),
            Some("no-referrer"),
            "{path}"
        );
        assert_eq!(
            header(&res, "content-security-policy").as_deref(),
            Some("default-src 'none'; frame-ancestors 'none'"),
            "{path}"
        );
        assert!(
            header(&res, "strict-transport-security").is_none(),
            "plain http: no HSTS"
        );
    }
    // Swagger UI needs its scripts: only the framing rule.
    let res = app.http.get(app.url("/docs/")).send().await.unwrap();
    assert_eq!(
        header(&res, "content-security-policy").as_deref(),
        Some("frame-ancestors 'none'")
    );
}

#[tokio::test]
async fn hsts_follows_an_https_public_url() {
    let app = TestApp::spawn_configured(axum::Router::new(), |state| {
        let mut config = (*state.config).clone();
        config.public_url = "https://id.example.com".parse().unwrap();
        config.hsts_max_age = 3600;
        state.config = Arc::new(config);
    })
    .await;
    let res = app.http.get(app.url("/healthz")).send().await.unwrap();
    assert_eq!(
        header(&res, "strict-transport-security").as_deref(),
        Some("max-age=3600; includeSubDomains")
    );
    let off = TestApp::spawn_configured(axum::Router::new(), |state| {
        let mut config = (*state.config).clone();
        config.public_url = "https://id.example.com".parse().unwrap();
        config.hsts_max_age = 0;
        state.config = Arc::new(config);
    })
    .await;
    let res = off.http.get(off.url("/healthz")).send().await.unwrap();
    assert!(header(&res, "strict-transport-security").is_none());
}

#[tokio::test]
async fn public_documents_answer_any_origin() {
    let app = TestApp::spawn().await;
    for path in [
        format!("/t/{}/.well-known/openid-configuration", app.tenant.slug),
        format!("/t/{}/.well-known/jwks.json", app.tenant.slug),
        format!("/t/{}/branding", app.tenant.slug),
        "/.well-known/webfinger?resource=acct:x@example.com".to_string(),
    ] {
        let res = app
            .http
            .get(app.url(&path))
            .header("origin", "https://anyone.example")
            .send()
            .await
            .unwrap();
        assert_eq!(
            header(&res, "access-control-allow-origin").as_deref(),
            Some("https://anyone.example"),
            "{path}"
        );
        assert!(
            header(&res, "vary")
                .unwrap()
                .to_lowercase()
                .contains("origin")
        );
    }
}

#[tokio::test]
async fn ui_origin_may_call_everything_and_strangers_nothing() {
    let app = TestApp::spawn_configured(axum::Router::new(), |state| {
        let mut config = (*state.config).clone();
        config.ui_url = "https://ui.example.com".parse().unwrap();
        state.config = Arc::new(config);
    })
    .await;
    let flows = format!("/t/{}/flows/x", app.tenant.slug);
    for path in ["/admin/tenants", flows.as_str(), "/openapi.json"] {
        let res = preflight(&app, path, "https://ui.example.com", "GET").await;
        assert_eq!(res.status(), 200, "{path}");
        assert_eq!(
            header(&res, "access-control-allow-origin").as_deref(),
            Some("https://ui.example.com")
        );
        assert_eq!(
            header(&res, "access-control-allow-credentials").as_deref(),
            Some("true")
        );
        let allowed = header(&res, "access-control-allow-headers")
            .unwrap()
            .to_lowercase();
        assert!(allowed.contains("authorization") && allowed.contains("content-type"));
        assert_eq!(
            header(&res, "access-control-max-age").as_deref(),
            Some("600")
        );

        let res = preflight(&app, path, "https://evil.example", "GET").await;
        assert!(
            header(&res, "access-control-allow-origin").is_none(),
            "{path}"
        );
    }
    // The API's own origin counts as well (embedded mode).
    let own = app.base_url.clone();
    let res = preflight(&app, "/admin/tenants", &own, "GET").await;
    assert_eq!(header(&res, "access-control-allow-origin"), Some(own));
}

#[tokio::test]
async fn registered_client_origins_are_admitted_per_tenant() {
    let app = TestApp::spawn().await;
    let token_path = format!("/t/{}/token", app.tenant.slug);
    let res = preflight(&app, &token_path, "https://spa.example", "POST").await;
    assert!(
        header(&res, "access-control-allow-origin").is_none(),
        "unknown before registration"
    );

    let created = clients::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("spa".into()),
            name: "SPA".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://spa.example/cb".into()],
            cors_origins: vec!["https://spa.example".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let res = preflight(&app, &token_path, "https://spa.example", "POST").await;
    assert_eq!(
        header(&res, "access-control-allow-origin").as_deref(),
        Some("https://spa.example")
    );
    let res = app
        .http
        .post(app.url(&token_path))
        .header("origin", "https://spa.example")
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", "spa"),
            ("code", "x"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        header(&res, "access-control-allow-origin").as_deref(),
        Some("https://spa.example")
    );
    let exposed = header(&res, "access-control-expose-headers")
        .unwrap()
        .to_lowercase();
    assert!(exposed.contains("retry-after") && exposed.contains("ratelimit-remaining"));

    // Another tenant does not inherit the origin.
    let other = common::create_tenant(&app.state.db).await;
    let res = preflight(
        &app,
        &format!("/t/{}/token", other.slug),
        "https://spa.example",
        "POST",
    )
    .await;
    assert!(header(&res, "access-control-allow-origin").is_none());

    // Changing the client's origins takes effect at once (cache evicted).
    let bearer = admin_token(&app, app.tenant.id, "ridm:owner").await;
    let (status, _, _) = call(
        &app,
        reqwest::Method::PATCH,
        &format!(
            "/admin/tenants/{}/clients/{}",
            app.tenant.slug, created.client.id
        ),
        Some(&bearer),
        Some(&json!({ "cors_origins": ["https://other.example"] })),
    )
    .await;
    assert_eq!(status, 200);
    let res = preflight(&app, &token_path, "https://spa.example", "POST").await;
    assert!(header(&res, "access-control-allow-origin").is_none());
    let res = preflight(&app, &token_path, "https://other.example", "POST").await;
    assert_eq!(
        header(&res, "access-control-allow-origin").as_deref(),
        Some("https://other.example")
    );

    // Disabling the client withdraws its origins.
    let (status, _, _) = call(
        &app,
        reqwest::Method::PATCH,
        &format!(
            "/admin/tenants/{}/clients/{}",
            app.tenant.slug, created.client.id
        ),
        Some(&bearer),
        Some(&json!({ "status": "disabled" })),
    )
    .await;
    assert_eq!(status, 200);
    let res = preflight(&app, &token_path, "https://other.example", "POST").await;
    assert!(header(&res, "access-control-allow-origin").is_none());
}

#[tokio::test]
async fn token_endpoint_checks_the_origin_against_the_client_itself() {
    let app = TestApp::spawn().await;
    for (id, origin) in [("a", "https://a.example"), ("b", "https://b.example")] {
        clients::create(
            &app.state,
            app.tenant.id,
            Actor::System,
            NewClient {
                client_id: Some(id.into()),
                name: id.into(),
                client_type: Some(ClientType::Spa),
                redirect_uris: vec![format!("{origin}/cb")],
                cors_origins: vec![origin.into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    let token = |client: &'static str, origin: &'static str| {
        app.http
            .post(app.tenant_url("/token"))
            .header("origin", origin)
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", client),
                ("refresh_token", "nope"),
            ])
            .send()
    };
    // The tenant admits b's origin, but client a did not register it.
    let res = token("a", "https://b.example").await.unwrap();
    assert_eq!(res.status(), 400);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("origin")
    );
    // Its own origin passes the check (and then fails on the bogus token).
    let res = token("a", "https://a.example").await.unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    // The UI's origin is always fine (same-origin posts carry Origin too).
    let own = app.base_url.clone();
    let res = app
        .http
        .post(app.tenant_url("/token"))
        .header("origin", &own)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "a"),
            ("refresh_token", "nope"),
        ])
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    // No Origin header (a server-side client) is never checked.
    let res = app
        .http
        .post(app.tenant_url("/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "a"),
            ("refresh_token", "nope"),
        ])
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
}
