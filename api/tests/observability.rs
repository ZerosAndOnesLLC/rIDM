//! Metrics exposition. The audit export sink has its own suite
//! (`audit_sink.rs`).

mod common;

use std::sync::Arc;

use common::TestApp;
use ridm_api::util::secret::SecretString;

#[tokio::test]
async fn metrics_expose_requests_tokens_and_logins() {
    let app = TestApp::spawn().await;
    // A token request (refused) and a discovery fetch leave their marks.
    app.http
        .post(app.tenant_url("/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "nobody"),
        ])
        .send()
        .await
        .unwrap();
    app.http
        .get(app.tenant_url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap();
    let res = app.http.get(app.url("/metrics")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert!(
        res.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let body = res.text().await.unwrap();
    assert!(body.contains("ridm_http_requests_total{"), "{body}");
    assert!(body.contains("route=\"/t/{slug}/token\""), "{body}");
    assert!(
        body.contains("ridm_http_request_duration_seconds_bucket"),
        "{body}"
    );
    assert!(body.contains("ridm_token_requests_total{"), "{body}");
    assert!(body.contains("outcome=\"invalid_client\""), "{body}");
}

#[tokio::test]
async fn metrics_can_demand_a_token() {
    let app = TestApp::spawn_configured(axum::Router::new(), |state| {
        let mut config = (*state.config).clone();
        config.metrics_token = Some(SecretString::new("scrape-me".into()));
        state.config = Arc::new(config);
    })
    .await;
    let res = app.http.get(app.url("/metrics")).send().await.unwrap();
    assert_eq!(res.status(), 401);
    assert!(
        res.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("metrics")
    );
    let res = app
        .http
        .get(app.url("/metrics"))
        .bearer_auth("wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let res = app
        .http
        .get(app.url("/metrics"))
        .bearer_auth("scrape-me")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}
