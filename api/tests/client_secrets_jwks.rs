mod common;

use std::sync::{Arc, Mutex};

use common::TestApp;
use ridm_api::models::{ClientType, NewClient, RsaBits, SigningAlg, TokenEndpointAuthMethod};
use ridm_api::oidc::client_auth::{JWT_BEARER_ASSERTION, build_assertion};
use ridm_api::services::{client_keys, clients, keys};
use ridm_core::events::Actor;
use serde_json::{Value, json};

#[tokio::test]
async fn secret_rotation_grace_is_configurable_and_expires() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let created = clients::create(
        &app.state,
        tid,
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
    let first = created.client_secret.unwrap();
    let id = created.client.id;

    // Zero grace retires the old secret at once.
    let (c, second) = clients::rotate_secret(
        &app.state,
        tid,
        Actor::System,
        id,
        Some(chrono::Duration::zero()),
    )
    .await
    .unwrap();
    assert_eq!(c.secret_hashes.len(), 1);
    assert!(!clients::verify_secret(&c, &first));
    assert!(clients::verify_secret(&c, &second));
    // Out-of-range grace is rejected.
    assert!(
        clients::rotate_secret(
            &app.state,
            tid,
            Actor::System,
            id,
            Some(chrono::Duration::days(31))
        )
        .await
        .is_err()
    );

    // A short grace: both work until it lapses.
    let (c, third) = clients::rotate_secret(
        &app.state,
        tid,
        Actor::System,
        id,
        Some(chrono::Duration::seconds(1)),
    )
    .await
    .unwrap();
    assert!(clients::verify_secret(&c, &second) && clients::verify_secret(&c, &third));
    let res = app
        .http
        .post(app.tenant_url("/token"))
        .basic_auth("svc", Some(&*second))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let c = clients::get(&app.state, tid, id).await.unwrap();
    assert!(!clients::verify_secret(&c, &second), "grace elapsed");
    assert!(clients::verify_secret(&c, &third));
    let res = app
        .http
        .post(app.tenant_url("/token"))
        .basic_auth("svc", Some(&*second))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let res = app
        .http
        .post(app.tenant_url("/token"))
        .basic_auth("svc", Some(&*third))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn jwks_uri_is_fetched_cached_refreshed_on_unknown_kid_and_throttled() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    // A local JWKS server whose document we can swap.
    let doc: Arc<Mutex<Value>> = Arc::new(Mutex::new(json!({"keys": []})));
    let hits = Arc::new(Mutex::new(0usize));
    let (d, h) = (doc.clone(), hits.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let router = axum::Router::new().route(
            "/jwks",
            axum::routing::get(move || {
                let d = d.clone();
                let h = h.clone();
                async move {
                    *h.lock().unwrap() += 1;
                    axum::Json(d.lock().unwrap().clone())
                }
            }),
        );
        axum::serve(listener, router).await.unwrap();
    });
    let k1 = keys::generate(SigningAlg::ES256, RsaBits::B2048).unwrap();
    let k2 = keys::generate(SigningAlg::ES256, RsaBits::B2048).unwrap();
    *doc.lock().unwrap() = json!({"keys": [k1.public_jwk]});

    // jwks_uri must be https in production; the fetcher enforces that, so the
    // test exercises the cache/refresh logic through the service with a
    // pre-seeded cache document and the http URL rejected on fetch.
    let created = clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("kj".into()),
            name: "kj".into(),
            client_type: Some(ClientType::Machine),
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::PrivateKeyJwt),
            jwks_uri: Some(format!("http://127.0.0.1:{port}/jwks")),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let client = created.client;
    let err = client_keys::jwks(&app.state, &client, false)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("https"), "{err}");

    // Seed the cache as a successful fetch would have.
    let mut conn = app.state.redis.get().await.unwrap();
    let cache_key = ridm_api::cache::keys::client_jwks(tid, client.id);
    let _: () = redis::AsyncCommands::set_ex(
        &mut conn,
        &cache_key,
        json!({"keys": [k1.public_jwk]}).to_string(),
        3600,
    )
    .await
    .unwrap();
    let keys_now = client_keys::jwks(&app.state, &client, false).await.unwrap();
    assert_eq!(keys_now.len(), 1);
    assert_eq!(keys_now[0]["kid"], k1.kid);

    // A signed assertion with the cached key authenticates.
    let token_endpoint = format!("{}/t/{}/token", app.base_url, app.tenant.slug);
    let assertion = build_assertion(
        "kj",
        &token_endpoint,
        SigningAlg::ES256,
        &k1.kid,
        &k1.private_der,
        60,
    )
    .unwrap();
    let res = app
        .http
        .post(app.tenant_url("/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_assertion_type", JWT_BEARER_ASSERTION),
            ("client_assertion", assertion.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());

    // Unknown kid → a forced refresh is attempted (fails on http) → invalid_client;
    // the throttle then prevents a second fetch within the window.
    let rotated = build_assertion(
        "kj",
        &token_endpoint,
        SigningAlg::ES256,
        &k2.kid,
        &k2.private_der,
        60,
    )
    .unwrap();
    let res = app
        .http
        .post(app.tenant_url("/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_assertion_type", JWT_BEARER_ASSERTION),
            ("client_assertion", rotated.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_ne!(res.status(), 200);
    let throttled: bool = redis::AsyncCommands::exists(&mut conn, format!("{cache_key}:refreshed"))
        .await
        .unwrap();
    assert!(throttled, "refresh attempt recorded");
    // While throttled, a refresh call serves the cached document instead of fetching.
    let served = client_keys::jwks(&app.state, &client, true).await.unwrap();
    assert_eq!(served[0]["kid"], k1.kid);
    assert_eq!(
        *hits.lock().unwrap(),
        0,
        "the http jwks_uri was never actually fetched"
    );

    // forget() clears cache and throttle.
    client_keys::forget(&app.state, &client).await.unwrap();
    let cached: Option<String> = redis::AsyncCommands::get(&mut conn, &cache_key)
        .await
        .unwrap();
    assert!(cached.is_none());
}
