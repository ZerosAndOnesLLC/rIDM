//! Regression: a confidential client keeps authenticating after its cached
//! document has been read back from Valkey (the in-process copy gone), and
//! so does RFC 7592 management with the registration token. Before Phase
//! 9.10 the Valkey copy lost both hashes and every node but the writer
//! refused the client after fifteen seconds.

mod common;

use common::TestApp;
use ridm_api::models::{ClientType, NewClient};
use ridm_api::services::clients;
use ridm_core::events::Actor;
use serde_json::Value;

#[tokio::test]
async fn a_confidential_client_survives_the_l1_cache_being_dropped() {
    let app = TestApp::spawn().await;
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
        .map(|s| s.to_string())
        .unwrap();
    let token = || {
        app.http
            .post(app.tenant_url("/token"))
            .basic_auth("svc", Some(&secret))
            .form(&[("grant_type", "client_credentials")])
            .send()
    };
    assert_eq!(
        token().await.unwrap().status(),
        200,
        "fresh from the database"
    );
    // Another node, or this one fifteen seconds later: the document comes
    // from Valkey.
    app.state.cache.l1().clear();
    let res = token().await.unwrap();
    assert_eq!(res.status(), 200, "{}", res.text().await.unwrap());
    // And a wrong secret is still wrong.
    let res = app
        .http
        .post(app.tenant_url("/token"))
        .basic_auth("svc", Some("nope"))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_client");
    // The admin view of the client never shows the hashes.
    let stored = clients::find_by_client_id(&app.state, app.tenant.id, "svc")
        .await
        .unwrap()
        .unwrap();
    let json = serde_json::to_value(&*stored).unwrap();
    assert!(json.get("secret_hashes").is_none());
    assert!(json.get("registration_access_token_hash").is_none());
    assert!(!stored.secret_hashes.is_empty(), "the service sees them");
}
