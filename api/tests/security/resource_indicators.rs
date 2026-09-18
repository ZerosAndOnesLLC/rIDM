//! Review finding (Phase 10): a refresh request's `resource` could name any
//! audience the client was allowed, not only one of the original grant's
//! (RFC 8707 §2.2), so a token granted for one API could be refreshed into
//! a token for another. A refresh may now narrow the audience, never widen
//! it, and a refused request leaves the refresh token unspent.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ridm_api::models::{NewClient, NewResourceServer};
use ridm_api::services::resource_servers;
use ridm_core::events::Actor;
use serde_json::{Value, json};

use crate::common::TestApp;
use crate::support::{self, param};

const ORDERS: &str = "https://orders.example";
const BILLING: &str = "https://billing.example";

fn aud(access_token: &str) -> Value {
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(access_token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    claims["aud"].clone()
}

#[tokio::test]
async fn a_refresh_cannot_widen_the_audience() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let slug = app.tenant.slug.clone();
    for identifier in [ORDERS, BILLING] {
        resource_servers::create(
            &app.state,
            tid,
            Actor::System,
            NewResourceServer {
                identifier: identifier.into(),
                name: identifier.into(),
                token_ttl_secs: None,
                signing_alg: None,
                allow_offline_access: None,
            },
        )
        .await
        .unwrap();
    }
    support::spa(
        &app,
        tid,
        NewClient {
            allowed_audiences: vec![ORDERS.into(), BILLING.into()],
            ..Default::default()
        },
    )
    .await;
    let alice = support::user_with_password(&app, tid, "alice").await;
    let (_, cookie) = support::session(&app, tid, &slug, alice).await;

    // The grant is for the orders API only.
    let loc = support::authorize(
        &app.http,
        &app,
        &slug,
        Some(&cookie),
        &[("resource", ORDERS)],
    )
    .await;
    let code = param(&loc, "code").expect("a code");
    let (status, tokens) = support::exchange(&app, &slug, &code).await;
    assert_eq!(status, 200, "{tokens}");
    let rt = tokens["refresh_token"].as_str().unwrap().to_string();

    // Refreshing into the billing API is refused...
    let (status, body) = support::refresh(&app, &slug, &rt, &[("resource", BILLING)]).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_target");

    // ... and did not spend the token: the same one still refreshes, within
    // the original audience.
    let (status, body) = support::refresh(&app, &slug, &rt, &[("resource", ORDERS)]).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        [json!(ORDERS), json!([ORDERS])].contains(&aud(body["access_token"].as_str().unwrap())),
        "{body}"
    );

    // The same holds at the code exchange: /authorize named the resources.
    let loc = support::authorize(
        &app.http,
        &app,
        &slug,
        Some(&cookie),
        &[("resource", ORDERS)],
    )
    .await;
    let code = param(&loc, "code").unwrap();
    let (status, body) = support::token(
        &app,
        &slug,
        &[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", support::REDIRECT),
            ("code_verifier", crate::VERIFIER),
            ("client_id", "spa"),
            ("resource", BILLING),
        ],
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_target");
}
