//! Phase 12.5: feature flags — stored with the tenant's settings, on or off
//! tenant-wide and per organization, and read by applications through the
//! `features` scope (a claim) or `GET /t/{slug}/features`.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::TestApp;
use common::admin::{admin_token, call};
use reqwest::Method;
use ridm_api::models::{NewOrganization, NewUser};
use ridm_api::services::admin_access::OWNER_ROLE;
use ridm_api::services::tokens::{self, AccessTokenRequest, IdTokenRequest, TokenClient};
use ridm_api::services::{organizations, tenants, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

fn payload(jwt: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

/// `PATCH` the tenant's settings with `features` (everything else default).
async fn set_flags(app: &TestApp, owner: &str, features: Value) -> (u16, Value) {
    let (status, body, _) = call(
        app,
        Method::PATCH,
        &format!("/admin/tenants/{}", app.tenant.slug),
        Some(owner),
        Some(&json!({ "settings": { "features": features } })),
    )
    .await;
    (status.as_u16(), body)
}

/// An access token for a user of the tenant, as a sign-in with `scopes`
/// acting in `org_id` would mint it.
async fn user_token(app: &TestApp, scopes: &[&str], org_id: Option<Uuid>) -> (String, String) {
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let user = users::create(
        &app.state,
        tenant.id,
        Actor::System,
        NewUser {
            username: format!("u-{}", &Uuid::now_v7().simple().to_string()[20..]),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    let client = TokenClient::public("app");
    let at = tokens::issue_access_token(
        &app.state,
        AccessTokenRequest {
            tenant: &tenant,
            client: &client,
            user: Some(&user),
            scopes: &scopes,
            audiences: &[],
            roles: &[],
            groups: &[],
            session_id: None,
            org_id,
            auth_time: None,
            amr: &[],
            acr: None,
            cnf_jkt: None,
            act: None,
        },
    )
    .await
    .unwrap()
    .token;
    let id = tokens::issue_id_token(
        &app.state,
        IdTokenRequest {
            tenant: &tenant,
            client: &client,
            user: &user,
            scopes: &scopes,
            roles: &[],
            groups: &[],
            session_id: None,
            auth_time: chrono::Utc::now(),
            org_id,
            nonce: None,
            amr: &[],
            acr: None,
            access_token: Some(&at),
            code: None,
            act: None,
        },
    )
    .await
    .unwrap()
    .token;
    (at, id)
}

async fn features_endpoint(app: &TestApp, bearer: Option<&str>) -> (u16, Value) {
    let mut req = app.http.get(app.tenant_url("/features"));
    if let Some(b) = bearer {
        req = req.bearer_auth(b);
    }
    let res = req.send().await.unwrap();
    (
        res.status().as_u16(),
        res.json().await.unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn flags_reach_applications_per_organization() {
    let app = TestApp::spawn().await;
    let owner = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let acme = organizations::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewOrganization {
            slug: "acme".into(),
            display_name: "Acme".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (status, body) = set_flags(
        &app,
        &owner,
        json!({
            "new-checkout": {"enabled": true, "description": "The rebuilt checkout"},
            "beta.reports": {"enabled": false, "organizations": {"acme": true}},
            // A stored document from before descriptions: a bare boolean.
            "legacy": true,
        }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["settings"]["features"]["legacy"],
        json!({"enabled": true}),
        "stored in the full form"
    );

    // Tenant-wide, through the scope: the claim lists what is on.
    let (at, id) = user_token(&app, &["openid", "features"], None).await;
    assert_eq!(payload(&at)["features"], json!(["legacy", "new-checkout"]));
    assert_eq!(payload(&id)["features"], payload(&at)["features"]);
    // In Acme, its own value wins.
    let (at_acme, _) = user_token(&app, &["openid", "features"], Some(acme.id)).await;
    assert_eq!(
        payload(&at_acme)["features"],
        json!(["beta.reports", "legacy", "new-checkout"])
    );
    // Without the scope there is no claim.
    let (plain, _) = user_token(&app, &["openid"], Some(acme.id)).await;
    assert!(payload(&plain).get("features").is_none());

    // The endpoint reads them live, for whatever token of the tenant.
    let (status, live) = features_endpoint(&app, Some(&plain)).await;
    assert_eq!(status, 200, "{live}");
    assert_eq!(live["features"], payload(&at_acme)["features"]);
    assert_eq!(live["org_id"], acme.id.to_string());
    set_flags(
        &app,
        &owner,
        json!({"beta.reports": {"enabled": false, "organizations": {"acme": false}}}),
    )
    .await;
    let (_, live) = features_endpoint(&app, Some(&plain)).await;
    assert_eq!(
        live["features"],
        json!(["legacy", "new-checkout"]),
        "a change shows at once"
    );
}

#[tokio::test]
async fn the_endpoint_wants_a_token_of_that_tenant() {
    let app = TestApp::spawn().await;
    let (status, _) = features_endpoint(&app, None).await;
    assert_eq!(status, 401);
    let (status, _) = features_endpoint(&app, Some("not-a-token")).await;
    assert_eq!(status, 401);
    let other = TestApp::spawn().await;
    let (foreign, _) = user_token(&other, &["openid"], None).await;
    let (status, _) = features_endpoint(&app, Some(&foreign)).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn bad_flags_are_refused_and_no_mapper_may_write_the_claim() {
    let app = TestApp::spawn().await;
    let owner = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    for bad in [
        json!({"Has Spaces": true}),
        json!({"ok": {"enabled": true, "organizations": {"Not A Slug": true}}}),
        json!({"ok": {"enabled": true, "description": "d".repeat(501)}}),
        json!({"ok": {"enabled": true, "surprise": 1}}),
    ] {
        let (status, body) = set_flags(&app, &owner, bad.clone()).await;
        assert!(status == 400 || status == 422, "{bad}: {status} {body}");
    }
    let (status, body, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/claim-mappers", app.tenant.slug),
        Some(&owner),
        Some(&json!({
            "name": "sneaky",
            "config": {"type": "hardcoded", "claim": "features", "value": ["all"], "include_in": ["access"]}
        })),
    )
    .await;
    assert_eq!(status.as_u16(), 400, "{body}");
}
