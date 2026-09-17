//! The published `ridm-auth` crate against a real tenant: a token minted by
//! this server, over the wire, verified by the crate a relying party would
//! depend on — discovery, the published key set, rotation, and the permission
//! the resource server granted.

mod common;

use std::time::Duration;

use common::TestApp;
use ridm_api::models::{
    ClientType, NewClient, NewPermission, NewResourceServer, NewRole, Principal, grants,
};
use ridm_api::services::{clients, keys, resource_servers, roles};
use ridm_auth::{AuthError, Validator};
use ridm_core::events::Actor;
use serde_json::Value;

const ORDERS: &str = "https://orders.example";
const BILLING: &str = "https://billing.example";

struct Fx {
    app: TestApp,
    client_id: String,
    secret: String,
}

/// A machine client with a service account that holds `orders:read` on the
/// orders resource server.
async fn fixture() -> Fx {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;

    let rs = resource_servers::create(
        &app.state,
        tid,
        Actor::System,
        NewResourceServer {
            identifier: ORDERS.into(),
            name: "Orders".into(),
            token_ttl_secs: None,
            signing_alg: None,
            allow_offline_access: None,
        },
    )
    .await
    .unwrap();
    resource_servers::create(
        &app.state,
        tid,
        Actor::System,
        NewResourceServer {
            identifier: BILLING.into(),
            name: "Billing".into(),
            token_ttl_secs: None,
            signing_alg: None,
            allow_offline_access: None,
        },
    )
    .await
    .unwrap();
    let permission = resource_servers::create_permission(
        &app.state,
        tid,
        Actor::System,
        rs.id,
        NewPermission {
            name: "orders:read".into(),
            description: None,
        },
    )
    .await
    .unwrap();
    let role = roles::create(
        &app.state,
        tid,
        Actor::System,
        NewRole {
            name: "orders-reader".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    resource_servers::grant(&app.state, tid, Actor::System, role.id, permission.id)
        .await
        .unwrap();

    let created = clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("orders-job".into()),
            name: "Orders job".into(),
            client_type: Some(ClientType::Machine),
            allowed_grants: Some(vec![grants::CLIENT_CREDENTIALS.into()]),
            allowed_audiences: vec![ORDERS.into(), BILLING.into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (_, service_account) =
        clients::enable_service_account(&app.state, tid, Actor::System, created.client.id)
            .await
            .unwrap();
    roles::assign(
        &app.state,
        tid,
        Actor::System,
        role.id,
        Principal::User {
            id: service_account.id,
        },
    )
    .await
    .unwrap();

    let secret = created.client_secret.unwrap().to_string();
    Fx {
        app,
        client_id: created.client.client_id,
        secret,
    }
}

/// `client_credentials` for the orders audience, over HTTP.
async fn access_token(fx: &Fx) -> String {
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .basic_auth(&fx.client_id, Some(&fx.secret))
        .form(&[
            ("grant_type", grants::CLIENT_CREDENTIALS),
            ("resource", ORDERS),
        ])
        .send()
        .await
        .unwrap();
    let status = res.status();
    let body: Value = res.json().await.unwrap();
    assert_eq!(status, 200, "{body}");
    body["access_token"].as_str().unwrap().to_string()
}

/// A validator built the way a relying party would build one, against this
/// tenant's issuer.
async fn validator(fx: &Fx) -> Validator {
    Validator::builder(fx.app.tenant_url(""))
        .audience(ORDERS)
        // The test server speaks plain HTTP on a loopback port.
        .allow_http(true)
        .discover()
        .await
        .unwrap()
}

#[tokio::test]
async fn a_relying_party_verifies_a_token_this_server_issued() {
    let fx = fixture().await;
    let validator = validator(&fx).await;
    assert_eq!(
        validator.jwks_uri(),
        fx.app.tenant_url("/.well-known/jwks.json"),
        "discovery names the tenant's own key set"
    );

    let claims = validator.validate(&access_token(&fx).await).await.unwrap();

    assert_eq!(claims.iss, fx.app.tenant_url(""));
    assert_eq!(claims.aud, [ORDERS]);
    assert_eq!(claims.client_id.as_deref(), Some(fx.client_id.as_str()));
    assert_eq!(
        claims.tid.as_deref(),
        Some(fx.app.tenant.id.to_string().as_str())
    );
    assert!(claims.has_role("orders-reader"), "{:?}", claims.roles);
    claims.require_permission("orders:read").unwrap();

    let denied = claims.require_permission("orders:write").unwrap_err();
    assert_eq!(denied.status(), 403);
}

#[tokio::test]
async fn a_token_for_another_audience_does_not_open_this_api() {
    let fx = fixture().await;
    let validator = validator(&fx).await;

    // The same client, entitled to both APIs, asking for a token for billing.
    let res = fx
        .app
        .http
        .post(fx.app.tenant_url("/token"))
        .basic_auth(&fx.client_id, Some(&fx.secret))
        .form(&[
            ("grant_type", grants::CLIENT_CREDENTIALS),
            ("resource", BILLING),
        ])
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    let for_billing = body["access_token"].as_str().unwrap();

    let e = validator.validate(for_billing).await.unwrap_err();
    assert!(matches!(e, AuthError::WrongAudience(_)), "{e}");
    assert_eq!(e.status(), 401);
}

#[tokio::test]
async fn an_id_token_from_this_server_is_not_an_access_token() {
    let fx = fixture().await;
    let validator = validator(&fx).await;
    let token = access_token(&fx).await;

    // The header this server puts on an access token is what lets the crate
    // tell the two apart.
    let header = jsonwebtoken::decode_header(&token).unwrap();
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    validator.validate(&token).await.unwrap();
}

#[tokio::test]
async fn a_rotated_key_is_picked_up_without_restarting_the_relying_party() {
    let fx = fixture().await;
    let tid = fx.app.tenant.id;
    let tenant = ridm_api::services::tenants::get(&fx.app.state, tid)
        .await
        .unwrap();
    // No cooldown: the rotation is meant to be seen on the next request.
    let validator = Validator::builder(fx.app.tenant_url(""))
        .audience(ORDERS)
        .allow_http(true)
        .min_refresh_interval(Duration::ZERO)
        .discover()
        .await
        .unwrap();
    let before = access_token(&fx).await;
    validator.validate(&before).await.unwrap();

    keys::rotate(&fx.app.state, tid, &tenant.settings.keys, Actor::System)
        .await
        .unwrap();

    let after = access_token(&fx).await;
    assert_ne!(
        jsonwebtoken::decode_header(&after).unwrap().kid,
        jsonwebtoken::decode_header(&before).unwrap().kid,
        "the rotation put a new key in front"
    );
    validator.validate(&after).await.unwrap();
    validator
        .validate(&before)
        .await
        .expect("the retiring key still verifies what it signed");
}
