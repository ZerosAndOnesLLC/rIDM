//! Phase 13.4 (design review): the ways a Kerberos acceptor is classically
//! broken, each pinned.
//!
//! * **Replay.** An AP-REQ is a bearer credential for as long as its
//!   authenticator is fresh; one captured in transit (a proxy log, a TLS
//!   terminator) must sign nobody in a second time. Accepted authenticators
//!   are remembered.
//! * **Another tenant's service.** Two tenants may name the same service
//!   principal (two rIDMs behind one name, a copied configuration); a
//!   ticket opens only under the keytab it was issued for.
//! * **A foreign realm's namesake.** `alice@OTHER.REALM` is not
//!   `alice@EXAMPLE.COM`. By default only the service's own realm is
//!   accepted, so a trusted-but-foreign realm cannot sign in as the local
//!   `alice` by name.
//! * **Login CSRF.** The Kerberos step is a login-flow step: without the
//!   flow's CSRF token a ticket (or an attacker page driving the victim's
//!   browser to negotiate) signs nothing in.

#![cfg(feature = "kerberos")]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ridm_api::kerberos::testing::Kdc;
use ridm_api::models::{
    ClientType, IdpKind, KerberosSettings, NewClient, NewIdentityProvider, NewUser, WriteOnly,
};
use ridm_api::services::{clients, identity_providers, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};

use crate::common::TestApp;

const SPN: &str = "HTTP/sso.example.com@EXAMPLE.COM";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

async fn fixture(kdc: &Kdc) -> TestApp {
    let app = TestApp::spawn().await;
    clients::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("spa".into()),
            name: "My App".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://app.example/cb".into()],
            require_consent: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    users::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewUser {
            username: "alice".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    identity_providers::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewIdentityProvider {
            alias: "desktop".into(),
            kind: Some(IdpKind::Kerberos),
            kerberos: Some(KerberosSettings {
                keytab: Some(WriteOnly(B64.encode(kdc.keytab()))),
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    app
}

/// Start a flow and post a Negotiate token to its Kerberos step.
async fn negotiate(app: &TestApp, token: &[u8], csrf: Option<&str>) -> (u16, Value) {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let res = http
        .get(app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "openid"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let flow = loc
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .unwrap()
        .1
        .into_owned();
    let state: Value = http
        .get(app.tenant_url(&format!("/flows/{flow}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let res = http
        .post(app.tenant_url(&format!("/flows/{flow}/kerberos")))
        .header("Authorization", format!("Negotiate {}", B64.encode(token)))
        .json(&json!({"csrf": csrf.unwrap_or(state["csrf"].as_str().unwrap())}))
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    assert!(
        status == 200 || res.headers().get("set-cookie").is_none(),
        "a refused step set a session cookie"
    );
    (status, res.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_captured_authenticator_signs_nobody_in_twice() {
    let kdc = Kdc::new(SPN);
    let app = fixture(&kdc).await;
    let (token, _) = kdc
        .negotiate_token(&kdc.request("alice@EXAMPLE.COM"))
        .unwrap();
    assert_eq!(negotiate(&app, &token, None).await.0, 200);
    let (s, body) = negotiate(&app, &token, None).await;
    assert_eq!((s, body["error"].as_str()), (403, Some("kerberos_replay")));
}

#[tokio::test]
async fn a_ticket_for_another_tenants_keytab_is_refused() {
    let ours = Kdc::new(SPN);
    let theirs = Kdc::new(SPN);
    let app = fixture(&ours).await;
    let (token, _) = theirs
        .negotiate_token(&theirs.request("alice@EXAMPLE.COM"))
        .unwrap();
    let (s, body) = negotiate(&app, &token, None).await;
    assert_eq!((s, body["error"].as_str()), (403, Some("kerberos_invalid")));
}

#[tokio::test]
async fn a_foreign_realms_namesake_is_not_the_local_user() {
    let kdc = Kdc::new(SPN);
    let app = fixture(&kdc).await;
    // A KDC trusting OTHER.REALM (cross-realm) issues rIDM's service a
    // ticket for alice@OTHER.REALM: not accepted unless the realm is.
    let (token, _) = kdc
        .negotiate_token(&kdc.request("alice@OTHER.REALM"))
        .unwrap();
    let (s, body) = negotiate(&app, &token, None).await;
    assert_eq!((s, body["error"].as_str()), (403, Some("kerberos_invalid")));
}

#[tokio::test]
async fn the_kerberos_step_needs_the_flows_csrf_token() {
    let kdc = Kdc::new(SPN);
    let app = fixture(&kdc).await;
    let (token, _) = kdc
        .negotiate_token(&kdc.request("alice@EXAMPLE.COM"))
        .unwrap();
    let (s, _) = negotiate(&app, &token, Some("not-the-token")).await;
    assert_eq!(s, 403);
    // Refused before the ticket was looked at: it is still good once.
    assert_eq!(negotiate(&app, &token, None).await.0, 200);
}
