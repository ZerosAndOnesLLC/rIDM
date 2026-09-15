//! End-to-end walk of a relying party through the public HTTP surface only:
//! discovery → PAR → authorize → token → userinfo → refresh → introspect →
//! revoke → RP-initiated logout. No internal service calls except seeding.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::TestApp;
use ridm_api::models::{ClientType, NewClient, NewUser};
use ridm_api::services::sessions::{self, NewSession};
use ridm_api::services::{clients, tenants, users};
use ridm_core::events::Actor;
use serde_json::Value;

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

#[tokio::test]
async fn relying_party_journey() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let user = users::create(
        &app.state,
        tid,
        Actor::System,
        NewUser {
            username: "alice".into(),
            email: Some("alice@example.com".into()),
            email_verified: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let rp = clients::create(
        &app.state,
        tid,
        Actor::System,
        NewClient {
            client_id: Some("rp".into()),
            name: "RP".into(),
            client_type: Some(ClientType::Web),
            redirect_uris: vec!["https://rp.example/cb".into()],
            post_logout_redirect_uris: vec!["https://rp.example/".into()],
            require_consent: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let secret = rp.client_secret.unwrap();
    // The browser has an SSO session (Phase 4 adds the login UI that creates it).
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    let session = sessions::create(
        &app.state,
        tid,
        NewSession {
            user_id: user.id,
            amr: vec!["pwd".into()],
            acr: None,
            ip: None,
            user_agent: None,
            policy: &tenant.settings.session,
        },
    )
    .await
    .unwrap();
    let cookie = format!("{}={}", sessions::cookie_name(&app.state), session.id);

    // 1. Discovery.
    let disco: Value = app
        .http
        .get(app.tenant_url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ep = |k: &str| disco[k].as_str().unwrap().to_string();
    let jwks: Value = app
        .http
        .get(ep("jwks_uri"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!jwks["keys"].as_array().unwrap().is_empty());

    // 2. PAR + authorize.
    let par: Value = app
        .http
        .post(ep("pushed_authorization_request_endpoint"))
        .basic_auth("rp", Some(&*secret))
        .form(&[
            ("response_type", "code"),
            ("redirect_uri", "https://rp.example/cb"),
            ("scope", "openid profile email offline_access"),
            ("state", "abc"),
            ("nonce", "n-1"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let res = app
        .http
        .get(ep("authorization_endpoint"))
        .query(&[
            ("client_id", "rp"),
            ("request_uri", par["request_uri"].as_str().unwrap()),
        ])
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let q = |k: &str| {
        loc.query_pairs()
            .find(|(a, _)| a == k)
            .map(|(_, v)| v.into_owned())
    };
    assert_eq!(q("state").as_deref(), Some("abc"));
    assert_eq!(q("iss").as_deref(), Some(disco["issuer"].as_str().unwrap()));
    let code = q("code").unwrap();

    // 3. Token.
    let tokens: Value = app
        .http
        .post(ep("token_endpoint"))
        .basic_auth("rp", Some(&*secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "https://rp.example/cb"),
            ("code_verifier", VERIFIER),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let at = tokens["access_token"].as_str().unwrap().to_string();
    let rt = tokens["refresh_token"].as_str().unwrap().to_string();
    let idt = tokens["id_token"].as_str().unwrap().to_string();
    let id_claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(idt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(id_claims["nonce"], "n-1");
    assert_eq!(id_claims["aud"], "rp");
    assert_eq!(id_claims["iss"], disco["issuer"]);
    assert_eq!(id_claims["email"], "alice@example.com");

    // 4. UserInfo.
    let ui: Value = app
        .http
        .get(ep("userinfo_endpoint"))
        .bearer_auth(&at)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ui["sub"], id_claims["sub"]);
    assert_eq!(ui["preferred_username"], "alice");

    // 5. Refresh (rotation).
    let refreshed: Value = app
        .http
        .post(ep("token_endpoint"))
        .basic_auth("rp", Some(&*secret))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt.as_str()),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rt2 = refreshed["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(rt2, rt);
    let at2 = refreshed["access_token"].as_str().unwrap().to_string();

    // 6. Introspect (active), then revoke, then introspect (inactive).
    let info: Value = app
        .http
        .post(ep("introspection_endpoint"))
        .basic_auth("rp", Some(&*secret))
        .form(&[("token", at2.as_str())])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["active"], true);
    assert_eq!(info["username"], "alice");
    let res = app
        .http
        .post(ep("revocation_endpoint"))
        .basic_auth("rp", Some(&*secret))
        .form(&[("token", at2.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let info: Value = app
        .http
        .post(ep("introspection_endpoint"))
        .basic_auth("rp", Some(&*secret))
        .form(&[("token", at2.as_str())])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["active"], false);
    assert_eq!(
        app.http
            .get(ep("userinfo_endpoint"))
            .bearer_auth(&at2)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );

    // 7. Logout: hint matches the session → straight back to the RP, cookie cleared, refresh dead.
    let res = app
        .http
        .get(ep("end_session_endpoint"))
        .query(&[
            ("id_token_hint", idt.as_str()),
            ("post_logout_redirect_uri", "https://rp.example/"),
            ("state", "bye"),
        ])
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    assert_eq!(res.headers()["location"], "https://rp.example/?state=bye");
    assert!(
        res.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    let res = app
        .http
        .post(ep("token_endpoint"))
        .basic_auth("rp", Some(&*secret))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt2.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    // A new authorization now requires login again.
    let res = app
        .http
        .get(ep("authorization_endpoint"))
        .query(&[
            ("client_id", "rp"),
            ("redirect_uri", "https://rp.example/cb"),
            ("response_type", "code"),
            ("scope", "openid"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert!(
        res.headers()["location"]
            .to_str()
            .unwrap()
            .contains("/login/")
    );
}
