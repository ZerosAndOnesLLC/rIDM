//! Phase 13.2 review finding: a brokered sign-in's callback
//! (`/broker/{alias}/callback?code=…&state=…`) was a bearer URL. An attacker
//! who starts a sign-in with their own upstream account and stops before the
//! callback could get a victim's browser to open it, signing the victim in
//! to the attacker's account (login CSRF). The sign-in is now bound to the
//! browser that started it by a `SameSite=Lax` cookie set at
//! `/broker/{alias}/start`; a posted callback (`form_post`) is parked and
//! continued by a same-site GET, so the cookie is always there to check.
//!
//! No upstream is needed: the binding is checked before the code is
//! redeemed, so a refused browser gets `invalid_state` while the starting
//! one reaches the (unreachable) token endpoint and gets `upstream`.

use ridm_api::models::{ClientType, IdpKind, NewClient, NewIdentityProvider};
use ridm_api::services::{clients, identity_providers};
use ridm_core::events::Actor;

use crate::common::TestApp;

fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap()
}

fn location(res: &reqwest::Response) -> String {
    res.headers()["location"].to_str().unwrap().to_string()
}

/// A sign-in started in `http`, stopped at the provider: the callback URL
/// the provider would send the browser back to.
async fn started(app: &TestApp, http: &reqwest::Client) -> String {
    let res = http
        .get(app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "openid"),
            (
                "code_challenge",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            ),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    let flow = url::Url::parse(&location(&res))
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .unwrap()
        .1
        .into_owned();
    let res = http
        .get(app.tenant_url(&format!("/broker/up/start?flow={flow}")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let to_provider = url::Url::parse(&location(&res)).unwrap();
    let state = to_provider
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    app.tenant_url(&format!(
        "/broker/up/callback?code=the-attackers-code&state={state}"
    ))
}

#[tokio::test]
async fn a_broker_callback_signs_in_only_the_browser_that_started_the_sign_in() {
    let app = TestApp::spawn().await;
    clients::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("spa".into()),
            name: "spa".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec!["https://app.example/cb".into()],
            require_consent: Some(false),
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
            alias: "up".into(),
            kind: Some(IdpKind::Oidc),
            issuer: Some("http://127.0.0.1:9".into()),
            authorization_endpoint: Some("http://127.0.0.1:9/authorize".into()),
            token_endpoint: Some("http://127.0.0.1:9/token".into()),
            jwks_uri: Some("http://127.0.0.1:9/jwks".into()),
            client_id: "rp".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // The attacker's callback, opened in the victim's browser: refused
    // before anything is redeemed.
    let attacker = browser();
    let callback = started(&app, &attacker).await;
    let victim = browser();
    let res = victim.get(&callback).send().await.unwrap();
    assert_eq!(res.status(), 303);
    let to = location(&res);
    assert!(to.contains("broker_error=invalid_state"), "{to}");
    assert!(
        !res.headers()
            .get_all("set-cookie")
            .iter()
            .any(|c| c.to_str().unwrap().contains("ridm_session_")),
        "the victim's browser was signed in"
    );

    // The same, posted (`form_post`): parked, then refused on the GET.
    let callback = started(&app, &attacker).await;
    let (path, query) = callback.split_once('?').unwrap();
    let form: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    let res = victim.post(path).form(&form).send().await.unwrap();
    assert_eq!(res.status(), 303);
    let cont = location(&res);
    assert!(cont.contains("/callback?continue="), "{cont}");
    let res = victim.get(&cont).send().await.unwrap();
    assert!(location(&res).contains("broker_error=invalid_state"));

    // The browser that started it gets as far as the code exchange (whose
    // endpoint is unreachable here), posted or not.
    let callback = started(&app, &attacker).await;
    let res = attacker.get(&callback).send().await.unwrap();
    let to = location(&res);
    assert!(to.contains("broker_error=upstream"), "{to}");
    let callback = started(&app, &attacker).await;
    let (path, query) = callback.split_once('?').unwrap();
    let form: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    let res = attacker.post(path).form(&form).send().await.unwrap();
    let res = attacker.get(location(&res)).send().await.unwrap();
    assert!(location(&res).contains("broker_error=upstream"));
}
