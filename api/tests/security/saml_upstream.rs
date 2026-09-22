//! Phase 13.2 (found in self-review): after the assertion consumer service
//! accepts a SAML response, the sign-in continues at a same-site
//! `…/saml/acs?continue=<id>` link. Without more, that link is a bearer
//! credential: an attacker who completes a sign-in with their own upstream
//! account and gets a victim's browser to open it signs the victim in to
//! the attacker's account (login CSRF). The sign-in is therefore bound to
//! the browser that started it by a `SameSite=Lax` cookie set at
//! `/broker/{alias}/start`: the link opened elsewhere signs nobody in.
//!
//! The upstream IdP here is hand-made — a test key signing responses built
//! with rIDM's own SAML builders — so nothing depends on rIDM's IdP side.

use chrono::Utc;
use ridm_api::models::{
    ClientType, IdpKind, LinkPolicy, NewClient, NewIdentityProvider, SamlUpstreamSettings,
    SigningAlg,
};
use ridm_api::saml::binding;
use ridm_api::saml::cert::{self, Certificate};
use ridm_api::saml::dsig::Signer;
use ridm_api::saml::{ns, protocol};
use ridm_api::services::{clients, identity_providers, keys, saml_sp, tenants};
use ridm_core::events::Actor;

use crate::common::TestApp;

const IDP: &str = "https://idp.example";

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

/// A browser's SP-initiated sign-in up to the IdP: the `AuthnRequest` ID and
/// the `RelayState` it carried.
async fn start(app: &TestApp, http: &reqwest::Client) -> (uuid::Uuid, String, String) {
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
    let flow: uuid::Uuid = url::Url::parse(&location(&res))
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .unwrap()
        .1
        .parse()
        .unwrap();
    let res = http
        .get(app.tenant_url(&format!("/broker/corp/start?flow={flow}")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let to_idp = location(&res);
    let received = binding::from_redirect(to_idp.split_once('?').unwrap().1).unwrap();
    let doc = ridm_api::saml::xml::parse(&received.xml).unwrap();
    let req = protocol::parse_authn_request(&doc).unwrap();
    (flow, req.id, received.relay_state.unwrap())
}

/// The IdP's signed answer to `request_id`, as the browser posts it.
fn response(signer: &Signer, sp: &saml_sp::SpEndpoints, request_id: &str, subject: &str) -> String {
    let now = Utc::now();
    let mut assertion = protocol::assertion(&protocol::AssertionContent {
        idp_entity_id: IDP,
        sp_entity_id: &sp.entity_id,
        acs_url: &sp.acs_url,
        in_response_to: Some(request_id),
        name_id: subject,
        name_id_format: ns::nameid::PERSISTENT,
        sp_name_qualifier: None,
        session_index: "_s1",
        authn_instant: now,
        authn_context: ns::AC_PASSWORD_PROTECTED,
        session_not_on_or_after: None,
        attributes: &[],
        now,
        lifetime: chrono::Duration::minutes(5),
    });
    signer.sign_enveloped(&mut assertion, 1).unwrap();
    let xml = protocol::response(
        IDP,
        &sp.acs_url,
        Some(request_id),
        now,
        (ns::status::SUCCESS, None, None),
        Some(assertion),
    )
    .to_document();
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, xml)
}

#[tokio::test]
async fn a_saml_continue_link_signs_in_only_the_browser_that_started_the_sign_in() {
    let app = TestApp::spawn().await;
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let generated = keys::generate(SigningAlg::RS256, ridm_api::models::RsaBits::B2048).unwrap();
    let der = cert::self_signed(&generated.private_der, "test idp", 1).unwrap();
    let signer = Signer::new(&generated.private_der, &der).unwrap();
    let certificate = Certificate::from_der(der).unwrap();
    clients::create(
        &app.state,
        tenant.id,
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
        tenant.id,
        Actor::System,
        NewIdentityProvider {
            alias: "corp".into(),
            kind: Some(IdpKind::Saml),
            link_policy: Some(LinkPolicy::AlwaysNew),
            saml: Some(SamlUpstreamSettings {
                entity_id: IDP.into(),
                sso_url: "https://idp.example/sso".into(),
                signing_certificates: vec![certificate.to_base64()],
                ..SamlUpstreamSettings::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let sp = saml_sp::endpoints(&app.state, &tenant, "corp");

    // The attacker signs in with their own upstream account and stops at
    // the continue link.
    let attacker = browser();
    let (_, request_id, relay) = start(&app, &attacker).await;
    let res = attacker
        .post(&sp.acs_url)
        .form(&[
            (
                "SAMLResponse",
                response(&signer, &sp, &request_id, "attacker"),
            ),
            ("RelayState", relay),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let link = location(&res);
    assert!(link.contains("continue="), "{link}");

    // The victim's browser opens it: no session, no sign-in.
    let victim = browser();
    let res = victim.get(&link).send().await.unwrap();
    assert!(
        !res.headers()
            .get_all("set-cookie")
            .iter()
            .any(|c| c.to_str().unwrap().contains("ridm_session_")),
        "the victim's browser was signed in"
    );
    let to = location(&res);
    assert!(to.contains("broker_error=invalid_state"), "{to}");

    // The browser that started a sign-in continues it as before.
    let user = browser();
    let (flow, request_id, relay) = start(&app, &user).await;
    let res = user
        .post(&sp.acs_url)
        .form(&[
            (
                "SAMLResponse",
                response(&signer, &sp, &request_id, "someone"),
            ),
            ("RelayState", relay),
        ])
        .send()
        .await
        .unwrap();
    let res = user.get(location(&res)).send().await.unwrap();
    assert_eq!(res.status(), 303);
    assert!(location(&res).contains(&flow.to_string()));
    assert!(
        res.headers()
            .get_all("set-cookie")
            .iter()
            .any(|c| c.to_str().unwrap().contains("ridm_session_")),
        "the starting browser is signed in"
    );
}
