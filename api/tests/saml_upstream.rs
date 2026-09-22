//! Phase 13.2: SAML 2.0 identity providers upstream (rIDM as the service
//! provider). The upstream IdP is rIDM itself (13.1) in a second tenant of
//! the same server: each side is configured from the other's published
//! metadata, and a browser with one cookie jar walks sign-in, both kinds of
//! Single Logout and IdP-initiated sign-in between them. Hand-made
//! responses cover what a well-behaved IdP never sends.

mod common;

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::TestApp;
use common::admin::{admin_token, call};
use reqwest::Method;
use ridm_api::models::{
    ClientType, IdpKind, LinkPolicy, NewClient, NewIdentityProvider, NewUser, SamlUpstreamSettings,
    Tenant, TenantSettings,
};
use ridm_api::saml::binding::{self, Kind};
use ridm_api::saml::protocol;
use ridm_api::services::admin_access::OWNER_ROLE;
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::{
    broker, clients, identity_providers, login_flows, saml_keys, saml_sp, saml_sps, sessions,
    tenant_config, tenants, users,
};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

const PASSWORD: &str = "correct-horse-battery";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const ALIAS: &str = "corp";

struct Fx {
    app: TestApp,
    /// The tenant signing in through the upstream IdP (the SP).
    sp: Tenant,
    /// The tenant acting as the upstream IdP.
    idp: Tenant,
    /// The SAML client the SP is registered as in the IdP tenant.
    sp_client: Uuid,
}

impl Fx {
    fn at(&self, tenant: &Tenant, path: &str) -> String {
        self.app.url(&format!("/t/{}{path}", tenant.slug))
    }
}

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

fn param(u: &str, k: &str) -> Option<String> {
    url::Url::parse(u)
        .unwrap()
        .query_pairs()
        .find(|(a, _)| a == k)
        .map(|(_, v)| v.into_owned())
}

/// The hidden fields and target of an auto-posting form.
fn form(html: &str) -> (String, HashMap<String, String>) {
    let unescape = |v: &str| {
        v.replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
    };
    let fields = regex::Regex::new(r#"name="([^"]+)" value="([^"]*)""#)
        .unwrap()
        .captures_iter(html)
        .map(|c| (c[1].to_string(), unescape(&c[2])))
        .collect();
    let action = regex::Regex::new(r#"action="([^"]+)""#)
        .unwrap()
        .captures(html)
        .expect("a form")[1]
        .to_string();
    (unescape(&action), fields)
}

async fn user_in(app: &TestApp, tenant: Uuid, username: &str, email: &str) -> Uuid {
    let user = users::create(
        &app.state,
        tenant,
        Actor::System,
        NewUser {
            username: username.into(),
            email: Some(email.into()),
            email_verified: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    password::set_password(
        &app.state,
        tenant,
        &TenantSettings::default().password,
        Actor::System,
        user.id,
        PASSWORD.to_string().into(),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();
    user.id
}

/// Both tenants, each configured from the other's metadata: the SP tenant
/// has the IdP as `corp` (through the admin API's metadata import), the
/// IdP tenant has the SP registered from rIDM's SP metadata.
async fn fixture_with(tweak: impl FnOnce(&mut SamlUpstreamSettings)) -> Fx {
    let app = TestApp::spawn().await;
    let sp = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let idp_t = common::create_tenant(&app.state.db).await;
    let idp = tenants::get(&app.state, idp_t.id).await.unwrap();
    user_in(&app, idp.id, "alice", "alice@corp.example").await;
    clients::create(
        &app.state,
        sp.id,
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

    // The SP side, from the IdP's metadata (by URL, which is kept).
    let token = admin_token(&app, sp.id, OWNER_ROLE).await;
    let metadata_url = app.url(&format!("/t/{}/saml/metadata", idp.slug));
    let (s, mut settings, _) = call(
        &app,
        Method::POST,
        &format!(
            "/admin/tenants/{}/identity-providers/saml-metadata",
            sp.slug
        ),
        Some(&token),
        Some(&json!({"url": metadata_url})),
    )
    .await;
    assert_eq!(s, 200, "{settings}");
    assert_eq!(settings["entity_id"], app.url(&format!("/t/{}", idp.slug)));
    assert_eq!(settings["metadata_url"], metadata_url);
    assert_eq!(settings["name_id_format"], "persistent");
    let mut typed: SamlUpstreamSettings = serde_json::from_value(settings.clone()).unwrap();
    tweak(&mut typed);
    settings = serde_json::to_value(&typed).unwrap();
    let (s, created, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/identity-providers", sp.slug),
        Some(&token),
        Some(&json!({
            "alias": ALIAS,
            "kind": "saml",
            "display_name": "Corp SSO",
            "trust_email": true,
            "saml": settings,
        })),
    )
    .await;
    assert_eq!(s, 201, "{created}");
    assert_eq!(created["kind"], "saml");
    let sp_meta_url = created["saml_sp"]["metadata_url"].as_str().unwrap();
    assert_eq!(created["saml_sp"]["entity_id"], sp_meta_url);
    assert_eq!(created["callback_url"], created["saml_sp"]["acs_url"]);

    // The IdP side, from rIDM's SP metadata.
    let res = app.http.get(sp_meta_url).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.headers()["content-type"],
        "application/samlmetadata+xml"
    );
    let mut input = saml_sps::from_metadata(&res.text().await.unwrap()).unwrap();
    input.name = "rIDM SP".into();
    input.allow_idp_initiated = Some(true);
    let view = saml_sps::create(&app.state, idp.id, Actor::System, input)
        .await
        .unwrap();
    Fx {
        app,
        sp,
        idp,
        sp_client: view.client.id,
    }
}

async fn fixture() -> Fx {
    fixture_with(|_| {}).await
}

/// `/authorize` at the SP tenant: the login flow a brokered sign-in joins.
async fn start_flow(http: &reqwest::Client, fx: &Fx) -> Uuid {
    let res = http
        .get(fx.at(&fx.sp, "/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "openid profile email"),
            ("state", "st"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    param(&location(&res), "flow").unwrap().parse().unwrap()
}

/// Sign alice in at the IdP's login flow and return its finish step's
/// answer (the auto-posting form to the SP).
async fn sign_in_at_idp(http: &reqwest::Client, fx: &Fx, login_url: &str) -> reqwest::Response {
    let flow: Uuid = param(login_url, "flow")
        .expect("a login flow")
        .parse()
        .unwrap();
    let state: Value = http
        .get(fx.at(&fx.idp, &format!("/flows/{flow}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let res = http
        .post(fx.at(&fx.idp, &format!("/flows/{flow}/password")))
        .json(&json!({
            "csrf": state["csrf"].as_str().unwrap(),
            "identifier": "alice",
            "password": PASSWORD,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let after: Value = res.json().await.unwrap();
    assert_eq!(after["stage"], "done", "{after}");
    http.get(after["finish_url"].as_str().unwrap())
        .send()
        .await
        .unwrap()
}

/// Post an auto-posting form page as the browser would.
async fn submit(http: &reqwest::Client, html: &str) -> reqwest::Response {
    let (action, fields) = form(html);
    http.post(action).form(&fields).send().await.unwrap()
}

/// The IdP's form page for a sign-in the SP tenant started, before it is
/// posted (so tests can look at or tamper with it).
async fn idp_answer(http: &reqwest::Client, fx: &Fx, flow: Uuid) -> String {
    let res = http
        .get(fx.at(&fx.sp, &format!("/broker/{ALIAS}/start?flow={flow}")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    let to_idp = location(&res);
    assert!(
        to_idp.starts_with(&fx.at(&fx.idp, "/saml/sso?SAMLRequest=")),
        "{to_idp}"
    );
    let received = binding::from_redirect(to_idp.split_once('?').unwrap().1).unwrap();
    assert!(
        received.signature.is_some(),
        "requests are signed by default"
    );
    let res = http.get(&to_idp).send().await.unwrap();
    let res = if res.status() == 303 {
        sign_in_at_idp(http, fx, &location(&res)).await
    } else {
        res
    };
    assert_eq!(res.status(), 200);
    res.text().await.unwrap()
}

/// A whole SP-initiated sign-in; returns the SP tenant's flow afterwards.
async fn sign_in(http: &reqwest::Client, fx: &Fx) -> login_flows::LoginFlow {
    let flow = start_flow(http, fx).await;
    let html = idp_answer(http, fx, flow).await;
    let res = submit(http, &html).await;
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    let cont = location(&res);
    assert!(cont.contains("/saml/acs?continue="), "{cont}");
    let res = http.get(&cont).send().await.unwrap();
    assert_eq!(res.status(), 303);
    let to_ui = location(&res);
    assert_eq!(
        param(&to_ui, "flow").as_deref(),
        Some(flow.to_string().as_str()),
        "{to_ui}"
    );
    assert!(
        res.headers().get_all("set-cookie").iter().any(|c| c
            .to_str()
            .unwrap()
            .contains(&format!("ridm_session_{}", fx.sp.slug))),
        "the SP tenant's session cookie is set on the same-site GET"
    );
    login_flows::get(&fx.app.state, fx.sp.id, flow)
        .await
        .unwrap()
        .expect("flow")
}

async fn session_live(fx: &Fx, tenant: &Tenant, id: Uuid) -> bool {
    sessions::get(&fx.app.state, tenant.id, id, &tenant.settings.session)
        .await
        .unwrap()
        .is_some()
}

/// Alice's live session at the IdP tenant.
async fn idp_session(fx: &Fx) -> Option<Uuid> {
    let alice = users::find_by_identifier(&fx.app.state, fx.idp.id, "alice")
        .await
        .unwrap()
        .unwrap();
    sessions::list_live_for_user(&fx.app.state, fx.idp.id, alice.id)
        .await
        .unwrap()
        .first()
        .map(|s| s.id)
}

#[tokio::test]
async fn an_sp_initiated_sign_in_through_another_ridm_creates_and_links_the_user() {
    let fx = fixture().await;
    let http = browser();
    let flow = sign_in(&http, &fx).await;
    assert_eq!(flow.stage, login_flows::FlowStage::Done);
    assert_eq!(flow.amr, ["fed"]);
    let user = users::get(&fx.app.state, fx.sp.id, flow.user_id.unwrap())
        .await
        .unwrap();
    // The IdP releases every claim of the SP client's scopes by default,
    // named after the claim: `email` and `preferred_username` land as is.
    assert_eq!(user.email.as_deref(), Some("alice@corp.example"));
    assert!(user.email_verified, "trust_email vouches for the address");
    assert_eq!(user.username, "alice");
    let links = broker::identities_of(&fx.app.state, fx.sp.id, user.id)
        .await
        .unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].alias, ALIAS);
    // A persistent (pairwise) NameID: opaque, not the IdP's user id.
    let alice_at_idp = users::find_by_identifier(&fx.app.state, fx.idp.id, "alice")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(links[0].external_subject, alice_at_idp.id.to_string());
    assert!(!links[0].external_subject.is_empty());

    // The session remembers its upstream for Single Logout.
    let sid = flow.session_id.unwrap();
    let up = saml_sp::upstream_of(&fx.app.state, fx.sp.id, sid)
        .await
        .unwrap()
        .expect("an upstream session");
    assert_eq!(up.name_id, links[0].external_subject);
    assert!(up.session_index.is_some());

    // The flow finishes like any other: a code for the client.
    let res = http
        .get(fx.at(&fx.sp, &format!("/flows/{}/finish", flow.id)))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    assert!(location(&res).starts_with("https://app.example/cb?code="));

    // A second sign-in, with the IdP session still open, reuses the link.
    let before = broker::identities_of(&fx.app.state, fx.sp.id, user.id)
        .await
        .unwrap()[0]
        .last_login_at;
    let http2 = browser();
    let again = sign_in(&http2, &fx).await;
    assert_eq!(again.user_id, Some(user.id));
    let after = broker::identities_of(&fx.app.state, fx.sp.id, user.id)
        .await
        .unwrap()[0]
        .last_login_at;
    assert!(after >= before);
}

#[tokio::test]
async fn a_response_is_accepted_once_and_only_for_its_request() {
    let fx = fixture().await;
    let http = browser();
    let flow = start_flow(&http, &fx).await;
    let html = idp_answer(&http, &fx, flow).await;
    let (action, fields) = form(&html);

    // Tampered: the IdP's signatures no longer hold.
    let xml = String::from_utf8(STANDARD.decode(&fields["SAMLResponse"]).unwrap()).unwrap();
    let mut forged = fields.clone();
    forged.insert(
        "SAMLResponse".into(),
        STANDARD.encode(xml.replacen("alice@corp.example", "admin@corp.example", 1)),
    );
    let res = http.post(&action).form(&forged).send().await.unwrap();
    assert_eq!(res.status(), 303);
    let to = location(&res);
    assert!(
        to.contains("broker_error=upstream_error") || to.contains("broker_error="),
        "{to}"
    );
    // The forged post spent the RelayState: the genuine one now has no
    // request to answer, and this provider takes no unsolicited responses.
    let res = http.post(&action).form(&fields).send().await.unwrap();
    assert_eq!(res.status(), 400, "{}", res.text().await.unwrap());

    // A fresh sign-in: accepted once; the same response again is refused
    // even with a new RelayState's request behind it.
    let http = browser();
    let flow = start_flow(&http, &fx).await;
    let html = idp_answer(&http, &fx, flow).await;
    let res = submit(&http, &html).await;
    assert_eq!(res.status(), 303);
    assert!(location(&res).contains("continue="));
    let res = submit(&http, &html).await;
    assert_eq!(res.status(), 400, "replayed after the RelayState was spent");

    // A continue link works once.
    let flow = start_flow(&http, &fx).await;
    let html = idp_answer(&http, &fx, flow).await;
    let cont = location(&submit(&http, &html).await);
    assert_eq!(http.get(&cont).send().await.unwrap().status(), 303);
    assert_eq!(http.get(&cont).send().await.unwrap().status(), 400);
}

#[tokio::test]
async fn encrypted_assertions_can_be_required() {
    let fx = fixture_with(|s| s.require_encrypted_assertions = true).await;
    // The IdP does not encrypt yet: refused.
    let http = browser();
    let flow = start_flow(&http, &fx).await;
    let html = idp_answer(&http, &fx, flow).await;
    let res = submit(&http, &html).await;
    assert_eq!(res.status(), 303);
    assert!(
        location(&res).contains("broker_error="),
        "{}",
        location(&res)
    );

    // It encrypts to the certificate in rIDM's SP metadata: accepted.
    let view = saml_sps::get(&fx.app.state, fx.idp.id, fx.sp_client)
        .await
        .unwrap();
    let mut input = saml_sps::to_input(&view.client, &view.saml);
    assert!(
        input.encryption_certificate.is_some(),
        "from the SP metadata"
    );
    input.encrypt_assertion = Some(true);
    saml_sps::replace(&fx.app.state, fx.idp.id, Actor::System, fx.sp_client, input)
        .await
        .unwrap();
    let http = browser();
    let flow = sign_in(&http, &fx).await;
    assert_eq!(flow.stage, login_flows::FlowStage::Done);
}

#[tokio::test]
async fn signing_out_at_the_sp_signs_out_at_the_idp_too() {
    let fx = fixture().await;
    let http = browser();
    let flow = sign_in(&http, &fx).await;
    let sp_session = flow.session_id.unwrap();
    let idp_session = idp_session(&fx).await.expect("an IdP session");

    // RP-initiated logout at the SP tenant, confirmed in its UI.
    let res = http
        .get(fx.at(&fx.sp, "/end_session"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let logout_flow: Uuid = param(&location(&res), "flow").unwrap().parse().unwrap();
    let page: Value = http
        .get(fx.at(&fx.sp, &format!("/end_session/{logout_flow}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let confirmed: Value = http
        .post(fx.at(&fx.sp, "/end_session/confirm"))
        .json(&json!({"flow": logout_flow, "csrf": page["csrf"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(confirmed["logged_out"], true);
    assert!(!session_live(&fx, &fx.sp, sp_session).await);
    let out = confirmed["redirect_to"].as_str().unwrap();
    assert!(
        out.contains(&format!("/broker/{ALIAS}/saml/slo/out/")),
        "{confirmed}"
    );

    // rIDM sends the IdP a signed LogoutRequest…
    let res = http.get(out).send().await.unwrap();
    assert_eq!(res.status(), 303);
    let to_idp = location(&res);
    assert!(
        to_idp.starts_with(&fx.at(&fx.idp, "/saml/slo?SAMLRequest=")),
        "{to_idp}"
    );
    let received = binding::from_redirect(to_idp.split_once('?').unwrap().1).unwrap();
    let certs = saml_keys::certificates(&fx.app.state, &fx.sp)
        .await
        .unwrap();
    received.signature.as_ref().unwrap().verify(&certs).unwrap();
    let doc = ridm_api::saml::xml::parse(&received.xml).unwrap();
    let req = protocol::parse_logout_request(&doc).unwrap();
    assert_eq!(req.session_indexes.len(), 1);

    // …which the IdP accepts (it checks the signature against the SP's
    // registered certificate), ends its session and answers.
    let res = http.get(&to_idp).send().await.unwrap();
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    assert!(
        !session_live(&fx, &fx.idp, idp_session).await,
        "the IdP session ended"
    );
    let back = location(&res);
    assert!(
        back.contains(&format!("/broker/{ALIAS}/saml/slo?SAMLResponse=")),
        "{back}"
    );
    // The answer takes the browser on to where the sign-out was going.
    let res = http.get(&back).send().await.unwrap();
    assert_eq!(res.status(), 303);
    assert!(location(&res).contains("/logout/"), "{}", location(&res));
    // Once only.
    assert_eq!(http.get(&back).send().await.unwrap().status(), 400);
}

#[tokio::test]
async fn signing_out_at_the_idp_signs_out_at_the_sp_too() {
    let fx = fixture().await;
    let http = browser();
    let flow = sign_in(&http, &fx).await;
    let sp_session = flow.session_id.unwrap();

    // Logout at the IdP tenant: it walks its SAML SPs, rIDM among them.
    let res = http
        .get(fx.at(&fx.idp, "/end_session"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let logout_flow: Uuid = param(&location(&res), "flow").unwrap().parse().unwrap();
    let page: Value = http
        .get(fx.at(&fx.idp, &format!("/end_session/{logout_flow}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let confirmed: Value = http
        .post(fx.at(&fx.idp, "/end_session/confirm"))
        .json(&json!({"flow": logout_flow, "csrf": page["csrf"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let chain = confirmed["redirect_to"].as_str().unwrap();
    assert!(chain.contains("/saml/slo/chain/"), "{confirmed}");
    let res = http.get(chain).send().await.unwrap();
    assert_eq!(res.status(), 303);
    let to_sp = location(&res);
    assert!(
        to_sp.contains(&format!("/broker/{ALIAS}/saml/slo?SAMLRequest=")),
        "{to_sp}"
    );

    // rIDM checks the IdP's signature, ends the brokered session, and
    // answers once its own downstream SPs (none here) had their turn.
    let res = http.get(&to_sp).send().await.unwrap();
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    assert!(
        !session_live(&fx, &fx.sp, sp_session).await,
        "the SP session ended"
    );
    let done = location(&res);
    assert!(done.contains("/saml/slo/done/"), "{done}");
    let res = http.get(&done).send().await.unwrap();
    assert_eq!(res.status(), 303);
    let answer = location(&res);
    assert!(
        answer.starts_with(&fx.at(&fx.idp, "/saml/slo?SAMLResponse=")),
        "{answer}"
    );
    // The IdP takes the answer and finishes its sign-out.
    let res = http.get(&answer).send().await.unwrap();
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    assert!(location(&res).contains("/logout/"), "{}", location(&res));

    // A replayed LogoutRequest is refused, and so is an unsigned one.
    assert_eq!(http.get(&to_sp).send().await.unwrap().status(), 400);
    let received = binding::from_redirect(to_sp.split_once('?').unwrap().1).unwrap();
    let doc = ridm_api::saml::xml::parse(&received.xml).unwrap();
    let req = protocol::parse_logout_request(&doc).unwrap();
    let fresh = protocol::logout_request(
        &req.issuer,
        req.destination.as_deref().unwrap(),
        &req.name_id,
        req.session_indexes.first().map(String::as_str),
        chrono::Utc::now(),
    )
    .to_string();
    let unsigned = binding::to_redirect(
        to_sp.split_once('?').unwrap().0,
        Kind::Request,
        &fresh,
        received.relay_state.as_deref(),
        None,
    )
    .unwrap();
    let res = http.get(&unsigned).send().await.unwrap();
    assert_eq!(res.status(), 400);
    assert!(res.text().await.unwrap().contains("must be signed"));
}

/// IdP-initiated sign-in at the IdP tenant to the SP tenant: the browser
/// and the SP's answer to the posted response.
async fn unsolicited(fx: &Fx) -> (reqwest::Client, reqwest::Response) {
    let http = browser();
    let sp_entity = saml_sp::endpoints(&fx.app.state, &fx.sp, ALIAS).entity_id;
    let url = format!(
        "{}?sp={}",
        fx.at(&fx.idp, "/saml/init"),
        url::form_urlencoded::byte_serialize(sp_entity.as_bytes()).collect::<String>()
    );
    let res = http.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 303);
    let res = sign_in_at_idp(&http, fx, &location(&res)).await;
    assert_eq!(res.status(), 200);
    let html = res.text().await.unwrap();
    let res = submit(&http, &html).await;
    (http, res)
}

#[tokio::test]
async fn idp_initiated_sign_in_needs_the_providers_consent() {
    let fx = fixture().await;
    // Off by default: nothing to answer.
    let (_, res) = unsolicited(&fx).await;
    assert_eq!(res.status(), 400, "{}", res.text().await.unwrap());

    // Allowed: signed in, landing on the account console.
    let mut idp = identity_providers::get(&fx.app.state, fx.sp.id, ALIAS)
        .await
        .unwrap();
    let mut settings = idp.saml.take().unwrap().settings();
    settings.allow_unsolicited = true;
    identity_providers::update(
        &fx.app.state,
        fx.sp.id,
        Actor::System,
        ALIAS,
        ridm_api::models::IdentityProviderUpdate {
            saml: Some(settings.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (http, res) = unsolicited(&fx).await;
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    let res = http.get(location(&res)).send().await.unwrap();
    assert_eq!(res.status(), 303);
    let landed = location(&res);
    assert!(landed.contains("/account/"), "{landed}");
    assert!(res.headers().get_all("set-cookie").iter().any(|c| {
        c.to_str()
            .unwrap()
            .contains(&format!("ridm_session_{}", fx.sp.slug))
    }));
    // Its session is brokered like any other: it knows its upstream.
    let alice = users::find_by_identifier(&fx.app.state, fx.sp.id, "alice")
        .await
        .unwrap()
        .expect("created");
    let live = sessions::list_live_for_user(&fx.app.state, fx.sp.id, alice.id)
        .await
        .unwrap();
    assert_eq!(live.len(), 1);
    assert!(
        saml_sp::upstream_of(&fx.app.state, fx.sp.id, live[0].id)
            .await
            .unwrap()
            .is_some()
    );

    // A named client must say where to land.
    settings.unsolicited_client_id = Some("spa".into());
    let err = identity_providers::update(
        &fx.app.state,
        fx.sp.id,
        Actor::System,
        ALIAS,
        ridm_api::models::IdentityProviderUpdate {
            saml: Some(settings),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("initiate_login_uri")
            || format!("{err:?}").contains("initiate_login_uri")
    );
}

#[tokio::test]
async fn admins_manage_saml_providers_and_metadata_refreshes_follow_a_rollover() {
    let fx = fixture().await;
    let token = admin_token(&fx.app, fx.sp.id, OWNER_ROLE).await;
    let base = format!("/admin/tenants/{}/identity-providers", fx.sp.slug);

    // Listed with its SP details; offered on the login page.
    let (s, list, _) = call(&fx.app, Method::GET, &base, Some(&token), None).await;
    assert_eq!(s, 200);
    let row = list
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["alias"] == ALIAS)
        .unwrap()
        .clone();
    assert_eq!(row["saml"]["sign_requests"], true);
    assert_eq!(row["saml"]["want_assertions_signed"], true);
    assert!(
        row["saml"]["signing_certificates"]
            .as_array()
            .unwrap()
            .len()
            == 1
    );
    assert!(row.get("client_secret_enc").is_none());
    let offered = identity_providers::offered(&fx.app.state, fx.sp.id)
        .await
        .unwrap();
    assert!(offered.iter().any(|p| p.alias == ALIAS));

    // Validation: no certificate, a plain-http endpoint, SAML settings on
    // an OIDC provider, changing the kind.
    let mut bad = row["saml"].clone();
    bad["signing_certificates"] = json!([]);
    let (s, body, _) = call(
        &fx.app,
        Method::PATCH,
        &format!("{base}/{ALIAS}"),
        Some(&token),
        Some(&json!({"saml": strip_status(&bad)})),
    )
    .await;
    assert_eq!(s, 400, "{body}");
    let mut bad = row["saml"].clone();
    bad["sso_url"] = json!("http://idp.example/sso");
    let (s, _, _) = call(
        &fx.app,
        Method::PATCH,
        &format!("{base}/{ALIAS}"),
        Some(&token),
        Some(&json!({"saml": strip_status(&bad)})),
    )
    .await;
    assert_eq!(s, 400);
    let (s, _, _) = call(
        &fx.app,
        Method::PATCH,
        &format!("{base}/{ALIAS}"),
        Some(&token),
        Some(&json!({"kind": "oidc"})),
    )
    .await;
    assert_eq!(s, 400);
    let (s, _, _) = call(
        &fx.app,
        Method::POST,
        &base,
        Some(&token),
        Some(&json!({"alias": "x", "kind": "oidc", "issuer": "https://accounts.google.com", "authorization_endpoint": "https://a.example/a", "token_endpoint": "https://a.example/t", "jwks_uri": "https://a.example/j", "client_id": "c", "saml": strip_status(&row["saml"])})),
    )
    .await;
    assert_eq!(s, 400);
    // A second provider with the same entity ID: a conflict.
    let (s, _, _) = call(
        &fx.app,
        Method::POST,
        &base,
        Some(&token),
        Some(&json!({"alias": "corp2", "kind": "saml", "saml": strip_status(&row["saml"])})),
    )
    .await;
    assert_eq!(s, 409);
    // Metadata that is not an IdP's.
    let (s, _, _) = call(&fx.app, Method::POST, &format!("{base}/saml-metadata"), Some(&token), Some(&json!({"metadata": "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"x\"/>"}))).await;
    assert_eq!(s, 400);

    // The IdP starts a key rollover: its metadata lists a second
    // certificate. A refresh picks it up.
    saml_keys::add_pending(&fx.app.state, &fx.idp, Actor::System)
        .await
        .unwrap();
    let (s, refreshed, _) = call(
        &fx.app,
        Method::POST,
        &format!("{base}/{ALIAS}/saml/refresh"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(s, 200, "{refreshed}");
    assert_eq!(
        refreshed["saml"]["signing_certificates"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(refreshed["saml"]["metadata_refreshed_at"].is_string());
    assert!(refreshed["saml"]["metadata_error"].is_null());

    // The rollover completes (the new key signs): sign-in still works.
    let keys = saml_keys::list(&fx.app.state, fx.idp.id).await.unwrap();
    let pending = keys
        .iter()
        .find(|k| k.status == ridm_api::models::SamlKeyStatus::Pending)
        .unwrap();
    saml_keys::activate(&fx.app.state, fx.idp.id, Actor::System, pending.id)
        .await
        .unwrap();
    let flow = sign_in(&browser(), &fx).await;
    assert_eq!(flow.stage, login_flows::FlowStage::Done);

    // A metadata URL that stops answering: the error is recorded, the
    // settings stay. The daily job does the same for every due provider.
    let mut settings: SamlUpstreamSettings =
        serde_json::from_value(strip_status(&refreshed["saml"])).unwrap();
    settings.metadata_url = Some(fx.app.url("/t/nope/saml/metadata"));
    identity_providers::update(
        &fx.app.state,
        fx.sp.id,
        Actor::System,
        ALIAS,
        ridm_api::models::IdentityProviderUpdate {
            saml: Some(settings),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (s, _, _) = call(
        &fx.app,
        Method::POST,
        &format!("{base}/{ALIAS}/saml/refresh"),
        Some(&token),
        None,
    )
    .await;
    assert!(s == 503 || s == 400, "{s}");
    let idp = identity_providers::get(&fx.app.state, fx.sp.id, ALIAS)
        .await
        .unwrap();
    let saml = idp.saml.unwrap();
    assert!(saml.metadata_error.is_some());
    assert_eq!(saml.signing_certificates.len(), 2, "kept");
    saml_sp::refresh_due(&fx.app.state).await.unwrap();

    // The SAML settings travel in the tenant document, and an import of
    // that document plans no change.
    let doc = tenant_config::export(&fx.app.state, &fx.sp).await.unwrap();
    let p = doc
        .identity_providers
        .iter()
        .find(|p| p.alias == ALIAS)
        .unwrap();
    assert_eq!(p.kind, IdpKind::Saml);
    assert!(p.saml.is_some());
    let plan = tenant_config::plan(&fx.app.state, &fx.sp, doc.clone(), false)
        .await
        .unwrap();
    assert!(
        plan.changes
            .iter()
            .all(|c| c.resource != "identity_provider"),
        "{:?}",
        plan.changes
    );

    // Deleting the provider takes its SAML settings with it.
    let (s, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("{base}/{ALIAS}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(s, 204);
    let (s, _, _) = call(
        &fx.app,
        Method::GET,
        &format!("/t/{}/broker/{ALIAS}/saml/metadata", fx.sp.slug),
        None,
        None,
    )
    .await;
    assert_eq!(s, 404);
}

/// Settings as the admin API returns them, without the read-only refresh
/// status (settings refuse unknown fields).
fn strip_status(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(o) = v.as_object_mut() {
        o.remove("metadata_refreshed_at");
        o.remove("metadata_error");
    }
    v
}

#[tokio::test]
async fn a_transient_name_id_needs_a_subject_mapper() {
    let fx = fixture().await;
    // The IdP sends transient identifiers to this SP.
    let view = saml_sps::get(&fx.app.state, fx.idp.id, fx.sp_client)
        .await
        .unwrap();
    let mut input = saml_sps::to_input(&view.client, &view.saml);
    input.name_id_format = Some(ridm_api::models::NameIdFormat::Transient);
    saml_sps::replace(&fx.app.state, fx.idp.id, Actor::System, fx.sp_client, input)
        .await
        .unwrap();
    let mut idp = identity_providers::get(&fx.app.state, fx.sp.id, ALIAS)
        .await
        .unwrap();
    let mut settings = idp.saml.take().unwrap().settings();
    settings.name_id_format = None;
    identity_providers::update(
        &fx.app.state,
        fx.sp.id,
        Actor::System,
        ALIAS,
        ridm_api::models::IdentityProviderUpdate {
            saml: Some(settings),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let http = browser();
    let flow = start_flow(&http, &fx).await;
    let html = idp_answer(&http, &fx, flow).await;
    let res = submit(&http, &html).await;
    assert_eq!(res.status(), 303);
    assert!(
        location(&res).contains("broker_error="),
        "{}",
        location(&res)
    );

    // With the subject mapped to a stable attribute it works.
    let mut mappers = idp.mappers.0.clone();
    mappers.subject = Some("email".into());
    identity_providers::update(
        &fx.app.state,
        fx.sp.id,
        Actor::System,
        ALIAS,
        ridm_api::models::IdentityProviderUpdate {
            mappers: Some(mappers),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let flow = sign_in(&browser(), &fx).await;
    let links = broker::identities_of(&fx.app.state, fx.sp.id, flow.user_id.unwrap())
        .await
        .unwrap();
    assert_eq!(links[0].external_subject, "alice@corp.example");
}

#[tokio::test]
async fn saml_settings_are_refused_on_other_kinds_and_required_on_saml() {
    let fx = fixture().await;
    let err = identity_providers::create(
        &fx.app.state,
        fx.sp.id,
        Actor::System,
        NewIdentityProvider {
            alias: "bare".into(),
            kind: Some(IdpKind::Saml),
            link_policy: Some(LinkPolicy::VerifiedEmail),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(format!("{err:?}").contains("saml"), "{err:?}");
    // The OIDC callback of a SAML provider has nothing to redeem.
    let res = fx
        .app
        .http
        .get(fx.at(&fx.sp, &format!("/broker/{ALIAS}/callback?code=x&state=y")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn a_downstream_sps_sign_out_reaches_the_upstream_idp_before_it_is_answered() {
    let fx = fixture().await;
    // The SP tenant is itself an IdP to a downstream SAML application.
    let down = "https://down.example";
    saml_sps::create(
        &fx.app.state,
        fx.sp.id,
        Actor::System,
        saml_sps::SamlSpInput {
            name: "Downstream".into(),
            entity_id: down.into(),
            acs_urls: vec![format!("{down}/acs")],
            slo_url: Some(format!("{down}/slo")),
            ..saml_sps::SamlSpInput::default()
        },
    )
    .await
    .unwrap();
    let http = browser();
    let flow = sign_in(&http, &fx).await;
    let sp_session = flow.session_id.unwrap();
    let idp_session = idp_session(&fx).await.expect("an IdP session");

    // The downstream app signs in through the brokered session.
    let sso = fx.at(&fx.sp, "/saml/sso");
    let req = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_d1" Version="2.0" IssueInstant="{}" Destination="{sso}"><saml:Issuer>{down}</saml:Issuer></samlp:AuthnRequest>"#,
        protocol::instant(chrono::Utc::now())
    );
    let res = http
        .get(binding::to_redirect(&sso, Kind::Request, &req, None, None).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        200,
        "signed in already: the response is posted at once"
    );
    let (_, fields) = form(&res.text().await.unwrap());
    let xml = String::from_utf8(STANDARD.decode(&fields["SAMLResponse"]).unwrap()).unwrap();
    let doc = ridm_api::saml::xml::parse(&xml).unwrap();
    let text = |local: &str| {
        doc.descendants()
            .find(|n| n.is_element() && n.tag_name().name() == local)
            .unwrap()
    };
    let name_id = ridm_api::saml::xml::text_of(text("NameID"));
    let format = text("NameID").attribute("Format").unwrap().to_string();
    let index = text("AuthnStatement")
        .attribute("SessionIndex")
        .unwrap()
        .to_string();

    // It signs out at the SP tenant.
    let slo = fx.at(&fx.sp, "/saml/slo");
    let logout = protocol::logout_request(
        down,
        &slo,
        &protocol::NameId {
            value: name_id,
            format: Some(format),
            sp_name_qualifier: None,
        },
        Some(&index),
        chrono::Utc::now(),
    )
    .to_string();
    let res = http
        .get(binding::to_redirect(&slo, Kind::Request, &logout, Some("rs"), None).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    assert!(!session_live(&fx, &fx.sp, sp_session).await);
    // Before answering, the browser goes through the upstream IdP…
    let out = location(&res);
    assert!(
        out.contains(&format!("/broker/{ALIAS}/saml/slo/out/")),
        "{out}"
    );
    let res = http.get(&out).send().await.unwrap();
    let to_idp = location(&res);
    assert!(
        to_idp.starts_with(&fx.at(&fx.idp, "/saml/slo?SAMLRequest=")),
        "{to_idp}"
    );
    let res = http.get(&to_idp).send().await.unwrap();
    assert!(
        !session_live(&fx, &fx.idp, idp_session).await,
        "the IdP session ended"
    );
    let res = http.get(location(&res)).send().await.unwrap();
    // …then back to finish: the downstream app gets its LogoutResponse.
    let back = location(&res);
    assert!(back.contains("/saml/slo/chain/"), "{back}");
    let res = http.get(&back).send().await.unwrap();
    let answer = location(&res);
    assert!(
        answer.starts_with(&format!("{down}/slo?SAMLResponse=")),
        "{answer}"
    );
    let received = binding::from_redirect(answer.split_once('?').unwrap().1).unwrap();
    assert_eq!(received.relay_state.as_deref(), Some("rs"));
}
