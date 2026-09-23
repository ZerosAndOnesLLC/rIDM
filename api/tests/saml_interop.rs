//! Phase 13.8: SAML interoperability with an independent implementation.
//! Keycloak (`common::keycloak`, Java and Apache Santuario, so nothing is
//! shared with rIDM's own XML signature code or with xmlsec1) plays both
//! parts, each side configured from the other's metadata:
//!
//! - rIDM as the IdP, a Keycloak realm brokering to it as the SP: signed
//!   (and encrypted) assertions Keycloak accepts, attributes it imports,
//!   Keycloak's signed requests checked and never accepted twice, Single
//!   Logout started from either side.
//! - A Keycloak realm as the IdP, rIDM as the SP (13.2's SAML upstream):
//!   sign-in, tampered and replayed responses, Single Logout both ways, and
//!   a metadata refresh after Keycloak rolls its signing key.
//!
//! A browser with one cookie jar walks every redirect and auto-posting form
//! between the two, as a real one would.

mod common;

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::TestApp;
use common::admin::{admin_token, call};
use common::keycloak::{self, Realm};
use reqwest::Method;
use ridm_api::models::{
    AttributeDef, AttributeNameFormat, ClientType, Exposure, NewClient, NewUser, ProfileSchema,
    SamlAttribute, Tenant, TenantSettings,
};
use ridm_api::services::admin_access::OWNER_ROLE;
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::saml_sps::{self, SamlSpInput};
use ridm_api::services::{
    broker, clients, login_flows, profile_schema, saml_idp, saml_keys, sessions, tenants, users,
};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

const PASSWORD: &str = "correct-horse-battery";
const APP_CB: &str = "https://app.example/cb";
const APP_OUT: &str = "https://app.example/out";
/// The alias of rIDM in the Keycloak realm (rIDM as the IdP).
const KC_ALIAS: &str = "ridm";
/// The alias of the Keycloak realm in rIDM (rIDM as the SP).
const ALIAS: &str = "corp";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap()
}

fn location(res: &reqwest::Response) -> String {
    res.headers()
        .get("location")
        .unwrap_or_else(|| panic!("no Location on a {}", res.status()))
        .to_str()
        .unwrap()
        .to_string()
}

fn param(u: &str, k: &str) -> Option<String> {
    url::Url::parse(u)
        .unwrap()
        .query_pairs()
        .find(|(a, _)| a == k)
        .map(|(_, v)| v.into_owned())
}

fn unescape(v: &str) -> String {
    v.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&#x2F;", "/")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// The target and fields of the first form on a page. Both rIDM and
/// Keycloak write `name` before `value` (Keycloak's SAML forms in capitals);
/// Keycloak's login form has inputs without a value, which the caller fills
/// in.
fn form(html: &str) -> (String, HashMap<String, String>) {
    let action = regex::Regex::new(r#"(?i)<form[^>]*action="([^"]+)""#)
        .unwrap()
        .captures(html)
        .unwrap_or_else(|| panic!("a form in: {html}"))[1]
        .to_string();
    let fields = regex::Regex::new(r#"(?i)name="([^"]+)"\s+value="([^"]*)""#)
        .unwrap()
        .captures_iter(html)
        .map(|c| (c[1].to_string(), unescape(&c[2])))
        .collect();
    (unescape(&action), fields)
}

/// The SAML message a form page posts, decoded.
fn posted_xml(html: &str, field: &str) -> String {
    let (_, fields) = form(html);
    String::from_utf8(
        STANDARD
            .decode(
                fields
                    .get(field)
                    .unwrap_or_else(|| panic!("{field} in {html}")),
            )
            .unwrap(),
    )
    .unwrap()
}

/// Post an auto-posting form page as the browser would.
async fn submit(http: &reqwest::Client, html: &str) -> reqwest::Response {
    let (action, fields) = form(html);
    http.post(action).form(&fields).send().await.unwrap()
}

/// Deliver a SAML message the way the answer carries it: follow a redirect
/// or post an auto-posting form.
async fn deliver(http: &reqwest::Client, res: reqwest::Response) -> reqwest::Response {
    match res.status().as_u16() {
        302 | 303 => {
            let to = location(&res);
            http.get(to).send().await.unwrap()
        }
        200 => {
            let html = res.text().await.unwrap();
            submit(http, &html).await
        }
        s => panic!(
            "neither a redirect nor a form: {s} {}",
            res.text().await.unwrap()
        ),
    }
}

/// Follow plain redirects until one leads to a URL starting with `prefix`.
async fn redirected_to(http: &reqwest::Client, mut res: reqwest::Response, prefix: &str) -> String {
    for _ in 0..10 {
        if !matches!(res.status().as_u16(), 302 | 303) {
            let (at, status) = (res.url().clone(), res.status());
            panic!(
                "stopped before {prefix} at {at} {status}: {}",
                res.text().await.unwrap()
            );
        }
        let to = location(&res);
        if to.starts_with(prefix) {
            return to;
        }
        let next = if to.starts_with('/') {
            let base = res.url().clone();
            base.join(&to).unwrap().to_string()
        } else {
            to
        };
        res = http.get(next).send().await.unwrap();
    }
    panic!("too many redirects before {prefix}");
}

async fn user_in(
    app: &TestApp,
    tenant: Uuid,
    username: &str,
    email: &str,
    given: &str,
    family: &str,
) -> Uuid {
    // The names are profile attributes the schema has to declare.
    let names = ["given_name", "family_name"].map(|name| AttributeDef {
        name: name.into(),
        visible_in: vec![Exposure::IdToken, Exposure::Userinfo],
        ..Default::default()
    });
    profile_schema::set(
        &app.state,
        tenant,
        Actor::System,
        ProfileSchema {
            attributes: names.to_vec(),
            allow_undeclared: false,
        },
    )
    .await
    .unwrap();
    let user = users::create(
        &app.state,
        tenant,
        Actor::System,
        NewUser {
            username: username.into(),
            email: Some(email.into()),
            email_verified: true,
            attributes: Some(json!({"given_name": given, "family_name": family})),
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

async fn live_sessions(app: &TestApp, tenant: Uuid, user: Uuid) -> usize {
    sessions::list_live_for_user(&app.state, tenant, user)
        .await
        .unwrap()
        .len()
}

// ---------------------------------------------------------------------------
// rIDM as the IdP, Keycloak as the SP
// ---------------------------------------------------------------------------

struct IdpFx {
    app: TestApp,
    tenant: Tenant,
    alice: Uuid,
    realm: Realm<'static>,
}

/// A Keycloak realm brokering to rIDM (from rIDM's endpoints and signing
/// certificate, as an admin would copy them from the metadata), with an
/// OIDC client `app` to start sign-ins from; rIDM with Keycloak registered
/// from its SP metadata, releasing attributes under their LDAP OIDs.
async fn idp_fixture(encrypt: bool) -> IdpFx {
    let app = TestApp::spawn().await;
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let alice = user_in(
        &app,
        tenant.id,
        "alice",
        "alice@example.com",
        "Alice",
        "Liddell",
    )
    .await;
    let realm = keycloak::keycloak().await.realm().await;

    let ep = saml_idp::endpoints(&app.state, &tenant);
    let certs = saml_keys::certificates(&app.state, &tenant).await.unwrap();
    let signing = certs
        .iter()
        .map(|c| c.to_base64())
        .collect::<Vec<_>>()
        .join(",");
    realm
        .ok(
            Method::POST,
            "/identity-provider/instances",
            Some(&json!({
                "alias": KC_ALIAS,
                "displayName": "rIDM",
                "providerId": "saml",
                "enabled": true,
                "trustEmail": true,
                "config": {
                    "entityId": realm.url(""),
                    "idpEntityId": ep.entity_id,
                    "singleSignOnServiceUrl": ep.sso_url,
                    "singleLogoutServiceUrl": ep.slo_url,
                    "nameIDPolicyFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                    "principalType": "SUBJECT",
                    "postBindingResponse": "true",
                    "postBindingAuthnRequest": "false",
                    "postBindingLogout": "false",
                    "wantAuthnRequestsSigned": "true",
                    "signatureAlgorithm": "RSA_SHA256",
                    "xmlSigKeyInfoKeyNameTransformer": "KEY_ID",
                    "validateSignature": "true",
                    "signingCertificate": signing,
                    "wantAssertionsSigned": "true",
                    "wantAssertionsEncrypted": encrypt.to_string(),
                    "backchannelSupported": "false",
                    "syncMode": "FORCE",
                    "allowCreate": "true",
                },
            })),
        )
        .await;
    for (name, attribute, user_attribute) in [
        ("email", "urn:oid:0.9.2342.19200300.100.1.3", "email"),
        ("first", "urn:oid:2.5.4.42", "firstName"),
        ("last", "urn:oid:2.5.4.4", "lastName"),
    ] {
        realm
            .ok(
                Method::POST,
                &format!("/identity-provider/instances/{KC_ALIAS}/mappers"),
                Some(&json!({
                    "name": name,
                    "identityProviderAlias": KC_ALIAS,
                    "identityProviderMapper": "saml-user-attribute-idp-mapper",
                    "config": {
                        "syncMode": "INHERIT",
                        "attribute.name": attribute,
                        "user.attribute": user_attribute,
                    },
                })),
            )
            .await;
    }
    realm
        .ok(
            Method::POST,
            "/clients",
            Some(&json!({
                "clientId": "app",
                "publicClient": true,
                "standardFlowEnabled": true,
                "redirectUris": [APP_CB],
                "attributes": {"post.logout.redirect.uris": APP_OUT},
            })),
        )
        .await;

    // rIDM's side, from Keycloak's SP metadata for the provider.
    let metadata = reqwest::get(realm.url(&format!("/broker/{KC_ALIAS}/endpoint/descriptor")))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let mut input = saml_sps::from_metadata(&metadata).unwrap();
    assert_eq!(input.entity_id, realm.url(""));
    assert_eq!(
        input.require_signed_requests,
        Some(true),
        "Keycloak's metadata says it signs its requests"
    );
    assert_eq!(
        input.encryption_certificate.is_some(),
        encrypt,
        "Keycloak publishes its encryption key only when it wants encryption"
    );
    input.name = "Keycloak".into();
    input.encrypt_assertion = Some(encrypt);
    let oid = |claim: &str, name: &str, friendly: &str| SamlAttribute {
        claim: claim.into(),
        name: name.into(),
        name_format: AttributeNameFormat::Uri,
        friendly_name: Some(friendly.into()),
    };
    input.attributes = Some(vec![
        oid("email", "urn:oid:0.9.2342.19200300.100.1.3", "mail"),
        oid("given_name", "urn:oid:2.5.4.42", "givenName"),
        oid("family_name", "urn:oid:2.5.4.4", "sn"),
    ]);
    saml_sps::create(
        &app.state,
        tenant.id,
        Actor::System,
        SamlSpInput { ..input },
    )
    .await
    .unwrap();
    IdpFx {
        app,
        tenant,
        alice,
        realm,
    }
}

/// Alice signs in at rIDM's login flow the browser was sent to; the finish
/// step's answer (the auto-posting form to the SP).
async fn sign_in_at_ridm(http: &reqwest::Client, fx: &IdpFx, login_url: &str) -> String {
    let flow: Uuid = param(login_url, "flow")
        .expect("a login flow")
        .parse()
        .unwrap();
    let state: Value = http
        .get(fx.app.tenant_url(&format!("/flows/{flow}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let res = http
        .post(fx.app.tenant_url(&format!("/flows/{flow}/password")))
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
    let res = http
        .get(after["finish_url"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    res.text().await.unwrap()
}

/// What one sign-in at Keycloak through rIDM left behind.
struct KcSignIn {
    /// Keycloak's signed `AuthnRequest`, as the redirect to rIDM carried it.
    request_url: String,
    /// rIDM's answer: the form page posting the `SAMLResponse` to Keycloak.
    answer: String,
    /// Where Keycloak finally sent the browser (the app's callback).
    callback: String,
}

/// Start at the app's Keycloak authorization endpoint with rIDM as the
/// hinted provider, up to rIDM's answer (not yet posted).
async fn to_ridm_and_back(http: &reqwest::Client, fx: &IdpFx) -> (String, String) {
    let res = http
        .get(fx.realm.url("/protocol/openid-connect/auth"))
        .query(&[
            ("client_id", "app"),
            ("redirect_uri", APP_CB),
            ("response_type", "code"),
            ("scope", "openid"),
            ("state", "st"),
            ("kc_idp_hint", KC_ALIAS),
        ])
        .send()
        .await
        .unwrap();
    let ep = saml_idp::endpoints(&fx.app.state, &fx.tenant);
    let request_url = redirected_to(http, res, &ep.sso_url).await;
    assert!(param(&request_url, "Signature").is_some(), "{request_url}");
    let res = http.get(&request_url).send().await.unwrap();
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    let answer = sign_in_at_ridm(http, fx, &location(&res)).await;
    (request_url, answer)
}

async fn sign_in_at_keycloak(http: &reqwest::Client, fx: &IdpFx) -> KcSignIn {
    let (request_url, answer) = to_ridm_and_back(http, fx).await;
    let (action, _) = form(&answer);
    assert_eq!(
        action,
        fx.realm.url(&format!("/broker/{KC_ALIAS}/endpoint")),
        "rIDM posts to the ACS Keycloak asked for"
    );
    let res = submit(http, &answer).await;
    let callback = redirected_to(http, res, APP_CB).await;
    assert_eq!(param(&callback, "state").as_deref(), Some("st"));
    assert!(param(&callback, "code").is_some(), "{callback}");
    KcSignIn {
        request_url,
        answer,
        callback,
    }
}

/// The NameID of an unencrypted assertion.
fn name_id_of(response_xml: &str) -> String {
    let doc = roxmltree::Document::parse(response_xml).unwrap();
    doc.descendants()
        .find(|n| n.has_tag_name((ridm_api::saml::ns::ASSERTION, "NameID")))
        .expect("a NameID")
        .text()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn keycloak_signs_in_through_ridm_and_imports_the_attributes() {
    let fx = idp_fixture(false).await;
    let http = browser();
    let done = sign_in_at_keycloak(&http, &fx).await;

    // What rIDM sent: a signed, unencrypted assertion with the pairwise
    // persistent NameID and the attributes under their OIDs.
    let response = posted_xml(&done.answer, "SAMLResponse");
    assert!(response.contains("urn:oid:2.5.4.42"), "{response}");
    let name_id = name_id_of(&response);
    assert_ne!(name_id, fx.alice.to_string(), "pairwise, not the user id");

    // Keycloak verified it (validateSignature is on), made the user from
    // the attributes, and linked it to that NameID.
    let user = fx
        .realm
        .user_by_email("alice@example.com")
        .await
        .expect("Keycloak created the brokered user");
    assert_eq!(user["firstName"], "Alice");
    assert_eq!(user["lastName"], "Liddell");
    assert_eq!(user["emailVerified"], true, "trustEmail");
    let links = fx
        .realm
        .ok(
            Method::GET,
            &format!("/users/{}/federated-identity", user["id"].as_str().unwrap()),
            None,
        )
        .await;
    assert_eq!(links[0]["identityProvider"], KC_ALIAS, "{links}");
    assert_eq!(links[0]["userId"], name_id.as_str());
    assert_eq!(live_sessions(&fx.app, fx.tenant.id, fx.alice).await, 1);
}

#[tokio::test]
async fn keycloak_decrypts_the_assertions_ridm_encrypts_to_it() {
    let fx = idp_fixture(true).await;
    let http = browser();
    let done = sign_in_at_keycloak(&http, &fx).await;
    let response = posted_xml(&done.answer, "SAMLResponse");
    assert!(response.contains("EncryptedAssertion"), "{response}");
    assert!(!response.contains("alice@example.com"), "nothing in clear");
    let user = fx
        .realm
        .user_by_email("alice@example.com")
        .await
        .expect("Keycloak decrypted the assertion and made the user");
    assert_eq!(user["firstName"], "Alice");
}

#[tokio::test]
async fn keycloak_refuses_an_assertion_changed_after_ridm_signed_it() {
    let fx = idp_fixture(false).await;
    let http = browser();
    let (_, answer) = to_ridm_and_back(&http, &fx).await;
    let (action, mut fields) = form(&answer);
    let xml = posted_xml(&answer, "SAMLResponse");
    fields.insert(
        "SAMLResponse".into(),
        STANDARD.encode(xml.replacen("alice@example.com", "admin@example.com", 1)),
    );
    let res = http.post(action).form(&fields).send().await.unwrap();
    assert_eq!(res.status(), 400);
    let page = res.text().await.unwrap();
    assert!(
        page.contains("Invalid signature in response from identity provider"),
        "{page}"
    );
    assert!(fx.realm.user_by_email("admin@example.com").await.is_none());
    assert!(fx.realm.user_by_email("alice@example.com").await.is_none());
}

#[tokio::test]
async fn ridm_checks_keycloaks_request_signatures_and_takes_each_request_once() {
    let fx = idp_fixture(false).await;
    let http = browser();
    let done = sign_in_at_keycloak(&http, &fx).await;

    // The same signed request again, even from another browser: refused.
    let other = browser();
    let res = other.get(&done.request_url).send().await.unwrap();
    assert_eq!(res.status(), 400, "a replayed AuthnRequest");

    // A fresh request with its RelayState swapped: Keycloak's signature
    // covers it, so rIDM refuses.
    let res = other
        .get(fx.realm.url("/protocol/openid-connect/auth"))
        .query(&[
            ("client_id", "app"),
            ("redirect_uri", APP_CB),
            ("response_type", "code"),
            ("scope", "openid"),
            ("kc_idp_hint", KC_ALIAS),
        ])
        .send()
        .await
        .unwrap();
    let ep = saml_idp::endpoints(&fx.app.state, &fx.tenant);
    let fresh = redirected_to(&other, res, &ep.sso_url).await;
    let relay = param(&fresh, "RelayState").expect("Keycloak sends a RelayState");
    let mut u = url::Url::parse(&fresh).unwrap();
    let pairs: Vec<(String, String)> = u
        .query_pairs()
        .map(|(k, v)| {
            let v = if k == "RelayState" {
                format!("{relay}x")
            } else {
                v.into_owned()
            };
            (k.into_owned(), v)
        })
        .collect();
    u.query_pairs_mut().clear().extend_pairs(pairs);
    let res = other.get(u.as_str()).send().await.unwrap();
    assert_eq!(
        res.status(),
        400,
        "a request whose signature no longer holds"
    );
    // The genuine one still works: nothing was spent by the forgery.
    let res = other.get(&fresh).send().await.unwrap();
    assert_eq!(res.status(), 303);
}

#[tokio::test]
async fn signing_out_at_keycloak_ends_the_ridm_session() {
    let fx = idp_fixture(false).await;
    let http = browser();
    let done = sign_in_at_keycloak(&http, &fx).await;
    let tokens: Value = http
        .post(fx.realm.url("/protocol/openid-connect/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", "app"),
            ("redirect_uri", APP_CB),
            ("code", &param(&done.callback, "code").unwrap()),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id_token = tokens["id_token"].as_str().expect("an ID token");
    assert_eq!(live_sessions(&fx.app, fx.tenant.id, fx.alice).await, 1);

    // RP-initiated logout at Keycloak: it sends rIDM a signed LogoutRequest
    // for the brokered session; rIDM ends its session and answers.
    let res = http
        .get(fx.realm.url("/protocol/openid-connect/logout"))
        .query(&[
            ("id_token_hint", id_token),
            ("post_logout_redirect_uri", APP_OUT),
            ("state", "bye"),
        ])
        .send()
        .await
        .unwrap();
    let ep = saml_idp::endpoints(&fx.app.state, &fx.tenant);
    let to_ridm = redirected_to(&http, res, &ep.slo_url).await;
    assert!(param(&to_ridm, "SAMLRequest").is_some(), "{to_ridm}");
    assert!(param(&to_ridm, "Signature").is_some(), "{to_ridm}");
    let res = http.get(&to_ridm).send().await.unwrap();
    assert_eq!(
        live_sessions(&fx.app, fx.tenant.id, fx.alice).await,
        0,
        "rIDM ended its session"
    );
    // rIDM's answer takes the browser back to Keycloak, which finishes.
    let res = deliver(&http, res).await;
    let out = redirected_to(&http, res, APP_OUT).await;
    assert_eq!(param(&out, "state").as_deref(), Some("bye"));
    let user = fx.realm.user_by_email("alice@example.com").await.unwrap();
    assert_eq!(
        fx.realm.session_count(user["id"].as_str().unwrap()).await,
        0
    );
}

#[tokio::test]
async fn signing_out_at_ridm_ends_the_keycloak_session() {
    let fx = idp_fixture(false).await;
    let http = browser();
    sign_in_at_keycloak(&http, &fx).await;
    let user = fx.realm.user_by_email("alice@example.com").await.unwrap();
    let kc_user = user["id"].as_str().unwrap();
    assert_eq!(fx.realm.session_count(kc_user).await, 1);

    // Sign-out at rIDM, confirmed in its UI, walks Keycloak first.
    let res = http
        .get(fx.app.tenant_url("/end_session"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let flow: Uuid = param(&location(&res), "flow").unwrap().parse().unwrap();
    let page: Value = http
        .get(fx.app.tenant_url(&format!("/end_session/{flow}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let confirmed: Value = http
        .post(fx.app.tenant_url("/end_session/confirm"))
        .json(&json!({"flow": flow, "csrf": page["csrf"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let chain = confirmed["redirect_to"].as_str().unwrap();
    assert!(chain.contains("/saml/slo/chain/"), "{confirmed}");
    let res = http.get(chain).send().await.unwrap();
    // To Keycloak: a signed LogoutRequest it checks against rIDM's
    // certificate before ending the brokered session…
    let res = deliver(&http, res).await;
    assert_eq!(
        fx.realm.session_count(kc_user).await,
        0,
        "Keycloak signed out"
    );
    // …and its answer brings the browser back to rIDM's signed-out page.
    let res = deliver(&http, res).await;
    assert_eq!(res.status(), 303);
    assert!(location(&res).contains("/logout/"), "{}", location(&res));
    assert_eq!(live_sessions(&fx.app, fx.tenant.id, fx.alice).await, 0);
}

// ---------------------------------------------------------------------------
// A Keycloak realm as the IdP, rIDM as the SP
// ---------------------------------------------------------------------------

struct SpFx {
    app: TestApp,
    tenant: Tenant,
    realm: Realm<'static>,
    /// Alice at Keycloak.
    kc_alice: String,
    token: String,
}

/// rIDM with the realm as `corp`, from the realm's metadata URL (kept for
/// refreshes); the realm with rIDM as a SAML client made by Keycloak's own
/// reading of rIDM's SP metadata, releasing email and names.
async fn sp_fixture() -> SpFx {
    let app = TestApp::spawn().await;
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    clients::create(
        &app.state,
        tenant.id,
        Actor::System,
        NewClient {
            client_id: Some("spa".into()),
            name: "My App".into(),
            client_type: Some(ClientType::Spa),
            redirect_uris: vec![APP_CB.into()],
            require_consent: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let realm = keycloak::keycloak().await.realm().await;
    let kc_alice = realm
        .user("alice", "alice@corp.example", "Alice", "Liddell")
        .await;

    let token = admin_token(&app, tenant.id, OWNER_ROLE).await;
    let metadata_url = realm.url("/protocol/saml/descriptor");
    let (s, settings, _) = call(
        &app,
        Method::POST,
        &format!(
            "/admin/tenants/{}/identity-providers/saml-metadata",
            tenant.slug
        ),
        Some(&token),
        Some(&json!({"url": metadata_url})),
    )
    .await;
    assert_eq!(s, 200, "{settings}");
    assert_eq!(settings["entity_id"], realm.url(""));
    assert_eq!(settings["metadata_url"], metadata_url);
    assert_eq!(settings["name_id_format"], "persistent");
    let (s, created, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/identity-providers", tenant.slug),
        Some(&token),
        Some(&json!({
            "alias": ALIAS,
            "kind": "saml",
            "display_name": "Corp (Keycloak)",
            "trust_email": true,
            "saml": settings,
        })),
    )
    .await;
    assert_eq!(s, 201, "{created}");

    // Keycloak's side, from rIDM's SP metadata.
    let sp_metadata = app
        .http
        .get(created["saml_sp"]["metadata_url"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let mut client = realm.client_from_metadata(&sp_metadata).await;
    assert_eq!(client["protocol"], "saml");
    assert_eq!(client["attributes"]["saml.client.signature"], "true");
    assert_eq!(client["attributes"]["saml.encrypt"], "true");
    client["attributes"]["saml_name_id_format"] = json!("persistent");
    client["attributes"]["saml.force.name.id.format"] = json!("true");
    let mappers: Vec<Value> = [
        ("email", "email", "email"),
        ("firstName", "givenName", "given"),
        ("lastName", "sn", "family"),
    ]
    .into_iter()
    .map(|(property, attribute, name)| {
        json!({
            "name": name,
            "protocol": "saml",
            "protocolMapper": "saml-user-property-mapper",
            "config": {
                "user.attribute": property,
                "attribute.name": attribute,
                "attribute.nameformat": "Basic",
            },
        })
    })
    .collect();
    client["protocolMappers"] = Value::from(mappers);
    let (s, _, body) = realm.call(Method::POST, "/clients", Some(&client)).await;
    assert_eq!(s, 201, "{body}");
    SpFx {
        app,
        tenant,
        realm,
        kc_alice,
        token,
    }
}

/// `/authorize` at rIDM: the login flow a brokered sign-in joins.
async fn start_flow(http: &reqwest::Client, fx: &SpFx) -> Uuid {
    let res = http
        .get(fx.app.tenant_url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", APP_CB),
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

/// From rIDM's broker start to Keycloak's answer: the auto-posting form
/// page carrying the `SAMLResponse` to rIDM, not yet posted. Alice types
/// her password into Keycloak's own login form unless Keycloak already
/// knows her.
async fn keycloak_answer(http: &reqwest::Client, fx: &SpFx, flow: Uuid) -> String {
    let res = http
        .get(
            fx.app
                .tenant_url(&format!("/broker/{ALIAS}/start?flow={flow}")),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    let to_kc = location(&res);
    assert!(
        to_kc.starts_with(&fx.realm.url("/protocol/saml?SAMLRequest=")),
        "{to_kc}"
    );
    assert!(
        param(&to_kc, "Signature").is_some(),
        "rIDM signs its requests"
    );
    let res = http.get(&to_kc).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let page = res.text().await.unwrap();
    if page.contains("SAMLResponse") {
        return page;
    }
    let (action, _) = form(&page);
    let res = http
        .post(action)
        .form(&[
            ("username", "alice"),
            ("password", keycloak::USER_PASSWORD),
            ("credentialId", ""),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let answer = res.text().await.unwrap();
    assert!(answer.contains("SAMLResponse"), "{answer}");
    answer
}

/// A whole SP-initiated sign-in through Keycloak; the flow afterwards and
/// the `SAMLResponse` Keycloak posted.
async fn sign_in_through_keycloak(
    http: &reqwest::Client,
    fx: &SpFx,
) -> (login_flows::LoginFlow, String) {
    let flow = start_flow(http, fx).await;
    let answer = keycloak_answer(http, fx, flow).await;
    let res = submit(http, &answer).await;
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    let cont = location(&res);
    assert!(cont.contains("/saml/acs?continue="), "{cont}");
    let res = http.get(&cont).send().await.unwrap();
    assert_eq!(res.status(), 303);
    assert_eq!(
        param(&location(&res), "flow").as_deref(),
        Some(flow.to_string().as_str())
    );
    let flow = login_flows::get(&fx.app.state, fx.tenant.id, flow)
        .await
        .unwrap()
        .expect("flow");
    (flow, posted_xml(&answer, "SAMLResponse"))
}

#[tokio::test]
async fn ridm_signs_in_through_keycloak_and_links_the_user() {
    let fx = sp_fixture().await;
    let http = browser();
    let (flow, response) = sign_in_through_keycloak(&http, &fx).await;
    // Keycloak signed the Response and encrypted the assertion to the
    // tenant's SAML key (AES-GCM content, which rIDM decrypts).
    assert!(response.contains("<saml:EncryptedAssertion>"), "{response}");
    assert!(response.contains("xmlenc11#aes256-gcm"), "{response}");
    assert_eq!(flow.stage, login_flows::FlowStage::Done);
    assert_eq!(flow.amr, ["fed"]);
    let user = users::get(&fx.app.state, fx.tenant.id, flow.user_id.unwrap())
        .await
        .unwrap();
    assert_eq!(user.email.as_deref(), Some("alice@corp.example"));
    assert!(user.email_verified, "trust_email");
    let links = broker::identities_of(&fx.app.state, fx.tenant.id, user.id)
        .await
        .unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].alias, ALIAS);
    assert_ne!(links[0].external_subject, fx.kc_alice);
    assert_eq!(fx.realm.session_count(&fx.kc_alice).await, 1);

    // The flow finishes like any other: a code for the client.
    let res = http
        .get(fx.app.tenant_url(&format!("/flows/{}/finish", flow.id)))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    assert!(location(&res).starts_with(&format!("{APP_CB}?code=")));

    // Signing in again from another browser: Keycloak's NameID is stable,
    // so the link is reused rather than a second account made.
    let other = browser();
    let (again, _) = sign_in_through_keycloak(&other, &fx).await;
    assert_eq!(again.user_id, Some(user.id));
}

/// The `IssueInstant` of the `Response`, a millisecond off: only the
/// signature notices.
fn shift_issue_instant(xml: &str) -> String {
    let re = regex::Regex::new(r#"IssueInstant="([^"]+)""#).unwrap();
    let at = re.captures(xml).unwrap()[1].to_string();
    let mut shifted = at.clone().into_bytes();
    let i = shifted.len() - 2;
    shifted[i] = if shifted[i] == b'0' { b'1' } else { b'0' };
    let shifted = String::from_utf8(shifted).unwrap();
    xml.replacen(
        &format!(r#"IssueInstant="{at}""#),
        &format!(r#"IssueInstant="{shifted}""#),
        1,
    )
}

#[tokio::test]
async fn ridm_refuses_keycloak_responses_tampered_with_or_replayed() {
    let fx = sp_fixture().await;
    let http = browser();
    let flow = start_flow(&http, &fx).await;
    let answer = keycloak_answer(&http, &fx, flow).await;
    let (action, fields) = form(&answer);

    // Tampered: Keycloak's signature over the Response no longer holds.
    let xml = posted_xml(&answer, "SAMLResponse");
    let mut forged = fields.clone();
    forged.insert(
        "SAMLResponse".into(),
        STANDARD.encode(shift_issue_instant(&xml)),
    );
    let res = http.post(&action).form(&forged).send().await.unwrap();
    assert_eq!(res.status(), 303);
    let to = location(&res);
    assert!(to.contains("broker_error="), "{to}");
    // The forgery spent the RelayState: the genuine answer has no request
    // left to answer.
    let res = http.post(&action).form(&fields).send().await.unwrap();
    assert_eq!(res.status(), 400);

    // Accepted once; the same answer again is refused.
    let http = browser();
    let flow = start_flow(&http, &fx).await;
    let answer = keycloak_answer(&http, &fx, flow).await;
    let res = submit(&http, &answer).await;
    assert_eq!(res.status(), 303);
    assert!(location(&res).contains("continue="));
    let res = submit(&http, &answer).await;
    assert_eq!(res.status(), 400, "replayed");
    // So is Keycloak's answer to one sign-in presented for another.
    let flow = start_flow(&http, &fx).await;
    let res = http
        .get(
            fx.app
                .tenant_url(&format!("/broker/{ALIAS}/start?flow={flow}")),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let (action, mut stale) = form(&answer);
    let (_, fresh) = form(&keycloak_answer(&http, &fx, flow).await);
    stale.insert("RelayState".into(), fresh["RelayState"].clone());
    let res = http.post(action).form(&stale).send().await.unwrap();
    assert_ne!(
        res.headers()
            .get("location")
            .map(|l| l.to_str().unwrap().contains("continue=")),
        Some(true),
        "an answer to another request"
    );
}

/// RP-initiated logout at rIDM, confirmed in its UI; where it sends the
/// browser next.
async fn end_session_at_ridm(http: &reqwest::Client, app: &TestApp) -> String {
    let res = http
        .get(app.tenant_url("/end_session"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let flow: Uuid = param(&location(&res), "flow").unwrap().parse().unwrap();
    let page: Value = http
        .get(app.tenant_url(&format!("/end_session/{flow}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let confirmed: Value = http
        .post(app.tenant_url("/end_session/confirm"))
        .json(&json!({"flow": flow, "csrf": page["csrf"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(confirmed["logged_out"], true, "{confirmed}");
    confirmed["redirect_to"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn signing_out_at_ridm_signs_out_at_keycloak() {
    let fx = sp_fixture().await;
    let http = browser();
    let (flow, _) = sign_in_through_keycloak(&http, &fx).await;
    let user = flow.user_id.unwrap();
    assert_eq!(fx.realm.session_count(&fx.kc_alice).await, 1);

    let out = end_session_at_ridm(&http, &fx.app).await;
    assert!(
        out.contains(&format!("/broker/{ALIAS}/saml/slo/out/")),
        "{out}"
    );
    assert_eq!(live_sessions(&fx.app, fx.tenant.id, user).await, 0);
    // A signed LogoutRequest to Keycloak, which checks it against the
    // client's certificate, ends its session and answers.
    let res = http.get(&out).send().await.unwrap();
    assert_eq!(res.status(), 303);
    let to_kc = location(&res);
    assert!(
        to_kc.starts_with(&fx.realm.url("/protocol/saml?SAMLRequest=")),
        "{to_kc}"
    );
    let res = http.get(&to_kc).send().await.unwrap();
    assert_eq!(fx.realm.session_count(&fx.kc_alice).await, 0);
    let res = deliver(&http, res).await;
    assert_eq!(res.status(), 303, "{}", res.text().await.unwrap());
    assert!(location(&res).contains("/logout/"), "{}", location(&res));
}

#[tokio::test]
async fn signing_out_at_keycloak_signs_out_at_ridm() {
    let fx = sp_fixture().await;
    let http = browser();
    let (flow, _) = sign_in_through_keycloak(&http, &fx).await;
    let user = flow.user_id.unwrap();
    assert_eq!(live_sessions(&fx.app, fx.tenant.id, user).await, 1);

    // Keycloak's own logout, confirmed on its page.
    let res = http
        .get(fx.realm.url("/protocol/openid-connect/logout"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let page_url = res.url().clone();
    let (action, mut fields) = form(&res.text().await.unwrap());
    let action = page_url.join(&action).unwrap();
    fields.insert("confirmLogout".into(), "Yes".into());
    let res = http.post(action).form(&fields).send().await.unwrap();
    // Keycloak tells rIDM through the browser: a LogoutRequest to the SP's
    // Single Logout service, which rIDM checks against Keycloak's key.
    let res = deliver(&http, res).await;
    assert_eq!(
        live_sessions(&fx.app, fx.tenant.id, user).await,
        0,
        "rIDM ended its session"
    );
    // rIDM answers (after a same-site hop that clears its cookies) with a
    // signed LogoutResponse; Keycloak finishes its logout.
    let res = deliver(&http, res).await;
    assert!(
        res.url().path().contains("/saml/slo/done/"),
        "{}",
        res.url()
    );
    let back = location(&res);
    assert!(
        back.starts_with(&fx.realm.url("/protocol/saml?SAMLResponse=")),
        "{back}"
    );
    assert!(param(&back, "Signature").is_some());
    let res = http.get(&back).send().await.unwrap();
    let status = res.status();
    let page = res.text().await.unwrap();
    assert!(status.is_success(), "{status} {page}");
    assert!(page.contains("You are logged out"), "{page}");

    assert_eq!(fx.realm.session_count(&fx.kc_alice).await, 0);
}

#[tokio::test]
async fn a_keycloak_key_rollover_reaches_ridm_through_a_metadata_refresh() {
    let fx = sp_fixture().await;
    let http = browser();
    sign_in_through_keycloak(&http, &fx).await;

    // Keycloak signs with a new key; the old one is disabled.
    let realm_id = fx.realm.ok(Method::GET, "", None).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let providers = fx
        .realm
        .ok(
            Method::GET,
            "/components?type=org.keycloak.keys.KeyProvider",
            None,
        )
        .await;
    let mut old = providers
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["providerId"] == "rsa-generated")
        .expect("the realm's RSA signing key")
        .clone();
    fx.realm
        .ok(
            Method::POST,
            "/components",
            Some(&json!({
                "name": "rsa-rolled",
                "providerId": "rsa-generated",
                "providerType": "org.keycloak.keys.KeyProvider",
                "parentId": realm_id,
                "config": {"priority": ["200"], "enabled": ["true"], "active": ["true"]},
            })),
        )
        .await;
    old["config"]["enabled"] = json!(["false"]);
    fx.realm
        .ok(
            Method::PUT,
            &format!("/components/{}", old["id"].as_str().unwrap()),
            Some(&old),
        )
        .await;

    // rIDM still trusts only the old certificate: refused.
    let base = format!("/admin/tenants/{}/identity-providers", fx.tenant.slug);
    let (_, before, _) = call(
        &fx.app,
        Method::GET,
        &format!("{base}/{ALIAS}"),
        Some(&fx.token),
        None,
    )
    .await;
    let http = browser();
    let flow = start_flow(&http, &fx).await;
    let answer = keycloak_answer(&http, &fx, flow).await;
    let res = submit(&http, &answer).await;
    assert_eq!(res.status(), 303);
    assert!(
        location(&res).contains("broker_error="),
        "{}",
        location(&res)
    );

    // A refresh reads Keycloak's metadata again and takes the new one.
    let (s, refreshed, _) = call(
        &fx.app,
        Method::POST,
        &format!("{base}/{ALIAS}/saml/refresh"),
        Some(&fx.token),
        None,
    )
    .await;
    assert_eq!(s, 200, "{refreshed}");
    assert_ne!(
        refreshed["saml"]["signing_certificates"],
        before["saml"]["signing_certificates"]
    );
    assert!(refreshed["saml"]["metadata_error"].is_null());
    let http = browser();
    let (flow, _) = sign_in_through_keycloak(&http, &fx).await;
    assert_eq!(flow.stage, login_flows::FlowStage::Done);
}
