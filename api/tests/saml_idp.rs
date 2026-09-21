//! Phase 13.1: rIDM as a SAML 2.0 identity provider. A test SP (built from
//! rIDM's own SAML code, checked against xmlsec1 where it is installed)
//! registers, sends `AuthnRequest`s over both bindings, reads the signed
//! (and encrypted) responses, and takes part in single logout.

mod common;

use std::collections::HashMap;
use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::{Duration, Utc};
use common::TestApp;
use common::admin::{admin_token, call};
use reqwest::Method;
use ridm_api::models::{NameIdFormat, NewUser, SamlAttribute, SloBinding, Tenant, TenantSettings};
use ridm_api::saml::binding::{self, Kind};
use ridm_api::saml::cert::{self, Certificate};
use ridm_api::saml::dsig::{self, Signer};
use ridm_api::saml::xml::{self, El, children, is, text_of};
use ridm_api::saml::{ns, protocol, xmlenc};
use ridm_api::services::admin_access::OWNER_ROLE;
use ridm_api::services::password::{self, SetPasswordOptions};
use ridm_api::services::saml_sps::{self, SamlSpInput, SamlSpView};
use ridm_api::services::{saml_idp, tenants, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

const PASSWORD: &str = "correct-horse-battery";

/// The test SP's own key and certificate, made once per test binary (RSA
/// generation is slow in debug builds).
fn sp_key() -> &'static (Vec<u8>, Certificate) {
    static KEY: OnceLock<(Vec<u8>, Certificate)> = OnceLock::new();
    KEY.get_or_init(|| {
        let generated = ridm_api::services::keys::generate(
            ridm_api::models::SigningAlg::RS256,
            ridm_api::models::RsaBits::B2048,
        )
        .unwrap();
        let der = cert::self_signed(&generated.private_der, "test sp", 1).unwrap();
        (
            generated.private_der.to_vec(),
            Certificate::from_der(der).unwrap(),
        )
    })
}

fn sp_signer() -> Signer {
    let (key, cert) = sp_key();
    Signer::new(key, &cert.der).unwrap()
}

struct Fx {
    app: TestApp,
    tenant: Tenant,
    alice: Uuid,
}

async fn fixture() -> Fx {
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
    password::set_password(
        &app.state,
        tid,
        &TenantSettings::default().password,
        Actor::System,
        user.id,
        PASSWORD.to_string().into(),
        SetPasswordOptions::default(),
    )
    .await
    .unwrap();
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    Fx {
        app,
        tenant,
        alice: user.id,
    }
}

fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap()
}

fn sp_input(entity: &str) -> SamlSpInput {
    SamlSpInput {
        name: format!("SP {entity}"),
        entity_id: entity.into(),
        acs_urls: vec![format!("{entity}/acs"), format!("{entity}/acs2")],
        slo_url: Some(format!("{entity}/slo")),
        ..SamlSpInput::default()
    }
}

async fn register(fx: &Fx, input: SamlSpInput) -> SamlSpView {
    saml_sps::create(&fx.app.state, fx.tenant.id, Actor::System, input)
        .await
        .unwrap()
}

fn endpoints(fx: &Fx) -> saml_idp::Endpoints {
    saml_idp::endpoints(&fx.app.state, &fx.tenant)
}

/// An `AuthnRequest` from `entity`; `attrs` and `inner` are spliced in.
fn authn_request(fx: &Fx, entity: &str, id: &str, attrs: &str, inner: &str) -> String {
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="{p}" xmlns:saml="{a}" ID="{id}" Version="2.0" IssueInstant="{now}" Destination="{dest}" {attrs}><saml:Issuer>{entity}</saml:Issuer>{inner}</samlp:AuthnRequest>"#,
        p = ns::PROTOCOL,
        a = ns::ASSERTION,
        now = protocol::instant(Utc::now()),
        dest = endpoints(fx).sso_url,
    )
}

fn redirect_url(fx: &Fx, xml: &str, relay: Option<&str>, signer: Option<&Signer>) -> String {
    binding::to_redirect(&endpoints(fx).sso_url, Kind::Request, xml, relay, signer).unwrap()
}

fn param(u: &str, k: &str) -> Option<String> {
    url::Url::parse(u)
        .unwrap()
        .query_pairs()
        .find(|(a, _)| a == k)
        .map(|(_, v)| v.into_owned())
}

fn location(res: &reqwest::Response) -> String {
    res.headers()["location"].to_str().unwrap().to_string()
}

/// The hidden fields of an auto-posting form.
fn form_fields(html: &str) -> HashMap<String, String> {
    let re = regex::Regex::new(r#"name="([^"]+)" value="([^"]*)""#).unwrap();
    re.captures_iter(html)
        .map(|c| {
            let v = c[2]
                .replace("&quot;", "\"")
                .replace("&#39;", "'")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&");
            (c[1].to_string(), v)
        })
        .collect()
}

fn form_action(html: &str) -> String {
    let re = regex::Regex::new(r#"action="([^"]+)""#).unwrap();
    re.captures(html).unwrap()[1].replace("&amp;", "&")
}

/// Sign alice in at the login flow the browser was sent to, and return the
/// response of the finish step.
async fn sign_in(http: &reqwest::Client, fx: &Fx, login_url: &str) -> reqwest::Response {
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
    http.get(after["finish_url"].as_str().unwrap())
        .send()
        .await
        .unwrap()
}

/// The posted `SAMLResponse` (decoded) and `RelayState` of a form page.
async fn posted(res: reqwest::Response) -> (String, String, Option<String>) {
    assert_eq!(res.status(), 200);
    let html = res.text().await.unwrap();
    let fields = form_fields(&html);
    let xml = String::from_utf8(
        STANDARD
            .decode(fields.get("SAMLResponse").expect("a SAMLResponse"))
            .unwrap(),
    )
    .unwrap();
    (form_action(&html), xml, fields.get("RelayState").cloned())
}

async fn idp_certs(fx: &Fx) -> Vec<Certificate> {
    let res = fx
        .app
        .http
        .get(fx.app.tenant_url("/saml/metadata"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.headers()["content-type"],
        "application/samlmetadata+xml"
    );
    let text = res.text().await.unwrap();
    let doc = xml::parse(&text).unwrap();
    doc.descendants()
        .filter(|n| is(*n, ns::DSIG, "X509Certificate"))
        .map(|n| Certificate::parse(&text_of(n)).unwrap())
        .collect()
}

/// What the test SP reads from a successful response, after checking both
/// signatures against the IdP's metadata.
#[derive(Debug)]
struct Assertion {
    in_response_to: Option<String>,
    /// The response's; `None` for an assertion read on its own.
    destination: Option<String>,
    audience: String,
    recipient: String,
    name_id: String,
    name_id_format: String,
    session_index: String,
    class: String,
    attributes: HashMap<String, Vec<String>>,
}

fn read_assertion(
    assertion: roxmltree::Node,
    doc: &roxmltree::Document,
    certs: &[Certificate],
) -> Assertion {
    dsig::verify_enveloped(doc, assertion, certs).expect("the assertion is signed");
    let find = |local: &str| {
        assertion
            .descendants()
            .find(|n| is(*n, ns::ASSERTION, local))
            .unwrap_or_else(|| panic!("{local} missing"))
    };
    let name_id = find("NameID");
    let mut attributes: HashMap<String, Vec<String>> = HashMap::new();
    for a in assertion
        .descendants()
        .filter(|n| is(*n, ns::ASSERTION, "Attribute"))
    {
        attributes.insert(
            a.attribute("Name").unwrap().to_string(),
            children(a, ns::ASSERTION, "AttributeValue")
                .map(text_of)
                .collect(),
        );
    }
    let root = doc.root_element();
    Assertion {
        in_response_to: root.attribute("InResponseTo").map(str::to_string),
        destination: root.attribute("Destination").map(str::to_string),
        audience: text_of(find("Audience")),
        recipient: find("SubjectConfirmationData")
            .attribute("Recipient")
            .unwrap()
            .to_string(),
        name_id: text_of(name_id),
        name_id_format: name_id.attribute("Format").unwrap().to_string(),
        session_index: find("AuthnStatement")
            .attribute("SessionIndex")
            .unwrap()
            .to_string(),
        class: text_of(find("AuthnContextClassRef")),
        attributes,
    }
}

fn status_of(doc: &roxmltree::Document) -> (String, Option<String>) {
    let code = doc
        .descendants()
        .find(|n| is(*n, ns::PROTOCOL, "StatusCode"))
        .unwrap();
    let second = code
        .children()
        .find(|n| is(*n, ns::PROTOCOL, "StatusCode"))
        .and_then(|n| n.attribute("Value"))
        .map(str::to_string);
    (code.attribute("Value").unwrap().to_string(), second)
}

/// A verified successful response: the response signature, then the
/// assertion's.
fn accept(xml: &str, certs: &[Certificate]) -> Assertion {
    let doc = xml::parse(xml).unwrap();
    let root = doc.root_element();
    dsig::verify_enveloped(&doc, root, certs).expect("the response is signed");
    assert_eq!(status_of(&doc).0, ns::status::SUCCESS);
    let assertion = children(root, ns::ASSERTION, "Assertion").next().unwrap();
    read_assertion(assertion, &doc, certs)
}

#[tokio::test]
async fn metadata_names_the_endpoints_and_a_stable_certificate() {
    let fx = fixture().await;
    let ep = endpoints(&fx);
    let text = fx
        .app
        .http
        .get(&ep.metadata_url)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let doc = xml::parse(&text).unwrap();
    assert_eq!(
        doc.root_element().attribute("entityID"),
        Some(ep.entity_id.as_str())
    );
    assert!(text.contains(&ep.sso_url) && text.contains(&ep.slo_url));
    let first = idp_certs(&fx).await;
    assert_eq!(first.len(), 1);
    assert_eq!(idp_certs(&fx).await, first, "the key is made once and kept");
}

#[tokio::test]
async fn sp_initiated_sign_in_posts_a_signed_assertion() {
    let fx = fixture().await;
    let entity = "https://sp.example";
    register(&fx, sp_input(entity)).await;
    let certs = idp_certs(&fx).await;
    let http = browser();

    let req = authn_request(&fx, entity, "_req1", "", "");
    let res = http
        .get(redirect_url(&fx, &req, Some("back/to?page=1"), None))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        303,
        "{}",
        res.text().await.unwrap_or_default()
    );
    let login = location(&res);
    assert!(login.contains("/login/"), "{login}");
    let (action, xml, relay) = posted(sign_in(&http, &fx, &login).await).await;
    assert_eq!(action, format!("{entity}/acs"));
    assert_eq!(relay.as_deref(), Some("back/to?page=1"));
    let a = accept(&xml, &certs);
    assert_eq!(a.in_response_to.as_deref(), Some("_req1"));
    assert_eq!(
        a.destination.as_deref(),
        Some(format!("{entity}/acs").as_str())
    );
    assert_eq!(a.recipient, format!("{entity}/acs"));
    assert_eq!(a.audience, entity);
    assert_eq!(a.name_id_format, ns::nameid::PERSISTENT);
    assert_ne!(
        a.name_id,
        fx.alice.to_string(),
        "persistent ids are pairwise"
    );
    assert_eq!(a.class, ns::AC_PASSWORD_PROTECTED);
    assert_eq!(a.attributes["email"], ["alice@example.com"]);
    assert_eq!(a.attributes["preferred_username"], ["alice"]);

    // The session is there now: the next request is answered at once, with
    // the same persistent id and session index, to the ACS it asked for.
    let req = authn_request(
        &fx,
        entity,
        "_req2",
        &format!(r#"AssertionConsumerServiceURL="{entity}/acs2""#),
        "",
    );
    let res = http
        .get(redirect_url(&fx, &req, None, None))
        .send()
        .await
        .unwrap();
    let (action, xml, relay) = posted(res).await;
    assert_eq!(action, format!("{entity}/acs2"));
    assert!(relay.is_none());
    let again = accept(&xml, &certs);
    assert_eq!(again.in_response_to.as_deref(), Some("_req2"));
    assert_eq!(again.name_id, a.name_id);
    assert_eq!(again.session_index, a.session_index);

    // Another SP sees another persistent id for alice.
    register(&fx, sp_input("https://other.example")).await;
    let req = authn_request(&fx, "https://other.example", "_req3", "", "");
    let res = http
        .get(redirect_url(&fx, &req, None, None))
        .send()
        .await
        .unwrap();
    let other = accept(&posted(res).await.1, &certs);
    assert_ne!(other.name_id, a.name_id);
    assert_eq!(other.audience, "https://other.example");
}

#[tokio::test]
async fn the_response_verifies_with_xmlsec1_too() {
    if std::process::Command::new("xmlsec1")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("xmlsec1 not installed; interop not checked");
        return;
    }
    let fx = fixture().await;
    register(&fx, sp_input("https://sp.example")).await;
    let certs = idp_certs(&fx).await;
    let http = browser();
    let req = authn_request(&fx, "https://sp.example", "_x1", "", "");
    let res = http
        .get(redirect_url(&fx, &req, None, None))
        .send()
        .await
        .unwrap();
    let (_, xml, _) = posted(sign_in(&http, &fx, &location(&res)).await).await;

    let dir = std::env::temp_dir().join(format!("ridm-saml-it-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("idp.pem"), certs[0].to_pem()).unwrap();
    std::fs::write(dir.join("response.xml"), &xml).unwrap();
    // Response first; then the assertion on its own, as an SP checking
    // only the assertion would.
    for node in ["Response", "Assertion"] {
        let ns_uri = if node == "Response" {
            ns::PROTOCOL
        } else {
            ns::ASSERTION
        };
        let out = std::process::Command::new("xmlsec1")
            .args(["--verify", "--lax-key-search", "--pubkey-cert-pem"])
            .arg(dir.join("idp.pem"))
            .arg("--id-attr:ID")
            .arg(format!("{ns_uri}:{node}"))
            .args([
                "--node-xpath",
                &format!("//*[local-name()='{node}']/*[local-name()='Signature']"),
            ])
            .arg(dir.join("response.xml"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "xmlsec1 rejected the {node} signature: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_post_binding_request_is_parked_until_the_browser_returns() {
    let fx = fixture().await;
    register(&fx, sp_input("https://sp.example")).await;
    let certs = idp_certs(&fx).await;
    let http = browser();
    let req = authn_request(&fx, "https://sp.example", "_p1", "", "");
    let res = http
        .post(endpoints(&fx).sso_url)
        .form(&[
            ("SAMLRequest", STANDARD.encode(&req)),
            ("RelayState", "rs".into()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let resume = location(&res);
    assert!(resume.contains("/saml/sso?continue="), "{resume}");
    let res = http.get(&resume).send().await.unwrap();
    assert_eq!(res.status(), 303);
    let (_, xml, relay) = posted(sign_in(&http, &fx, &location(&res)).await).await;
    assert_eq!(accept(&xml, &certs).in_response_to.as_deref(), Some("_p1"));
    assert_eq!(relay.as_deref(), Some("rs"));
    // The parked request is taken once.
    let res = http.get(&resume).send().await.unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn signed_requests_are_checked_against_the_registered_certificate() {
    let fx = fixture().await;
    let entity = "https://signed.example";
    register(
        &fx,
        SamlSpInput {
            signing_certificates: vec![sp_key().1.to_pem()],
            require_signed_requests: Some(true),
            ..sp_input(entity)
        },
    )
    .await;
    let http = browser();

    // Unsigned: refused.
    let req = authn_request(&fx, entity, "_s1", "", "");
    let res = http
        .get(redirect_url(&fx, &req, None, None))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert!(res.text().await.unwrap().contains("must be signed"));

    // Signed in the query string: admitted.
    let req = authn_request(&fx, entity, "_s2", "", "");
    let res = http
        .get(redirect_url(&fx, &req, Some("r"), Some(&sp_signer())))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);

    // A changed parameter breaks the query-string signature.
    let req = authn_request(&fx, entity, "_s3", "", "");
    let url = redirect_url(&fx, &req, Some("one"), Some(&sp_signer()))
        .replace("RelayState=one", "RelayState=two");
    let res = http.get(url).send().await.unwrap();
    assert_eq!(res.status(), 400);

    // Signed inside the XML (POST binding): admitted.
    let signed = {
        let mut el = El::new("samlp:AuthnRequest")
            .attr("xmlns:samlp", ns::PROTOCOL)
            .attr("xmlns:saml", ns::ASSERTION)
            .attr("ID", "_s4")
            .attr("Version", "2.0")
            .attr("IssueInstant", protocol::instant(Utc::now()))
            .attr("Destination", endpoints(&fx).sso_url)
            .child(El::new("saml:Issuer").text(entity));
        sp_signer().sign_enveloped(&mut el, 1).unwrap();
        el.to_document()
    };
    let res = http
        .post(endpoints(&fx).sso_url)
        .form(&[("SAMLRequest", STANDARD.encode(&signed))])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);

    // Signed by some other key: refused.
    let (other_key, other_cert) = {
        let g = ridm_api::services::keys::generate(
            ridm_api::models::SigningAlg::RS256,
            ridm_api::models::RsaBits::B2048,
        )
        .unwrap();
        let der = cert::self_signed(&g.private_der, "intruder", 1).unwrap();
        (g.private_der.to_vec(), der)
    };
    let intruder = Signer::new(&other_key, &other_cert).unwrap();
    let req = authn_request(&fx, entity, "_s5", "", "");
    let res = http
        .get(redirect_url(&fx, &req, None, Some(&intruder)))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert!(res.text().await.unwrap().contains("registered certificate"));
}

#[tokio::test]
async fn bad_requests_are_refused_before_anything_is_sent_to_an_acs() {
    let fx = fixture().await;
    let entity = "https://sp.example";
    register(&fx, sp_input(entity)).await;
    let http = browser();
    let get = |xml: String| {
        let url = redirect_url(&fx, &xml, None, None);
        let http = http.clone();
        async move {
            let res = http.get(url).send().await.unwrap();
            (res.status().as_u16(), res.text().await.unwrap())
        }
    };

    let (s, body) = get(authn_request(&fx, "https://unknown.example", "_b1", "", "")).await;
    assert_eq!(s, 400);
    assert!(body.contains("not a registered service provider"), "{body}");

    let (s, body) = get(authn_request(
        &fx,
        entity,
        "_b2",
        r#"AssertionConsumerServiceURL="https://evil.example/acs""#,
        "",
    ))
    .await;
    assert_eq!(s, 400);
    assert!(body.contains("not registered"), "{body}");

    let (s, _) = get(authn_request(&fx, entity, "_b3", "", "")).await;
    assert_eq!(s, 303);
    let (s, body) = get(authn_request(&fx, entity, "_b3", "", "")).await;
    assert_eq!(s, 400, "a replayed request ID");
    assert!(body.contains("already used"), "{body}");

    let old = authn_request(&fx, entity, "_b4", "", "").replace(
        &protocol::instant(Utc::now()),
        &protocol::instant(Utc::now() - Duration::hours(1)),
    );
    let (s, _) = get(old).await;
    assert_eq!(s, 400);

    let elsewhere = authn_request(&fx, entity, "_b5", "", "")
        .replace(&endpoints(&fx).sso_url, "https://other-idp.example/sso");
    let (s, body) = get(elsewhere).await;
    assert_eq!(s, 400);
    assert!(body.contains("Destination"), "{body}");

    let xxe = format!(
        r#"<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>{}"#,
        authn_request(&fx, entity, "_b6", "", "")
    );
    let (s, _) = get(xxe).await;
    assert_eq!(s, 400);

    let (s, _) = get(authn_request(
        &fx,
        entity,
        "_b7",
        r#"AssertionConsumerServiceIndex="9""#,
        "",
    ))
    .await;
    assert_eq!(s, 400);
}

#[tokio::test]
async fn failures_the_sp_may_hear_are_posted_to_it_as_statuses() {
    let fx = fixture().await;
    let entity = "https://sp.example";
    register(&fx, sp_input(entity)).await;
    let certs = idp_certs(&fx).await;
    let http = browser();
    let status = |xml: &str| {
        let doc = xml::parse(xml).unwrap();
        dsig::verify_enveloped(&doc, doc.root_element(), &certs)
            .expect("error responses are signed");
        status_of(&doc)
    };

    // IsPassive with no session: NoPassive.
    let req = authn_request(&fx, entity, "_f1", r#"IsPassive="true""#, "");
    let res = http
        .get(redirect_url(&fx, &req, None, None))
        .send()
        .await
        .unwrap();
    let (_, xml, _) = posted(res).await;
    assert_eq!(
        status(&xml),
        (
            ns::status::RESPONDER.into(),
            Some(ns::status::NO_PASSIVE.into())
        )
    );

    // A NameID format the SP is not configured for.
    let req = authn_request(
        &fx,
        entity,
        "_f2",
        "",
        &format!(r#"<samlp:NameIDPolicy Format="{}"/>"#, ns::nameid::EMAIL),
    );
    let res = http
        .get(redirect_url(&fx, &req, None, None))
        .send()
        .await
        .unwrap();
    let (_, xml, _) = posted(res).await;
    assert_eq!(
        status(&xml).1.as_deref(),
        Some(ns::status::INVALID_NAMEID_POLICY)
    );

    // A binding responses are never sent with.
    let req = authn_request(
        &fx,
        entity,
        "_f3",
        &format!(r#"ProtocolBinding="{}""#, ns::BINDING_REDIRECT),
        "",
    );
    let res = http
        .get(redirect_url(&fx, &req, None, None))
        .send()
        .await
        .unwrap();
    let (_, xml, _) = posted(res).await;
    assert_eq!(
        status(&xml).1.as_deref(),
        Some(ns::status::UNSUPPORTED_BINDING)
    );

    // The user cancels at the login page: RequestDenied, delivered once.
    let req = authn_request(&fx, entity, "_f4", "", "");
    let res = http
        .get(redirect_url(&fx, &req, Some("keep"), None))
        .send()
        .await
        .unwrap();
    let flow: Uuid = param(&location(&res), "flow").unwrap().parse().unwrap();
    let state: Value = http
        .get(fx.app.tenant_url(&format!("/flows/{flow}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cancelled: Value = http
        .post(fx.app.tenant_url(&format!("/flows/{flow}/cancel")))
        .json(&json!({"csrf": state["csrf"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let to = cancelled["redirect_to"].as_str().unwrap();
    assert!(to.contains("/saml/respond/"), "{to}");
    let (action, xml, relay) = posted(http.get(to).send().await.unwrap()).await;
    assert_eq!(action, format!("{entity}/acs"));
    assert_eq!(relay.as_deref(), Some("keep"));
    let doc = xml::parse(&xml).unwrap();
    assert_eq!(doc.root_element().attribute("InResponseTo"), Some("_f4"));
    assert_eq!(status(&xml).1.as_deref(), Some(ns::status::REQUEST_DENIED));
    assert_eq!(http.get(to).send().await.unwrap().status(), 404);
}

#[tokio::test]
async fn assertions_are_encrypted_to_the_sp_when_it_asks() {
    let fx = fixture().await;
    let entity = "https://secret.example";
    register(
        &fx,
        SamlSpInput {
            encryption_certificate: Some(sp_key().1.to_pem()),
            encrypt_assertion: Some(true),
            name_id_format: Some(NameIdFormat::Email),
            attributes: Some(vec![SamlAttribute {
                claim: "email".into(),
                name: "urn:oid:0.9.2342.19200300.100.1.3".into(),
                name_format: ridm_api::models::AttributeNameFormat::Uri,
                friendly_name: Some("mail".into()),
            }]),
            ..sp_input(entity)
        },
    )
    .await;
    let certs = idp_certs(&fx).await;
    let http = browser();
    let req = authn_request(&fx, entity, "_e1", "", "");
    let res = http
        .get(redirect_url(&fx, &req, None, None))
        .send()
        .await
        .unwrap();
    let (_, xml, _) = posted(sign_in(&http, &fx, &location(&res)).await).await;
    assert!(
        !xml.contains("alice@example.com"),
        "nothing readable on the wire"
    );
    let doc = xml::parse(&xml).unwrap();
    dsig::verify_enveloped(&doc, doc.root_element(), &certs).unwrap();
    let encrypted = doc
        .descendants()
        .find(|n| is(*n, ns::XENC, "EncryptedData"))
        .expect("an encrypted assertion");
    let plain = xmlenc::decrypt(encrypted, &sp_key().0).unwrap();
    let inner = xml::parse(&plain).unwrap();
    let a = read_assertion(inner.root_element(), &inner, &certs);
    assert_eq!(a.name_id, "alice@example.com");
    assert_eq!(a.name_id_format, ns::nameid::EMAIL);
    // Only the mapped attribute, under the SP's name.
    assert_eq!(a.attributes.len(), 1);
    assert_eq!(
        a.attributes["urn:oid:0.9.2342.19200300.100.1.3"],
        ["alice@example.com"]
    );
}

#[tokio::test]
async fn idp_initiated_sign_in_needs_the_sps_consent() {
    let fx = fixture().await;
    register(&fx, sp_input("https://closed.example")).await;
    let open = register(
        &fx,
        SamlSpInput {
            allow_idp_initiated: Some(true),
            default_relay_state: Some("/dashboard".into()),
            ..sp_input("https://open.example")
        },
    )
    .await;
    let certs = idp_certs(&fx).await;
    let http = browser();
    let init = |sp: &str| format!("{}?sp={}", fx.app.tenant_url("/saml/init"), urlencoding(sp));

    let res = http
        .get(init("https://closed.example"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // By client id as well as entity ID.
    let res = http.get(init(&open.client.client_id)).send().await.unwrap();
    assert_eq!(res.status(), 303);
    let (action, xml, relay) = posted(sign_in(&http, &fx, &location(&res)).await).await;
    assert_eq!(action, "https://open.example/acs");
    assert_eq!(relay.as_deref(), Some("/dashboard"));
    let a = accept(&xml, &certs);
    assert!(a.in_response_to.is_none(), "unsolicited");
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Sign alice in to `entity` and return what it was told.
async fn sso(
    http: &reqwest::Client,
    fx: &Fx,
    entity: &str,
    id: &str,
    certs: &[Certificate],
) -> Assertion {
    let req = authn_request(fx, entity, id, "", "");
    let res = http
        .get(redirect_url(fx, &req, None, None))
        .send()
        .await
        .unwrap();
    assert!(res.status() == 303 || res.status() == 200);
    let res = if res.status() == 303 {
        sign_in(http, fx, &location(&res)).await
    } else {
        res
    };
    accept(&posted(res).await.1, certs)
}

#[tokio::test]
async fn sp_initiated_logout_walks_the_other_sps_then_answers() {
    let fx = fixture().await;
    let a_entity = "https://a.example";
    let b_entity = "https://b.example";
    register(&fx, sp_input(a_entity)).await;
    register(
        &fx,
        SamlSpInput {
            signing_certificates: vec![sp_key().1.to_pem()],
            ..sp_input(b_entity)
        },
    )
    .await;
    let certs = idp_certs(&fx).await;
    let http = browser();
    let at_a = sso(&http, &fx, a_entity, "_la", &certs).await;
    let at_b = sso(&http, &fx, b_entity, "_lb", &certs).await;

    // A asks to end the session.
    let ep = endpoints(&fx);
    let logout = protocol::logout_request(
        a_entity,
        &ep.slo_url,
        &protocol::NameId {
            value: at_a.name_id.clone(),
            format: Some(at_a.name_id_format.clone()),
            sp_name_qualifier: None,
        },
        &at_a.session_index,
        Utc::now(),
    )
    .to_string();
    let a_request_id = xml::parse(&logout)
        .unwrap()
        .root_element()
        .attribute("ID")
        .unwrap()
        .to_string();
    let url =
        binding::to_redirect(&ep.slo_url, Kind::Request, &logout, Some("a-relay"), None).unwrap();
    let res = http.get(url).send().await.unwrap();

    // rIDM sends B a signed LogoutRequest for its own NameID first.
    assert_eq!(res.status(), 303);
    let to_b = location(&res);
    assert!(to_b.starts_with(&format!("{b_entity}/slo?")), "{to_b}");
    let received = binding::from_redirect(to_b.split_once('?').unwrap().1).unwrap();
    received
        .signature
        .as_ref()
        .expect("signed")
        .verify(&certs)
        .unwrap();
    let doc = xml::parse(&received.xml).unwrap();
    let to_b_req = protocol::parse_logout_request(&doc).unwrap();
    assert_eq!(to_b_req.name_id.value, at_b.name_id);
    assert_eq!(
        to_b_req.session_indexes,
        std::slice::from_ref(&at_b.session_index)
    );
    let chain = received.relay_state.clone().unwrap();

    // B answers (signed, as it has a registered certificate).
    let answer = protocol::logout_response(
        b_entity,
        &ep.slo_url,
        &to_b_req.id,
        (ns::status::SUCCESS, None),
        Utc::now(),
    )
    .to_string();
    let url = binding::to_redirect(
        &ep.slo_url,
        Kind::Response,
        &answer,
        Some(&chain),
        Some(&sp_signer()),
    )
    .unwrap();
    let res = http.get(url).send().await.unwrap();

    // Then A hears Success, with its RelayState.
    assert_eq!(res.status(), 303);
    let to_a = location(&res);
    assert!(to_a.starts_with(&format!("{a_entity}/slo?")), "{to_a}");
    let received = binding::from_redirect(to_a.split_once('?').unwrap().1).unwrap();
    received.signature.as_ref().unwrap().verify(&certs).unwrap();
    assert_eq!(received.relay_state.as_deref(), Some("a-relay"));
    let doc = xml::parse(&received.xml).unwrap();
    let done = protocol::parse_logout_response(&doc).unwrap();
    assert_eq!(done.in_response_to.as_deref(), Some(a_request_id.as_str()));
    assert_eq!(done.status, ns::status::SUCCESS);

    // The session is over: SSO asks for a sign-in again.
    let req = authn_request(&fx, a_entity, "_after", "", "");
    let res = http
        .get(redirect_url(&fx, &req, None, None))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    assert!(location(&res).contains("/login/"));

    // B's answer cannot be replayed into another chain step.
    let url = binding::to_redirect(
        &ep.slo_url,
        Kind::Response,
        &answer,
        Some(&chain),
        Some(&sp_signer()),
    )
    .unwrap();
    assert_eq!(http.get(url).send().await.unwrap().status(), 400);
}

#[tokio::test]
async fn an_oidc_logout_walks_the_saml_sps_before_leaving() {
    let fx = fixture().await;
    let entity = "https://sp.example";
    register(&fx, sp_input(entity)).await;
    let certs = idp_certs(&fx).await;
    let http = browser();
    let at_sp = sso(&http, &fx, entity, "_o1", &certs).await;

    // No id_token_hint and no client: the UI asks for confirmation.
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
    let chain_url = confirmed["redirect_to"].as_str().unwrap();
    assert!(chain_url.contains("/saml/slo/chain/"), "{confirmed}");

    let res = http.get(chain_url).send().await.unwrap();
    assert_eq!(res.status(), 303);
    let to_sp = location(&res);
    let received = binding::from_redirect(to_sp.split_once('?').unwrap().1).unwrap();
    received.signature.as_ref().unwrap().verify(&certs).unwrap();
    let doc = xml::parse(&received.xml).unwrap();
    let req = protocol::parse_logout_request(&doc).unwrap();
    assert_eq!(req.name_id.value, at_sp.name_id);

    // The SP answers; rIDM goes on to the signed-out page.
    let ep = endpoints(&fx);
    let answer = protocol::logout_response(
        entity,
        &ep.slo_url,
        &req.id,
        (ns::status::SUCCESS, None),
        Utc::now(),
    )
    .to_string();
    let url = binding::to_redirect(
        &ep.slo_url,
        Kind::Response,
        &answer,
        received.relay_state.as_deref(),
        None,
    )
    .unwrap();
    let res = http.get(url).send().await.unwrap();
    assert_eq!(res.status(), 303);
    assert!(location(&res).contains("/logout/"), "{}", location(&res));
}

#[tokio::test]
async fn admins_register_sps_from_metadata_and_roll_the_signing_key() {
    let fx = fixture().await;
    let token = admin_token(&fx.app, fx.tenant.id, OWNER_ROLE).await;
    let base = format!("/admin/tenants/{}/saml", fx.tenant.slug);

    let (s, idp, _) = call(&fx.app, Method::GET, &base, Some(&token), None).await;
    assert_eq!(s, 200, "{idp}");
    assert_eq!(idp["keys"].as_array().unwrap().len(), 1);
    assert_eq!(idp["sso_url"], endpoints(&fx).sso_url);

    let metadata = format!(
        r#"<md:EntityDescriptor xmlns:md="{md}" xmlns:ds="{ds}" entityID="https://imported.example">
  <md:SPSSODescriptor protocolSupportEnumeration="{p}" AuthnRequestsSigned="true">
    <md:KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleLogoutService Binding="{post}" Location="https://imported.example/slo"/>
    <md:AssertionConsumerService Binding="{post}" Location="https://imported.example/acs" index="0"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"#,
        md = ns::METADATA,
        ds = ns::DSIG,
        p = ns::PROTOCOL,
        cert = sp_key().1.to_base64(),
        post = ns::BINDING_POST,
    );
    let (s, draft, _) = call(
        &fx.app,
        Method::POST,
        &format!("{base}/service-providers/metadata"),
        Some(&token),
        Some(&json!({"metadata": metadata})),
    )
    .await;
    assert_eq!(s, 200, "{draft}");
    assert_eq!(draft["entity_id"], "https://imported.example");
    assert_eq!(draft["require_signed_requests"], true);
    assert_eq!(draft["slo_binding"], "post");

    let (s, created, _) = call(
        &fx.app,
        Method::POST,
        &format!("{base}/service-providers"),
        Some(&token),
        Some(&draft),
    )
    .await;
    assert_eq!(s, 201, "{created}");
    assert_eq!(created["client"]["client_type"], "saml");
    let id = created["client"]["id"].as_str().unwrap().to_string();
    let sp_path = format!("{base}/service-providers/{id}");

    // The same entity ID twice is a conflict.
    let (s, _, _) = call(
        &fx.app,
        Method::POST,
        &format!("{base}/service-providers"),
        Some(&token),
        Some(&draft),
    )
    .await;
    assert_eq!(s, 409);

    // The OIDC client routes will not edit its metadata, but they do
    // disable it, and a disabled SP gets no sign-in.
    let clients = format!("/admin/tenants/{}/clients/{id}", fx.tenant.slug);
    let (s, _, _) = call(
        &fx.app,
        Method::PATCH,
        &clients,
        Some(&token),
        Some(&json!({"name": "x"})),
    )
    .await;
    assert_eq!(s, 409);
    let (s, _, _) = call(
        &fx.app,
        Method::PATCH,
        &clients,
        Some(&token),
        Some(&json!({"status": "disabled"})),
    )
    .await;
    assert_eq!(s, 200);
    let signed = {
        let mut el = El::new("samlp:AuthnRequest")
            .attr("xmlns:samlp", ns::PROTOCOL)
            .attr("xmlns:saml", ns::ASSERTION)
            .attr("ID", "_disabled")
            .attr("Version", "2.0")
            .attr("IssueInstant", protocol::instant(Utc::now()))
            .attr("Destination", endpoints(&fx).sso_url)
            .child(El::new("saml:Issuer").text("https://imported.example"));
        sp_signer().sign_enveloped(&mut el, 1).unwrap();
        el.to_document()
    };
    let res = browser()
        .get(redirect_url(&fx, &signed, None, None))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let (s, _, _) = call(
        &fx.app,
        Method::PATCH,
        &clients,
        Some(&token),
        Some(&json!({"status": "active"})),
    )
    .await;
    assert_eq!(s, 200);

    // A KeyDescriptor without `use` serves both purposes.
    assert_eq!(
        draft["encryption_certificate"],
        json!(sp_key().1.to_base64())
    );
    let mut edit = draft.clone();
    edit["name"] = json!("Imported");
    edit["encrypt_assertion"] = json!(true);
    edit["encryption_certificate"] = Value::Null;
    let (s, body, _) = call(&fx.app, Method::PUT, &sp_path, Some(&token), Some(&edit)).await;
    assert_eq!(s, 400, "no encryption certificate: {body}");
    edit["encryption_certificate"] = json!(sp_key().1.to_pem());
    let (s, body, _) = call(&fx.app, Method::PUT, &sp_path, Some(&token), Some(&edit)).await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["saml"]["encrypt_assertion"], true);
    assert_eq!(body["client"]["name"], "Imported");
    let (s, list, _) = call(
        &fx.app,
        Method::GET,
        &format!("{base}/service-providers"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(list.as_array().unwrap().len(), 1);

    // Rollover: a pending key is published at once but signs nothing.
    let old = idp_certs(&fx).await;
    let (s, pending, _) = call(
        &fx.app,
        Method::POST,
        &format!("{base}/keys"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(s, 201, "{pending}");
    let (s, _, _) = call(
        &fx.app,
        Method::POST,
        &format!("{base}/keys"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(s, 409, "one pending key at a time");
    let both = idp_certs(&fx).await;
    assert_eq!(both.len(), 2);
    assert_eq!(both[0], old[0], "the active key is listed first");

    register(&fx, sp_input("https://sp.example")).await;
    let http = browser();
    let a = sso(&http, &fx, "https://sp.example", "_k1", &old).await;
    assert!(!a.name_id.is_empty());

    let key = pending["id"].as_str().unwrap();
    let (s, _, _) = call(
        &fx.app,
        Method::POST,
        &format!("{base}/keys/{key}/activate"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(s, 204);
    let new_cert: Vec<Certificate> = idp_certs(&fx)
        .await
        .into_iter()
        .filter(|c| *c != old[0])
        .collect();
    sso(&http, &fx, "https://sp.example", "_k2", &new_cert).await;

    // The retired key can go; the active one cannot.
    let (_, idp, _) = call(&fx.app, Method::GET, &base, Some(&token), None).await;
    let retiring = idp["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["status"] == "retiring")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("{base}/keys/{key}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(s, 409);
    let (s, _, _) = call(
        &fx.app,
        Method::DELETE,
        &format!("{base}/keys/{retiring}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(s, 204);
    assert_eq!(idp_certs(&fx).await, new_cert);

    let (s, _, _) = call(&fx.app, Method::DELETE, &sp_path, Some(&token), None).await;
    assert_eq!(s, 204);
    let (s, _, _) = call(&fx.app, Method::GET, &sp_path, Some(&token), None).await;
    assert_eq!(s, 404);
}

#[tokio::test]
async fn slo_binding_post_and_unknown_answers() {
    let fx = fixture().await;
    let entity = "https://post.example";
    register(
        &fx,
        SamlSpInput {
            slo_binding: Some(SloBinding::Post),
            ..sp_input(entity)
        },
    )
    .await;
    let certs = idp_certs(&fx).await;
    let http = browser();
    let at = sso(&http, &fx, entity, "_q1", &certs).await;

    // SP-initiated logout by POST, found by SessionIndex; the answer is a
    // signed LogoutResponse posted back.
    let ep = endpoints(&fx);
    let logout = protocol::logout_request(
        entity,
        &ep.slo_url,
        &protocol::NameId {
            value: at.name_id.clone(),
            format: Some(at.name_id_format.clone()),
            sp_name_qualifier: None,
        },
        &at.session_index,
        Utc::now(),
    )
    .to_document();
    let res = reqwest::Client::new()
        .post(&ep.slo_url)
        .form(&[("SAMLRequest", STANDARD.encode(&logout))])
        .send()
        .await
        .unwrap();
    let (action, xml, _) = posted(res).await;
    assert_eq!(action, format!("{entity}/slo"));
    let doc = xml::parse(&xml).unwrap();
    dsig::verify_enveloped(&doc, doc.root_element(), &certs).unwrap();
    assert_eq!(
        protocol::parse_logout_response(&doc).unwrap().status,
        ns::status::SUCCESS
    );

    // The browser's session went with it.
    let req = authn_request(&fx, entity, "_q2", "", "");
    let res = http
        .get(redirect_url(&fx, &req, None, None))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);

    // An answer nobody waits for is refused.
    let stray = protocol::logout_response(
        entity,
        &ep.slo_url,
        "_nothing",
        (ns::status::SUCCESS, None),
        Utc::now(),
    )
    .to_string();
    let url = binding::to_redirect(
        &ep.slo_url,
        Kind::Response,
        &stray,
        Some(&Uuid::new_v4().to_string()),
        None,
    )
    .unwrap();
    assert_eq!(http.get(url).send().await.unwrap().status(), 400);
}
