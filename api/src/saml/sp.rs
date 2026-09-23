//! The service-provider side of Web Browser SSO (SAML Profiles §4.1.4):
//! building the `AuthnRequest` rIDM sends an upstream IdP, and validating
//! the `Response` it posts back.
//!
//! Validation reads only elements a verified signature covers. The key is
//! one of the IdP's registered certificates, never the message's
//! `KeyInfo`. The assertion is the single one inside a signed `Response`,
//! or is itself signed; with `want_assertions_signed` it must be. An
//! encrypted assertion is decrypted with the tenant's SAML keys first. Its
//! issuer, audience, recipient, validity window and `InResponseTo` must all
//! be the ones expected, so an assertion meant for another SP, another
//! request or another time proves nothing here. Replay across requests is
//! the caller's (it remembers assertion IDs until they expire).

use chrono::{DateTime, Utc};
use roxmltree::{Document, Node};

use super::cert::Certificate;
use super::dsig;
use super::error::{SamlError, SamlResult};
use super::ns;
use super::protocol::{NameId, instant, new_id};
use super::xml::{self, El, child, children, is, text_of};
use super::xmlenc;

/// How far the IdP's clock may be ahead of or behind ours.
pub const CLOCK_SKEW: chrono::Duration = chrono::Duration::minutes(3);
/// How old a `Response` may be when it arrives.
const MAX_RESPONSE_AGE: chrono::Duration = chrono::Duration::minutes(10);

/// What goes into an `AuthnRequest`.
pub struct AuthnRequestOut<'a> {
    pub sp_entity_id: &'a str,
    /// The IdP's single sign-on service.
    pub destination: &'a str,
    pub acs_url: &'a str,
    pub name_id_format: Option<&'a str>,
    pub force_authn: bool,
    /// Classes asked for with Comparison `exact`; none asks for nothing.
    pub class_refs: &'a [String],
    pub now: DateTime<Utc>,
}

/// An `AuthnRequest` (not yet signed) and its ID, which the `Response`
/// must answer.
pub fn authn_request(r: &AuthnRequestOut) -> (El, String) {
    let id = new_id();
    let policy = El::new("samlp:NameIDPolicy")
        .attr_opt("Format", r.name_id_format)
        .attr("AllowCreate", "true");
    let context = (!r.class_refs.is_empty()).then(|| {
        r.class_refs.iter().fold(
            El::new("samlp:RequestedAuthnContext").attr("Comparison", "exact"),
            |ctx, c| ctx.child(El::new("saml:AuthnContextClassRef").text(c)),
        )
    });
    let el = El::new("samlp:AuthnRequest")
        .attr("xmlns:samlp", ns::PROTOCOL)
        .attr("xmlns:saml", ns::ASSERTION)
        .attr("ID", &id)
        .attr("Version", "2.0")
        .attr("IssueInstant", instant(r.now))
        .attr("Destination", r.destination)
        .attr("AssertionConsumerServiceURL", r.acs_url)
        .attr("ProtocolBinding", ns::BINDING_POST)
        .attr_opt("ForceAuthn", r.force_authn.then_some("true"))
        .child(El::new("saml:Issuer").text(r.sp_entity_id))
        .child(policy)
        .child_opt(context);
    (el, id)
}

/// What a `Response` must match.
pub struct Expected<'a> {
    pub idp_entity_id: &'a str,
    pub sp_entity_id: &'a str,
    pub acs_url: &'a str,
    /// The ID of the `AuthnRequest` this answers; `None` for an unsolicited
    /// response, which must then answer no request at all.
    pub in_response_to: Option<&'a str>,
    /// The IdP's registered signing certificates.
    pub certificates: &'a [Certificate],
    /// The tenant's SAML private keys (PKCS#8 DER), any of which the IdP
    /// may have encrypted to.
    pub decryption_keys: &'a [&'a [u8]],
    pub want_assertions_signed: bool,
    pub require_encrypted: bool,
    pub now: DateTime<Utc>,
}

/// One attribute of the assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertedAttribute {
    pub name: String,
    pub friendly_name: Option<String>,
    pub values: Vec<String>,
}

/// What a valid assertion says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asserted {
    pub assertion_id: String,
    /// Until when the assertion could be presented: replay protection
    /// remembers its ID that long.
    pub valid_until: DateTime<Utc>,
    pub name_id: NameId,
    pub session_index: Option<String>,
    pub session_not_on_or_after: Option<DateTime<Utc>>,
    pub authn_instant: Option<DateTime<Utc>>,
    pub authn_context: Option<String>,
    pub attributes: Vec<AssertedAttribute>,
}

/// Why a `Response` gives no identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseError {
    /// The IdP answered with a failure status: the top-level code, the
    /// second-level one and its message.
    Status {
        code: String,
        second: Option<String>,
        message: Option<String>,
    },
    /// The response is not acceptable.
    Invalid(SamlError),
}

impl From<SamlError> for ResponseError {
    fn from(e: SamlError) -> Self {
        Self::Invalid(e)
    }
}

impl std::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status { code, second, .. } => {
                write!(f, "the identity provider answered {code}")?;
                if let Some(s) = second {
                    write!(f, " ({s})")?;
                }
                Ok(())
            }
            Self::Invalid(e) => e.fmt(f),
        }
    }
}

fn bad(s: impl Into<String>) -> SamlError {
    SamlError::malformed(s)
}

fn time(node: Node, name: &str) -> SamlResult<Option<DateTime<Utc>>> {
    node.attribute(name)
        .map(|v| {
            DateTime::parse_from_rfc3339(v.trim())
                .map(|t| t.with_timezone(&Utc))
                .map_err(|_| bad(format!("{name} is not a date-time")))
        })
        .transpose()
}

/// The `Issuer` of `node`, which must be `expected` when present (and is
/// required when `required`).
fn check_issuer(node: Node, expected: &str, required: bool) -> SamlResult<()> {
    match child(node, ns::ASSERTION, "Issuer")? {
        Some(el) => {
            if let Some(f) = el.attribute("Format")
                && f != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
            {
                return Err(bad("Issuer must be an entity ID"));
            }
            if text_of(el) != expected {
                return Err(bad("the Issuer is not the registered identity provider"));
            }
            Ok(())
        }
        None if required => Err(bad("the assertion has no Issuer")),
        None => Ok(()),
    }
}

/// Read and check a `Response` posted to the assertion consumer service.
pub fn validate_response(xml_text: &str, e: &Expected) -> Result<Asserted, ResponseError> {
    let doc = xml::parse(xml_text)?;
    let root = doc.root_element();
    if !is(root, ns::PROTOCOL, "Response") {
        return Err(bad("not a Response").into());
    }
    if root.attribute("Version") != Some("2.0") {
        return Err(bad("Version must be 2.0").into());
    }
    if root.attribute("ID").is_none() {
        return Err(bad("the Response has no ID").into());
    }
    let issued = time(root, "IssueInstant")?.ok_or_else(|| bad("IssueInstant is missing"))?;
    if issued < e.now - MAX_RESPONSE_AGE - CLOCK_SKEW || issued > e.now + CLOCK_SKEW {
        return Err(
            bad("IssueInstant is outside the accepted window (check the IdP's clock)").into(),
        );
    }
    check_issuer(root, e.idp_entity_id, false)?;

    // A signature on the Response covers everything in it.
    let response_signed = match dsig::signature_of(root)? {
        Some(_) => {
            dsig::verify_enveloped(&doc, root, e.certificates)?;
            true
        }
        None => false,
    };
    match root.attribute("Destination") {
        Some(d) if d != e.acs_url => {
            return Err(bad("Destination is not this service provider's consumer URL").into());
        }
        None if response_signed => {
            return Err(bad("a signed Response must name its Destination").into());
        }
        _ => {}
    }
    check_in_response_to(root.attribute("InResponseTo"), e.in_response_to, "Response")?;

    let status = child(root, ns::PROTOCOL, "Status")?.ok_or_else(|| bad("Status is missing"))?;
    let code =
        child(status, ns::PROTOCOL, "StatusCode")?.ok_or_else(|| bad("StatusCode is missing"))?;
    let top = code
        .attribute("Value")
        .ok_or_else(|| bad("StatusCode has no Value"))?;
    if top != ns::status::SUCCESS {
        return Err(ResponseError::Status {
            code: top.to_string(),
            second: child(code, ns::PROTOCOL, "StatusCode")?
                .and_then(|c| c.attribute("Value"))
                .map(str::to_string),
            message: child(status, ns::PROTOCOL, "StatusMessage")?.map(text_of),
        });
    }

    let plain = children(root, ns::ASSERTION, "Assertion").count();
    let encrypted = children(root, ns::ASSERTION, "EncryptedAssertion").count();
    if plain + encrypted != 1 {
        return Err(bad("a Response must carry exactly one assertion").into());
    }
    if encrypted == 0 {
        if e.require_encrypted {
            return Err(bad("assertions from this identity provider must be encrypted").into());
        }
        let assertion = child(root, ns::ASSERTION, "Assertion")?
            .ok_or_else(|| bad("a Response must carry exactly one assertion"))?;
        return read_assertion(&doc, assertion, response_signed, e);
    }
    let container = child(root, ns::ASSERTION, "EncryptedAssertion")?
        .ok_or_else(|| bad("a Response must carry exactly one assertion"))?;
    let data = child(container, ns::XENC, "EncryptedData")?
        .ok_or_else(|| bad("EncryptedAssertion holds no EncryptedData"))?;
    let decrypted = e
        .decryption_keys
        .iter()
        .find_map(|k| xmlenc::decrypt(data, k).ok())
        .ok_or_else(|| {
            SamlError::Crypto(
                "the assertion could not be decrypted with this tenant's SAML keys".into(),
            )
        })?;
    // The plaintext may use prefixes declared on the Response; it is read
    // inside an element declaring what was in scope where it was.
    let mut wrapper = String::from("<w");
    for n in container.namespaces() {
        match n.name() {
            Some(p) => wrapper.push_str(&format!(" xmlns:{p}=\"{}\"", xml::escape_attr(n.uri()))),
            None => wrapper.push_str(&format!(" xmlns=\"{}\"", xml::escape_attr(n.uri()))),
        }
    }
    let wrapped = format!("{wrapper}>{decrypted}</w>");
    let inner = xml::parse(&wrapped)?;
    let mut elements = inner.root_element().children().filter(Node::is_element);
    let assertion = elements
        .next()
        .filter(|n| is(*n, ns::ASSERTION, "Assertion"))
        .ok_or_else(|| bad("the decrypted content is not an assertion"))?;
    if elements.next().is_some() {
        return Err(bad("the decrypted content is more than one element").into());
    }
    read_assertion(&inner, assertion, response_signed, e)
}

fn check_in_response_to(found: Option<&str>, expected: Option<&str>, what: &str) -> SamlResult<()> {
    match (found, expected) {
        (Some(f), Some(x)) if f == x => Ok(()),
        (None, None) => Ok(()),
        (_, Some(_)) => Err(bad(format!(
            "the {what} does not answer the request rIDM sent"
        ))),
        (Some(_), None) => Err(bad(format!(
            "the {what} answers a request, so it is not unsolicited"
        ))),
    }
}

fn read_assertion(
    doc: &Document,
    a: Node,
    response_signed: bool,
    e: &Expected,
) -> Result<Asserted, ResponseError> {
    let assertion_signed = match dsig::signature_of(a)? {
        Some(_) => {
            dsig::verify_enveloped(doc, a, e.certificates)?;
            true
        }
        None => false,
    };
    if e.want_assertions_signed && !assertion_signed {
        return Err(bad("the assertion must be signed").into());
    }
    if !(assertion_signed || response_signed) {
        return Err(
            SamlError::signature("neither the Response nor the assertion is signed").into(),
        );
    }
    if a.attribute("Version") != Some("2.0") {
        return Err(bad("the assertion's Version must be 2.0").into());
    }
    let assertion_id = a
        .attribute("ID")
        .ok_or_else(|| bad("the assertion has no ID"))?
        .to_string();
    check_issuer(a, e.idp_entity_id, true)?;

    // Subject: the NameID, and a bearer confirmation for this consumer URL,
    // this request and now.
    let subject = child(a, ns::ASSERTION, "Subject")?.ok_or_else(|| bad("Subject is missing"))?;
    if child(subject, ns::ASSERTION, "EncryptedID")?.is_some() {
        return Err(SamlError::Unsupported("an encrypted NameID".into()).into());
    }
    let name_id_el =
        child(subject, ns::ASSERTION, "NameID")?.ok_or_else(|| bad("NameID is missing"))?;
    // Every text node, so a comment cannot shorten the value.
    let name_id = NameId {
        value: text_of(name_id_el),
        format: name_id_el.attribute("Format").map(str::to_string),
        sp_name_qualifier: name_id_el.attribute("SPNameQualifier").map(str::to_string),
    };
    if name_id.value.is_empty() || name_id.value.len() > 512 {
        return Err(bad("the NameID is empty or too long").into());
    }
    let mut confirmed_until = None;
    let mut reasons = vec![];
    for sc in children(subject, ns::ASSERTION, "SubjectConfirmation") {
        if sc.attribute("Method") != Some(ns::CM_BEARER) {
            continue;
        }
        match check_bearer(sc, e) {
            Ok(until) => {
                confirmed_until = Some(until);
                break;
            }
            Err(r) => reasons.push(r),
        }
    }
    let Some(confirmed_until) = confirmed_until else {
        return Err(reasons
            .into_iter()
            .next()
            .unwrap_or_else(|| bad("the assertion has no bearer SubjectConfirmation"))
            .into());
    };

    // Conditions: now, and for this SP.
    let conditions =
        child(a, ns::ASSERTION, "Conditions")?.ok_or_else(|| bad("Conditions are missing"))?;
    if let Some(nb) = time(conditions, "NotBefore")?
        && nb > e.now + CLOCK_SKEW
    {
        return Err(bad("the assertion is not valid yet (check the IdP's clock)").into());
    }
    let mut valid_until = confirmed_until;
    if let Some(na) = time(conditions, "NotOnOrAfter")? {
        if na <= e.now - CLOCK_SKEW {
            return Err(bad("the assertion has expired").into());
        }
        valid_until = valid_until.min(na);
    }
    let mut restrictions = children(conditions, ns::ASSERTION, "AudienceRestriction").peekable();
    if restrictions.peek().is_none() {
        return Err(bad("the assertion names no audience").into());
    }
    for r in restrictions {
        if !children(r, ns::ASSERTION, "Audience").any(|au| text_of(au) == e.sp_entity_id) {
            return Err(bad("the assertion is meant for another service provider").into());
        }
    }

    let authn = children(a, ns::ASSERTION, "AuthnStatement")
        .next()
        .ok_or_else(|| bad("the assertion has no AuthnStatement"))?;
    let session_not_on_or_after = time(authn, "SessionNotOnOrAfter")?;
    if session_not_on_or_after.is_some_and(|t| t <= e.now - CLOCK_SKEW) {
        return Err(bad("the identity provider's session has already ended").into());
    }
    let authn_context = child(authn, ns::ASSERTION, "AuthnContext")?
        .and_then(|c| {
            child(c, ns::ASSERTION, "AuthnContextClassRef")
                .ok()
                .flatten()
        })
        .map(text_of);

    let mut attributes = vec![];
    for statement in children(a, ns::ASSERTION, "AttributeStatement") {
        for attr in children(statement, ns::ASSERTION, "Attribute") {
            let Some(name) = attr.attribute("Name") else {
                return Err(bad("an Attribute has no Name").into());
            };
            attributes.push(AssertedAttribute {
                name: name.to_string(),
                friendly_name: attr.attribute("FriendlyName").map(str::to_string),
                values: children(attr, ns::ASSERTION, "AttributeValue")
                    .map(text_of)
                    .collect(),
            });
        }
    }
    Ok(Asserted {
        assertion_id,
        valid_until,
        name_id,
        session_index: authn.attribute("SessionIndex").map(str::to_string),
        session_not_on_or_after,
        authn_instant: time(authn, "AuthnInstant")?,
        authn_context,
        attributes,
    })
}

/// A bearer `SubjectConfirmation` must be for this consumer URL and this
/// request, and not yet expired; returns until when.
fn check_bearer(sc: Node, e: &Expected) -> SamlResult<DateTime<Utc>> {
    let data = child(sc, ns::ASSERTION, "SubjectConfirmationData")?
        .ok_or_else(|| bad("a bearer confirmation has no SubjectConfirmationData"))?;
    if data.attribute("Recipient") != Some(e.acs_url) {
        return Err(bad(
            "the assertion's Recipient is not this service provider's consumer URL",
        ));
    }
    let until = time(data, "NotOnOrAfter")?
        .ok_or_else(|| bad("a bearer confirmation must expire (NotOnOrAfter)"))?;
    if until <= e.now - CLOCK_SKEW {
        return Err(bad("the assertion has expired"));
    }
    if let Some(nb) = time(data, "NotBefore")?
        && nb > e.now + CLOCK_SKEW
    {
        return Err(bad(
            "the assertion is not valid yet (check the IdP's clock)",
        ));
    }
    check_in_response_to(
        data.attribute("InResponseTo"),
        e.in_response_to,
        "assertion",
    )?;
    Ok(until)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::saml::dsig::Signer;
    use crate::saml::protocol::{self, AssertionContent, Attribute};
    use crate::saml::testkit::{other_rsa_cert, other_rsa_pkcs8, rsa_cert, rsa_pkcs8};
    use crate::saml::xmlenc::{DataEncryption, KeyTransport};

    const IDP: &str = "https://idp.example";
    const SP: &str = "https://ridm/t/acme/broker/corp/saml/metadata";
    const ACS: &str = "https://ridm/t/acme/broker/corp/saml/acs";

    fn idp_signer() -> Signer {
        Signer::new(&rsa_pkcs8(), &rsa_cert().der).unwrap()
    }

    struct Build {
        audience: &'static str,
        recipient: &'static str,
        in_response_to: Option<&'static str>,
        name_id: &'static str,
        sign_assertion: bool,
        sign_response: bool,
        encrypt_to: Option<Certificate>,
        issued: DateTime<Utc>,
    }

    impl Default for Build {
        fn default() -> Self {
            Self {
                audience: SP,
                recipient: ACS,
                in_response_to: Some("_req1"),
                name_id: "alice@idp.example",
                sign_assertion: true,
                sign_response: true,
                encrypt_to: None,
                issued: Utc::now(),
            }
        }
    }

    fn build(b: Build) -> String {
        let attrs = [Attribute {
            name: "mail".into(),
            name_format: ns::ATTRNAME_BASIC,
            friendly_name: Some("email".into()),
            values: vec!["alice@idp.example".into()],
        }];
        let mut a = protocol::assertion(&AssertionContent {
            idp_entity_id: IDP,
            sp_entity_id: b.audience,
            acs_url: b.recipient,
            in_response_to: b.in_response_to,
            name_id: b.name_id,
            name_id_format: ns::nameid::PERSISTENT,
            sp_name_qualifier: Some(SP),
            session_index: "_s1",
            authn_instant: b.issued,
            authn_context: ns::AC_PASSWORD_PROTECTED,
            session_not_on_or_after: None,
            attributes: &attrs,
            now: b.issued,
            lifetime: chrono::Duration::minutes(5),
        });
        let signer = idp_signer();
        if b.sign_assertion {
            signer.sign_enveloped(&mut a, 1).unwrap();
        }
        let body = match &b.encrypt_to {
            Some(cert) => El::new("saml:EncryptedAssertion").child(
                xmlenc::encrypt(
                    &a.to_string(),
                    cert,
                    DataEncryption::Aes256Gcm,
                    KeyTransport::RsaOaepMgf1p,
                )
                .unwrap(),
            ),
            None => a,
        };
        let mut r = protocol::response(
            IDP,
            ACS,
            b.in_response_to,
            b.issued,
            (ns::status::SUCCESS, None, None),
            Some(body),
        );
        if b.sign_response {
            signer.sign_enveloped(&mut r, 1).unwrap();
        }
        r.to_document()
    }

    fn check(xml: &str, tweak: impl FnOnce(&mut Expected)) -> Result<Asserted, ResponseError> {
        let key = rsa_pkcs8();
        check_with(xml, &[rsa_cert()], &[&key], tweak)
    }

    fn check_with(
        xml: &str,
        certs: &[Certificate],
        keys: &[&[u8]],
        tweak: impl FnOnce(&mut Expected),
    ) -> Result<Asserted, ResponseError> {
        let mut e = Expected {
            idp_entity_id: IDP,
            sp_entity_id: SP,
            acs_url: ACS,
            in_response_to: Some("_req1"),
            certificates: certs,
            decryption_keys: keys,
            want_assertions_signed: true,
            require_encrypted: false,
            now: Utc::now(),
        };
        tweak(&mut e);
        validate_response(xml, &e)
    }

    fn refused(r: Result<Asserted, ResponseError>, needle: &str) {
        let err = r.expect_err("accepted");
        assert!(err.to_string().contains(needle), "{err} lacks {needle}");
    }

    #[test]
    fn a_signed_response_is_read() {
        let got = check(&build(Build::default()), |_| {}).unwrap();
        assert_eq!(got.name_id.value, "alice@idp.example");
        assert_eq!(got.name_id.format.as_deref(), Some(ns::nameid::PERSISTENT));
        assert_eq!(got.session_index.as_deref(), Some("_s1"));
        assert_eq!(
            got.authn_context.as_deref(),
            Some(ns::AC_PASSWORD_PROTECTED)
        );
        assert_eq!(
            got.attributes,
            [AssertedAttribute {
                name: "mail".into(),
                friendly_name: Some("email".into()),
                values: vec!["alice@idp.example".into()]
            }]
        );
        assert!(got.valid_until > Utc::now());
    }

    #[test]
    fn an_encrypted_assertion_is_decrypted_with_any_tenant_key() {
        let xml = build(Build {
            encrypt_to: Some(other_rsa_cert()),
            ..Build::default()
        });
        let other = other_rsa_pkcs8();
        let mine = rsa_pkcs8();
        let got = check_with(&xml, &[rsa_cert()], &[&mine, &other], |_| {}).unwrap();
        assert_eq!(got.name_id.value, "alice@idp.example");
        // Not to a key of ours: refused.
        refused(check(&xml, |_| {}), "could not be decrypted");
        // Plain where encryption is required: refused.
        refused(
            check(&build(Build::default()), |e| e.require_encrypted = true),
            "must be encrypted",
        );
    }

    #[test]
    fn signatures_are_required_and_must_be_the_idps() {
        // Unsigned throughout.
        let xml = build(Build {
            sign_assertion: false,
            sign_response: false,
            ..Build::default()
        });
        refused(check(&xml, |e| e.want_assertions_signed = false), "neither");
        // A signed Response around an unsigned assertion: only when the
        // assertion need not be signed itself.
        let xml = build(Build {
            sign_assertion: false,
            ..Build::default()
        });
        refused(check(&xml, |_| {}), "assertion must be signed");
        check(&xml, |e| e.want_assertions_signed = false).unwrap();
        // Signed by someone else.
        let key = rsa_pkcs8();
        refused(
            check_with(
                &build(Build::default()),
                &[other_rsa_cert()],
                &[&key],
                |_| {},
            ),
            "registered certificate",
        );
        // Altered after signing.
        let xml = build(Build::default()).replace("alice@idp.example", "admin@idp.example");
        assert!(check(&xml, |_| {}).is_err());
    }

    #[test]
    fn a_wrapped_assertion_proves_nothing() {
        // The genuine signed assertion is tucked into an Extensions-like
        // spot and a forged one takes its place: the Response then carries
        // two assertions, or the forged one's signature references the
        // wrong ID.
        let genuine = build(Build {
            sign_response: false,
            ..Build::default()
        });
        let doc = xml::parse(&genuine).unwrap();
        let a = child(doc.root_element(), ns::ASSERTION, "Assertion")
            .unwrap()
            .unwrap();
        let a_xml = &genuine[a.range()];
        let forged = a_xml.replace("alice@idp.example", "admin@idp.example");
        let two = genuine.replace(a_xml, &format!("{forged}{a_xml}"));
        refused(check(&two, |_| {}), "exactly one assertion");
        let swapped = genuine.replace(a_xml, &forged);
        assert!(check(&swapped, |_| {}).is_err());
    }

    #[test]
    fn a_comment_cannot_shorten_the_name_id() {
        // Canonicalization drops comments, so the signature still holds;
        // the value read must be the whole text either way.
        let xml = build(Build {
            name_id: "admin@idp.example.evil",
            ..Build::default()
        })
        .replace(
            "admin@idp.example.evil</saml:NameID>",
            "admin@idp.example<!-- x -->.evil</saml:NameID>",
        );
        let got = check(&xml, |_| {}).unwrap();
        assert_eq!(got.name_id.value, "admin@idp.example.evil");
    }

    #[test]
    fn audience_recipient_and_request_must_be_ours() {
        refused(
            check(
                &build(Build {
                    audience: "https://other-sp",
                    ..Build::default()
                }),
                |_| {},
            ),
            "another service provider",
        );
        refused(
            check(
                &build(Build {
                    recipient: "https://other-sp/acs",
                    ..Build::default()
                }),
                |_| {},
            ),
            "Recipient",
        );
        refused(
            check(&build(Build::default()), |e| {
                e.in_response_to = Some("_req2")
            }),
            "does not answer",
        );
        refused(
            check(&build(Build::default()), |e| {
                e.acs_url = "https://ridm/other/acs"
            }),
            "Destination",
        );
        refused(
            check(&build(Build::default()), |e| {
                e.idp_entity_id = "https://other-idp"
            }),
            "Issuer",
        );
    }

    #[test]
    fn unsolicited_responses_answer_no_request() {
        let unsolicited = build(Build {
            in_response_to: None,
            ..Build::default()
        });
        check(&unsolicited, |e| e.in_response_to = None).unwrap();
        // One answering some request cannot be replayed as unsolicited.
        refused(
            check(&build(Build::default()), |e| e.in_response_to = None),
            "not unsolicited",
        );
        // And an unsolicited one is not the answer to ours.
        refused(check(&unsolicited, |_| {}), "does not answer");
    }

    #[test]
    fn stale_and_early_assertions_are_refused() {
        let old = build(Build {
            issued: Utc::now() - chrono::Duration::minutes(30),
            ..Build::default()
        });
        assert!(check(&old, |_| {}).is_err());
        let ahead = build(Build::default());
        refused(
            check(&ahead, |e| {
                e.now = Utc::now() - chrono::Duration::minutes(10)
            }),
            "IssueInstant",
        );
        // Five minutes of lifetime plus the skew, then it is over.
        refused(
            check(&build(Build::default()), |e| {
                e.now = Utc::now() + chrono::Duration::minutes(9)
            }),
            "expired",
        );
    }

    #[test]
    fn a_failure_status_is_reported_as_such() {
        let mut r = protocol::response(
            IDP,
            ACS,
            Some("_req1"),
            Utc::now(),
            (
                ns::status::RESPONDER,
                Some(ns::status::REQUEST_DENIED),
                Some("no"),
            ),
            None,
        );
        idp_signer().sign_enveloped(&mut r, 1).unwrap();
        match check(&r.to_document(), |_| {}) {
            Err(ResponseError::Status {
                code,
                second,
                message,
            }) => {
                assert_eq!(code, ns::status::RESPONDER);
                assert_eq!(second.as_deref(), Some(ns::status::REQUEST_DENIED));
                assert_eq!(message.as_deref(), Some("no"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_authn_request_carries_what_the_idp_checks() {
        let classes = [ns::AC_REFEDS_MFA.to_string()];
        let (el, id) = authn_request(&AuthnRequestOut {
            sp_entity_id: SP,
            destination: "https://idp.example/sso",
            acs_url: ACS,
            name_id_format: Some(ns::nameid::PERSISTENT),
            force_authn: true,
            class_refs: &classes,
            now: Utc::now(),
        });
        let text = el.to_document();
        let doc = xml::parse(&text).unwrap();
        // rIDM's own IdP reader accepts it.
        let r = protocol::parse_authn_request(&doc).unwrap();
        assert_eq!(r.id, id);
        assert_eq!(r.issuer, SP);
        assert_eq!(r.acs_url.as_deref(), Some(ACS));
        assert_eq!(r.protocol_binding.as_deref(), Some(ns::BINDING_POST));
        assert!(r.force_authn);
        assert_eq!(r.name_id_format.as_deref(), Some(ns::nameid::PERSISTENT));
        assert_eq!(r.requested_authn_context.unwrap().class_refs, classes);
    }

    #[test]
    fn xmlsec1_signed_responses_are_accepted() {
        use crate::saml::testkit::{rsa_key_pem, scratch, xmlsec1, xmlsec1_lax};
        let Some(tool) = xmlsec1() else {
            eprintln!("xmlsec1 not installed; interop not checked");
            return;
        };
        let dir = scratch("sp-response");
        let now = Utc::now();
        let template = format!(
            r##"<samlp:Response xmlns:samlp="{p}" xmlns:saml="{a}" ID="_r1" Version="2.0" IssueInstant="{t}" Destination="{acs}" InResponseTo="_req1">
  <saml:Issuer>{idp}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="{ok}"/></samlp:Status>
  <saml:Assertion ID="_a1" Version="2.0" IssueInstant="{t}">
    <saml:Issuer>{idp}</saml:Issuer>
    <ds:Signature xmlns:ds="{d}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{c}"/><ds:SignatureMethod Algorithm="{s}"/><ds:Reference URI="#_a1"><ds:Transforms><ds:Transform Algorithm="{e}"/><ds:Transform Algorithm="{c}"/></ds:Transforms><ds:DigestMethod Algorithm="{h}"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature>
    <saml:Subject>
      <saml:NameID Format="{pers}">bob</saml:NameID>
      <saml:SubjectConfirmation Method="{bearer}"><saml:SubjectConfirmationData InResponseTo="_req1" NotOnOrAfter="{until}" Recipient="{acs}"/></saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{t}" NotOnOrAfter="{until}"><saml:AudienceRestriction><saml:Audience>{sp}</saml:Audience></saml:AudienceRestriction></saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{t}" SessionIndex="_sx"><saml:AuthnContext><saml:AuthnContextClassRef>{pw}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>"##,
            p = ns::PROTOCOL,
            a = ns::ASSERTION,
            d = ns::DSIG,
            c = ns::alg::EXC_C14N,
            s = ns::alg::RSA_SHA256,
            e = ns::alg::ENVELOPED,
            h = ns::alg::SHA256,
            t = instant(now),
            until = instant(now + chrono::Duration::minutes(5)),
            acs = ACS,
            idp = IDP,
            sp = SP,
            ok = ns::status::SUCCESS,
            pers = ns::nameid::PERSISTENT,
            bearer = ns::CM_BEARER,
            pw = ns::AC_PASSWORD_PROTECTED,
        );
        let tmpl = dir.join("response.xml");
        let key = dir.join("key.pem");
        std::fs::write(&tmpl, template).unwrap();
        std::fs::write(&key, rsa_key_pem()).unwrap();
        let out = std::process::Command::new(&tool)
            .arg("--sign")
            .args(xmlsec1_lax())
            .arg("--privkey-pem")
            .arg(&key)
            .arg("--id-attr:ID")
            .arg(format!("{}:Assertion", ns::ASSERTION))
            .arg(&tmpl)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let signed = String::from_utf8(out.stdout).unwrap();
        let got = check(&signed, |_| {}).unwrap();
        assert_eq!(got.name_id.value, "bob");
        assert_eq!(got.session_index.as_deref(), Some("_sx"));
        assert!(check(&signed.replace(">bob<", ">eve<"), |_| {}).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
