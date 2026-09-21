//! SAML 2.0 protocol messages (SAML Core §3): reading `AuthnRequest`,
//! `LogoutRequest` and `LogoutResponse`, and building `Response` (with its
//! `Assertion`), `LogoutRequest` and `LogoutResponse`.
//!
//! Parsing checks shape only; what a message may ask for (its issuer, its
//! consumer URL, its signature, its age) is the caller's business.

use chrono::{DateTime, Utc};
use roxmltree::{Document, Node};

use super::error::{SamlError, SamlResult};
use super::ns;
use super::xml::{El, child, is, text_of};

/// A fresh message or assertion ID: an NCName, 128 random bits.
pub fn new_id() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    format!("_{}", hex::encode(bytes))
}

/// `xs:dateTime` in UTC, whole seconds, as SAML profiles expect.
pub fn instant(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn parse_instant(s: &str) -> SamlResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s.trim())
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| SamlError::malformed("IssueInstant is not a UTC date-time"))
}

fn required_attr<'a>(node: Node<'a, '_>, name: &str) -> SamlResult<&'a str> {
    node.attribute(name)
        .ok_or_else(|| SamlError::malformed(format!("{name} is missing")))
}

fn issuer(node: Node) -> SamlResult<String> {
    let el = child(node, ns::ASSERTION, "Issuer")?
        .ok_or_else(|| SamlError::malformed("Issuer is missing"))?;
    // Only the entity format (the default) names an SP.
    if let Some(f) = el.attribute("Format")
        && f != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
    {
        return Err(SamlError::malformed("Issuer must be an entity ID"));
    }
    let v = text_of(el);
    if v.is_empty() {
        return Err(SamlError::malformed("Issuer is empty"));
    }
    Ok(v)
}

/// What every request shares (SAML Core §3.2.1).
fn request_header(root: Node) -> SamlResult<(String, DateTime<Utc>, Option<String>, String)> {
    if root.attribute("Version") != Some("2.0") {
        return Err(SamlError::malformed("Version must be 2.0"));
    }
    let id = required_attr(root, "ID")?.to_string();
    let instant = parse_instant(required_attr(root, "IssueInstant")?)?;
    let destination = root.attribute("Destination").map(str::to_string);
    Ok((id, instant, destination, issuer(root)?))
}

fn boolean(node: Node, name: &str) -> SamlResult<bool> {
    match node.attribute(name) {
        None | Some("false") | Some("0") => Ok(false),
        Some("true") | Some("1") => Ok(true),
        Some(_) => Err(SamlError::malformed(format!("{name} is not a boolean"))),
    }
}

/// `RequestedAuthnContext` (SAML Core §3.3.2.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedAuthnContext {
    /// `exact` (the default), `minimum`, `maximum` or `better`.
    pub comparison: String,
    pub class_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnRequest {
    pub id: String,
    pub issuer: String,
    pub issue_instant: DateTime<Utc>,
    pub destination: Option<String>,
    pub acs_url: Option<String>,
    pub acs_index: Option<u32>,
    pub protocol_binding: Option<String>,
    pub force_authn: bool,
    pub is_passive: bool,
    pub name_id_format: Option<String>,
    pub requested_authn_context: Option<RequestedAuthnContext>,
}

/// Read an `AuthnRequest` document (its root element).
pub fn parse_authn_request(doc: &Document) -> SamlResult<AuthnRequest> {
    let root = doc.root_element();
    if !is(root, ns::PROTOCOL, "AuthnRequest") {
        return Err(SamlError::malformed("not an AuthnRequest"));
    }
    let (id, issue_instant, destination, issuer) = request_header(root)?;
    let acs_index =
        match root.attribute("AssertionConsumerServiceIndex") {
            Some(i) => Some(i.parse::<u32>().map_err(|_| {
                SamlError::malformed("AssertionConsumerServiceIndex is not a number")
            })?),
            None => None,
        };
    let acs_url = root
        .attribute("AssertionConsumerServiceURL")
        .map(str::to_string);
    if acs_url.is_some() && acs_index.is_some() {
        return Err(SamlError::malformed(
            "AssertionConsumerServiceURL and AssertionConsumerServiceIndex exclude each other",
        ));
    }
    let name_id_format = child(root, ns::PROTOCOL, "NameIDPolicy")?
        .and_then(|p| p.attribute("Format"))
        .map(str::to_string);
    let requested_authn_context = match child(root, ns::PROTOCOL, "RequestedAuthnContext")? {
        None => None,
        Some(rac) => {
            let comparison = rac.attribute("Comparison").unwrap_or("exact").to_string();
            if !matches!(
                comparison.as_str(),
                "exact" | "minimum" | "maximum" | "better"
            ) {
                return Err(SamlError::malformed(
                    "unknown RequestedAuthnContext Comparison",
                ));
            }
            if rac
                .children()
                .any(|c| is(c, ns::ASSERTION, "AuthnContextDeclRef"))
            {
                return Err(SamlError::Unsupported("AuthnContextDeclRef".into()));
            }
            let class_refs: Vec<String> = rac
                .children()
                .filter(|c| is(*c, ns::ASSERTION, "AuthnContextClassRef"))
                .map(text_of)
                .collect();
            Some(RequestedAuthnContext {
                comparison,
                class_refs,
            })
        }
    };
    if child(root, ns::ASSERTION, "Subject")?.is_some() {
        return Err(SamlError::Unsupported(
            "a Subject in an AuthnRequest".into(),
        ));
    }
    Ok(AuthnRequest {
        id,
        issuer,
        issue_instant,
        destination,
        acs_url,
        acs_index,
        protocol_binding: root.attribute("ProtocolBinding").map(str::to_string),
        force_authn: boolean(root, "ForceAuthn")?,
        is_passive: boolean(root, "IsPassive")?,
        name_id_format,
        requested_authn_context,
    })
}

/// A `NameID` as sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameId {
    pub value: String,
    pub format: Option<String>,
    pub sp_name_qualifier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutRequest {
    pub id: String,
    pub issuer: String,
    pub issue_instant: DateTime<Utc>,
    pub destination: Option<String>,
    pub not_on_or_after: Option<DateTime<Utc>>,
    pub name_id: NameId,
    pub session_indexes: Vec<String>,
}

pub fn parse_logout_request(doc: &Document) -> SamlResult<LogoutRequest> {
    let root = doc.root_element();
    if !is(root, ns::PROTOCOL, "LogoutRequest") {
        return Err(SamlError::malformed("not a LogoutRequest"));
    }
    let (id, issue_instant, destination, issuer) = request_header(root)?;
    if child(root, ns::ASSERTION, "EncryptedID")?.is_some() {
        return Err(SamlError::Unsupported("an encrypted NameID".into()));
    }
    let name_id = child(root, ns::ASSERTION, "NameID")?
        .ok_or_else(|| SamlError::malformed("NameID is missing"))?;
    let not_on_or_after = root
        .attribute("NotOnOrAfter")
        .map(parse_instant)
        .transpose()?;
    Ok(LogoutRequest {
        id,
        issuer,
        issue_instant,
        destination,
        not_on_or_after,
        name_id: NameId {
            value: text_of(name_id),
            format: name_id.attribute("Format").map(str::to_string),
            sp_name_qualifier: name_id.attribute("SPNameQualifier").map(str::to_string),
        },
        session_indexes: root
            .children()
            .filter(|c| is(*c, ns::PROTOCOL, "SessionIndex"))
            .map(text_of)
            .collect(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutResponse {
    pub id: String,
    pub issuer: String,
    pub in_response_to: Option<String>,
    pub destination: Option<String>,
    /// The top-level status code.
    pub status: String,
}

pub fn parse_logout_response(doc: &Document) -> SamlResult<LogoutResponse> {
    let root = doc.root_element();
    if !is(root, ns::PROTOCOL, "LogoutResponse") {
        return Err(SamlError::malformed("not a LogoutResponse"));
    }
    let (id, _, destination, issuer) = request_header(root)?;
    let status = child(root, ns::PROTOCOL, "Status")?
        .and_then(|s| child(s, ns::PROTOCOL, "StatusCode").ok().flatten())
        .and_then(|c| c.attribute("Value"))
        .ok_or_else(|| SamlError::malformed("StatusCode is missing"))?
        .to_string();
    Ok(LogoutResponse {
        id,
        issuer,
        in_response_to: root.attribute("InResponseTo").map(str::to_string),
        destination,
        status,
    })
}

fn issuer_el(entity_id: &str) -> El {
    El::new("saml:Issuer").text(entity_id)
}

fn status_el(code: &str, second: Option<&str>, message: Option<&str>) -> El {
    let mut top = El::new("samlp:StatusCode").attr("Value", code);
    if let Some(s) = second {
        top = top.child(El::new("samlp:StatusCode").attr("Value", s));
    }
    El::new("samlp:Status")
        .child(top)
        .child_opt(message.map(|m| El::new("samlp:StatusMessage").text(m)))
}

/// One attribute and its values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub name: String,
    pub name_format: &'static str,
    pub friendly_name: Option<String>,
    pub values: Vec<String>,
}

/// What goes into an assertion.
#[derive(Debug, Clone)]
pub struct AssertionContent<'a> {
    pub idp_entity_id: &'a str,
    pub sp_entity_id: &'a str,
    pub acs_url: &'a str,
    pub in_response_to: Option<&'a str>,
    pub name_id: &'a str,
    pub name_id_format: &'a str,
    /// `SPNameQualifier` for persistent and transient identifiers.
    pub sp_name_qualifier: Option<&'a str>,
    pub session_index: &'a str,
    pub authn_instant: DateTime<Utc>,
    pub authn_context: &'a str,
    pub session_not_on_or_after: Option<DateTime<Utc>>,
    pub attributes: &'a [Attribute],
    pub now: DateTime<Utc>,
    pub lifetime: chrono::Duration,
}

/// The assertion (not yet signed or encrypted).
pub fn assertion(c: &AssertionContent) -> El {
    let not_before = c.now - chrono::Duration::seconds(60);
    let not_after = c.now + c.lifetime;
    let subject = El::new("saml:Subject")
        .child(
            El::new("saml:NameID")
                .attr("Format", c.name_id_format)
                .attr_opt("SPNameQualifier", c.sp_name_qualifier)
                .text(c.name_id),
        )
        .child(
            El::new("saml:SubjectConfirmation")
                .attr("Method", ns::CM_BEARER)
                .child(
                    El::new("saml:SubjectConfirmationData")
                        .attr_opt("InResponseTo", c.in_response_to)
                        .attr("NotOnOrAfter", instant(not_after))
                        .attr("Recipient", c.acs_url),
                ),
        );
    let conditions = El::new("saml:Conditions")
        .attr("NotBefore", instant(not_before))
        .attr("NotOnOrAfter", instant(not_after))
        .child(
            El::new("saml:AudienceRestriction")
                .child(El::new("saml:Audience").text(c.sp_entity_id)),
        );
    let authn = El::new("saml:AuthnStatement")
        .attr("AuthnInstant", instant(c.authn_instant))
        .attr("SessionIndex", c.session_index)
        .attr_opt(
            "SessionNotOnOrAfter",
            c.session_not_on_or_after.map(instant),
        )
        .child(
            El::new("saml:AuthnContext")
                .child(El::new("saml:AuthnContextClassRef").text(c.authn_context)),
        );
    let attributes = (!c.attributes.is_empty()).then(|| {
        c.attributes
            .iter()
            .fold(El::new("saml:AttributeStatement"), |statement, a| {
                let attr = a.values.iter().fold(
                    El::new("saml:Attribute")
                        .attr("Name", &a.name)
                        .attr("NameFormat", a.name_format)
                        .attr_opt("FriendlyName", a.friendly_name.as_deref()),
                    |attr, v| {
                        attr.child(
                            El::new("saml:AttributeValue")
                                .attr("xsi:type", "xs:string")
                                .text(v),
                        )
                    },
                );
                statement.child(attr)
            })
    });
    El::new("saml:Assertion")
        .attr("xmlns:saml", ns::ASSERTION)
        .attr("xmlns:xs", ns::XS)
        .attr("xmlns:xsi", ns::XSI)
        .attr("ID", new_id())
        .attr("Version", "2.0")
        .attr("IssueInstant", instant(c.now))
        .child(issuer_el(c.idp_entity_id))
        .child(subject)
        .child(conditions)
        .child(authn)
        .child_opt(attributes)
}

/// A `samlp:Response` around `body` (an assertion, an encrypted assertion,
/// or nothing for an error), with its status.
pub fn response(
    idp_entity_id: &str,
    destination: &str,
    in_response_to: Option<&str>,
    now: DateTime<Utc>,
    status: (&str, Option<&str>, Option<&str>),
    body: Option<El>,
) -> El {
    El::new("samlp:Response")
        .attr("xmlns:samlp", ns::PROTOCOL)
        .attr("xmlns:saml", ns::ASSERTION)
        .attr("ID", new_id())
        .attr("Version", "2.0")
        .attr("IssueInstant", instant(now))
        .attr("Destination", destination)
        .attr_opt("InResponseTo", in_response_to)
        .child(issuer_el(idp_entity_id))
        .child(status_el(status.0, status.1, status.2))
        .child_opt(body)
}

/// A `samlp:LogoutRequest` to an SP.
pub fn logout_request(
    idp_entity_id: &str,
    destination: &str,
    name_id: &NameId,
    session_index: &str,
    now: DateTime<Utc>,
) -> El {
    El::new("samlp:LogoutRequest")
        .attr("xmlns:samlp", ns::PROTOCOL)
        .attr("xmlns:saml", ns::ASSERTION)
        .attr("ID", new_id())
        .attr("Version", "2.0")
        .attr("IssueInstant", instant(now))
        .attr("Destination", destination)
        .attr("NotOnOrAfter", instant(now + chrono::Duration::minutes(5)))
        .child(issuer_el(idp_entity_id))
        .child(
            El::new("saml:NameID")
                .attr_opt("Format", name_id.format.as_deref())
                .attr_opt("SPNameQualifier", name_id.sp_name_qualifier.as_deref())
                .text(&name_id.value),
        )
        .child(El::new("samlp:SessionIndex").text(session_index))
}

/// A `samlp:LogoutResponse` to an SP.
pub fn logout_response(
    idp_entity_id: &str,
    destination: &str,
    in_response_to: &str,
    status: (&str, Option<&str>),
    now: DateTime<Utc>,
) -> El {
    El::new("samlp:LogoutResponse")
        .attr("xmlns:samlp", ns::PROTOCOL)
        .attr("xmlns:saml", ns::ASSERTION)
        .attr("ID", new_id())
        .attr("Version", "2.0")
        .attr("IssueInstant", instant(now))
        .attr("Destination", destination)
        .attr("InResponseTo", in_response_to)
        .child(issuer_el(idp_entity_id))
        .child(status_el(status.0, status.1, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::saml::xml::parse;

    const REQ: &str = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2026-09-21T10:00:00.123Z" Destination="https://idp/sso" AssertionConsumerServiceURL="https://sp/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ForceAuthn="true">
  <saml:Issuer>https://sp.example</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
  <samlp:RequestedAuthnContext Comparison="minimum"><saml:AuthnContextClassRef>https://refeds.org/profile/mfa</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>
</samlp:AuthnRequest>"#;

    #[test]
    fn an_authn_request_is_read() {
        let doc = parse(REQ).unwrap();
        let r = parse_authn_request(&doc).unwrap();
        assert_eq!(r.id, "_r1");
        assert_eq!(r.issuer, "https://sp.example");
        assert_eq!(r.acs_url.as_deref(), Some("https://sp/acs"));
        assert!(r.force_authn && !r.is_passive);
        assert_eq!(r.name_id_format.as_deref(), Some(ns::nameid::EMAIL));
        let rac = r.requested_authn_context.unwrap();
        assert_eq!(rac.comparison, "minimum");
        assert_eq!(rac.class_refs, [ns::AC_REFEDS_MFA]);
        assert_eq!(instant(r.issue_instant), "2026-09-21T10:00:00Z");
    }

    #[test]
    fn malformed_requests_are_refused() {
        for (from, to) in [
            ("Version=\"2.0\"", "Version=\"1.1\""),
            ("ID=\"_r1\" ", ""),
            ("<saml:Issuer>https://sp.example</saml:Issuer>", ""),
            ("ForceAuthn=\"true\"", "ForceAuthn=\"yes\""),
            (
                "IssueInstant=\"2026-09-21T10:00:00.123Z\"",
                "IssueInstant=\"yesterday\"",
            ),
            (
                "AssertionConsumerServiceURL=\"https://sp/acs\"",
                "AssertionConsumerServiceURL=\"https://sp/acs\" AssertionConsumerServiceIndex=\"1\"",
            ),
        ] {
            let bad = REQ.replace(from, to);
            let doc = parse(&bad).unwrap();
            assert!(parse_authn_request(&doc).is_err(), "accepted with {to}");
        }
        let other = REQ.replace("samlp:AuthnRequest", "samlp:LogoutRequest");
        assert!(parse_authn_request(&parse(&other).unwrap()).is_err());
    }

    #[test]
    fn a_response_carries_what_the_sp_checks() {
        let attrs = [Attribute {
            name: "mail".into(),
            name_format: ns::ATTRNAME_BASIC,
            friendly_name: None,
            values: vec!["a@example.com".into(), "b<&>".into()],
        }];
        let now = Utc::now();
        let a = assertion(&AssertionContent {
            idp_entity_id: "https://idp",
            sp_entity_id: "https://sp.example",
            acs_url: "https://sp/acs",
            in_response_to: Some("_r1"),
            name_id: "abc",
            name_id_format: ns::nameid::PERSISTENT,
            sp_name_qualifier: Some("https://sp.example"),
            session_index: "_s1",
            authn_instant: now,
            authn_context: ns::AC_PASSWORD_PROTECTED,
            session_not_on_or_after: None,
            attributes: &attrs,
            now,
            lifetime: chrono::Duration::minutes(5),
        });
        let r = response(
            "https://idp",
            "https://sp/acs",
            Some("_r1"),
            now,
            (ns::status::SUCCESS, None, None),
            Some(a),
        )
        .to_string();
        let doc = parse(&r).unwrap();
        let root = doc.root_element();
        assert_eq!(root.attribute("InResponseTo"), Some("_r1"));
        let assertion = child(root, ns::ASSERTION, "Assertion").unwrap().unwrap();
        let values: Vec<String> = assertion
            .descendants()
            .filter(|n| is(*n, ns::ASSERTION, "AttributeValue"))
            .map(text_of)
            .collect();
        assert_eq!(values, ["a@example.com", "b<&>"]);
        let audience = assertion
            .descendants()
            .find(|n| is(*n, ns::ASSERTION, "Audience"))
            .unwrap();
        assert_eq!(text_of(audience), "https://sp.example");
    }

    #[test]
    fn logout_messages_round_trip() {
        let now = Utc::now();
        let nid = NameId {
            value: "abc".into(),
            format: Some(ns::nameid::PERSISTENT.into()),
            sp_name_qualifier: None,
        };
        let req = logout_request("https://idp", "https://sp/slo", &nid, "_s1", now).to_string();
        let doc = parse(&req).unwrap();
        let parsed = parse_logout_request(&doc).unwrap();
        assert_eq!(parsed.name_id, nid);
        assert_eq!(parsed.session_indexes, ["_s1"]);
        assert_eq!(parsed.issuer, "https://idp");

        let res = logout_response(
            "https://idp",
            "https://sp/slo",
            &parsed.id,
            (ns::status::SUCCESS, None),
            now,
        )
        .to_string();
        let doc = parse(&res).unwrap();
        let parsed_res = parse_logout_response(&doc).unwrap();
        assert_eq!(
            parsed_res.in_response_to.as_deref(),
            Some(parsed.id.as_str())
        );
        assert_eq!(parsed_res.status, ns::status::SUCCESS);
    }
}
