//! The deployment's RFC 9116 `security.txt`.
//!
//! The document names whoever answers for *this* deployment's security, which
//! is its operator, not the rIDM project: a researcher who finds a hole in
//! `id.acme.example` must reach Acme. So nothing is served until the operator
//! configures it, either as a whole document (`SECURITY_TXT` or
//! `SECURITY_TXT_FILE`, which may be OpenPGP-signed and is served byte for
//! byte) or as contacts the server writes the document around
//! (`SECURITY_CONTACT`, `SECURITY_POLICY_URL`).

use chrono::{DateTime, Duration, NaiveTime, Utc};
use url::Url;

/// How far ahead a generated document's `Expires` lies. The contacts come from
/// the running configuration, so the document is as fresh as the process; a
/// short rolling window still keeps a copy scraped today from being trusted
/// for long.
const GENERATED_VALIDITY_DAYS: i64 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityTxt {
    /// Written by the operator and served as is.
    Document(String),
    /// Built per request from the configured contacts.
    Generated {
        contacts: Vec<String>,
        policy: Option<Url>,
    },
}

impl SecurityTxt {
    /// The configuration, from the three settings' values. `Ok(None)` when
    /// none is set. A document wins over contacts; giving both is refused so
    /// that an operator never edits contacts that are not being served.
    pub fn from_settings(
        document: Option<String>,
        contacts: Option<String>,
        policy: Option<String>,
    ) -> Result<Option<Self>, (&'static str, String)> {
        if let Some(doc) = document {
            if contacts.is_some() || policy.is_some() {
                return Err((
                    "SECURITY_TXT",
                    "set either SECURITY_TXT (or SECURITY_TXT_FILE) or SECURITY_CONTACT \
                     and SECURITY_POLICY_URL, not both"
                        .into(),
                ));
            }
            return validate_document(doc)
                .map(|d| Some(Self::Document(d)))
                .map_err(|e| ("SECURITY_TXT", e));
        }
        let policy = policy
            .map(|p| {
                Url::parse(&p)
                    .map_err(|e| e.to_string())
                    .and_then(|u| {
                        (u.scheme() == "https")
                            .then_some(u)
                            .ok_or_else(|| "must be an https URL".to_string())
                    })
                    .map_err(|e| ("SECURITY_POLICY_URL", e))
            })
            .transpose()?;
        let Some(contacts) = contacts else {
            return match policy {
                Some(_) => Err((
                    "SECURITY_POLICY_URL",
                    "needs SECURITY_CONTACT: a security.txt must name a contact".into(),
                )),
                None => Ok(None),
            };
        };
        let contacts = contacts
            .split(',')
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(validate_contact)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ("SECURITY_CONTACT", e))?;
        if contacts.is_empty() {
            return Err(("SECURITY_CONTACT", "names no contact".into()));
        }
        Ok(Some(Self::Generated { contacts, policy }))
    }

    /// The document as served at `now`.
    pub fn render(&self, now: DateTime<Utc>) -> String {
        match self {
            Self::Document(doc) => doc.clone(),
            Self::Generated { contacts, policy } => {
                let expires = (now + Duration::days(GENERATED_VALIDITY_DAYS))
                    .date_naive()
                    .and_time(NaiveTime::MIN)
                    .and_utc();
                let mut out = String::new();
                for c in contacts {
                    out.push_str(&format!("Contact: {c}\n"));
                }
                out.push_str(&format!(
                    "Expires: {}\n",
                    expires.format("%Y-%m-%dT%H:%M:%S%.3fZ")
                ));
                if let Some(p) = policy {
                    out.push_str(&format!("Policy: {p}\n"));
                }
                out
            }
        }
    }

    /// The `Expires` of an operator's document, for the start-up warning
    /// when it has passed. A generated one never has.
    pub fn document_expires(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::Document(doc) => field_values(doc, "expires")
                .next()
                .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                .map(|d| d.with_timezone(&Utc)),
            Self::Generated { .. } => None,
        }
    }
}

/// RFC 9116 §2.5.3: a contact is a URI, `mailto:`, `tel:` or `https:`.
fn validate_contact(c: &str) -> Result<String, String> {
    let url = Url::parse(c).map_err(|e| format!("`{c}`: {e}"))?;
    if !matches!(url.scheme(), "mailto" | "tel" | "https") {
        return Err(format!(
            "`{c}`: a contact must be a mailto:, tel: or https: URI"
        ));
    }
    Ok(url.to_string())
}

/// The two fields RFC 9116 requires: at least one `Contact`, exactly one
/// `Expires` in RFC 3339 form. Anything else is the operator's business.
fn validate_document(doc: String) -> Result<String, String> {
    if field_values(&doc, "contact").next().is_none() {
        return Err("the document has no Contact field".into());
    }
    let expires: Vec<&str> = field_values(&doc, "expires").collect();
    match expires.as_slice() {
        [one] => {
            DateTime::parse_from_rfc3339(one)
                .map_err(|e| format!("Expires `{one}` is not an RFC 3339 date-time: {e}"))?;
        }
        [] => return Err("the document has no Expires field".into()),
        _ => return Err("the document has more than one Expires field".into()),
    }
    // Served as a text file: end it with a line break however it was given.
    Ok(if doc.ends_with('\n') {
        doc
    } else {
        format!("{doc}\n")
    })
}

/// Values of field `name` (lower-case), matched case-insensitively as the RFC
/// requires. A signed document's fields sit at the start of their lines too.
fn field_values<'a>(doc: &'a str, name: &'a str) -> impl Iterator<Item = &'a str> {
    doc.lines().filter_map(move |line| {
        let (field, value) = line.split_once(':')?;
        field
            .trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn nothing_configured_serves_nothing() {
        assert_eq!(SecurityTxt::from_settings(None, None, None), Ok(None));
    }

    #[test]
    fn contacts_are_written_into_a_document_with_a_rolling_expiry() {
        let txt = SecurityTxt::from_settings(
            None,
            Some("mailto:security@acme.example, https://acme.example/security".into()),
            Some("https://acme.example/disclosure".into()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            txt.render(at("2026-09-19T15:30:00Z")),
            "Contact: mailto:security@acme.example\n\
             Contact: https://acme.example/security\n\
             Expires: 2026-10-19T00:00:00.000Z\n\
             Policy: https://acme.example/disclosure\n"
        );
        assert_eq!(txt.document_expires(), None);
    }

    #[test]
    fn contacts_must_be_mailto_tel_or_https() {
        for bad in [
            "http://acme.example/security",
            "security@acme.example",
            "ftp://x",
        ] {
            assert_eq!(
                SecurityTxt::from_settings(None, Some(bad.into()), None)
                    .unwrap_err()
                    .0,
                "SECURITY_CONTACT",
                "{bad}"
            );
        }
        assert!(SecurityTxt::from_settings(None, Some("tel:+1-201-555-0123".into()), None).is_ok());
        assert!(SecurityTxt::from_settings(None, Some(" , ".into()), None).is_err());
    }

    #[test]
    fn a_policy_alone_is_refused() {
        let err = SecurityTxt::from_settings(None, None, Some("https://acme.example/p".into()))
            .unwrap_err();
        assert_eq!(err.0, "SECURITY_POLICY_URL");
        let err = SecurityTxt::from_settings(
            None,
            Some("mailto:s@acme.example".into()),
            Some("http://acme.example/p".into()),
        )
        .unwrap_err();
        assert_eq!(err.0, "SECURITY_POLICY_URL");
    }

    #[test]
    fn a_document_is_served_as_written() {
        let doc = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n\
                   contact: mailto:security@acme.example\n\
                   EXPIRES: 2027-01-01T00:00:00.000Z\n\
                   -----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----";
        let txt = SecurityTxt::from_settings(Some(doc.into()), None, None)
            .unwrap()
            .unwrap();
        assert_eq!(txt.render(Utc::now()), format!("{doc}\n"));
        assert_eq!(txt.document_expires(), Some(at("2027-01-01T00:00:00Z")));
    }

    #[test]
    fn a_document_needs_one_contact_and_one_valid_expiry() {
        let refused = |doc: &str| SecurityTxt::from_settings(Some(doc.into()), None, None).is_err();
        assert!(refused("Expires: 2027-01-01T00:00:00Z\n"));
        assert!(refused("Contact: mailto:s@acme.example\n"));
        assert!(refused(
            "Contact: mailto:s@acme.example\nExpires: next year\n"
        ));
        assert!(refused(
            "Contact: mailto:s@acme.example\nExpires: 2027-01-01T00:00:00Z\nExpires: 2028-01-01T00:00:00Z\n"
        ));
    }

    #[test]
    fn a_document_and_contacts_together_are_refused() {
        let err = SecurityTxt::from_settings(
            Some("Contact: mailto:s@acme.example\nExpires: 2027-01-01T00:00:00Z\n".into()),
            Some("mailto:other@acme.example".into()),
            None,
        )
        .unwrap_err();
        assert_eq!(err.0, "SECURITY_TXT");
    }
}
