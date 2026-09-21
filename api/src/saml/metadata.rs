//! SAML metadata (SAML Metadata §2): the IdP's own `EntityDescriptor`, and
//! reading an SP's to prefill its registration.

use super::cert::Certificate;
use super::error::{SamlError, SamlResult};
use super::ns;
use super::xml::{self, El, children, is, text_of};

/// Where the IdP's endpoints are and what it signs with.
pub struct IdpMetadata<'a> {
    pub entity_id: &'a str,
    pub sso_url: &'a str,
    pub slo_url: &'a str,
    /// Every published signing certificate (active, pending, retiring).
    pub certificates: &'a [Certificate],
    pub name_id_formats: &'a [&'a str],
}

/// The IdP's metadata document.
pub fn idp_metadata(m: &IdpMetadata) -> String {
    let mut idp = El::new("md:IDPSSODescriptor")
        .attr("protocolSupportEnumeration", ns::PROTOCOL)
        .attr("WantAuthnRequestsSigned", "false");
    for cert in m.certificates {
        idp = idp.child(El::new("md:KeyDescriptor").attr("use", "signing").child(
            El::new("ds:KeyInfo").child(
                El::new("ds:X509Data").child(El::new("ds:X509Certificate").text(cert.to_base64())),
            ),
        ));
    }
    for binding in [ns::BINDING_REDIRECT, ns::BINDING_POST] {
        idp = idp.child(
            El::new("md:SingleLogoutService")
                .attr("Binding", binding)
                .attr("Location", m.slo_url),
        );
    }
    for f in m.name_id_formats {
        idp = idp.child(El::new("md:NameIDFormat").text(*f));
    }
    for binding in [ns::BINDING_REDIRECT, ns::BINDING_POST] {
        idp = idp.child(
            El::new("md:SingleSignOnService")
                .attr("Binding", binding)
                .attr("Location", m.sso_url),
        );
    }
    El::new("md:EntityDescriptor")
        .attr("xmlns:md", ns::METADATA)
        .attr("xmlns:ds", ns::DSIG)
        .attr("entityID", m.entity_id)
        .child(idp)
        .to_document()
}

/// What an SP's metadata says, as far as registration uses it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpMetadata {
    pub entity_id: String,
    /// HTTP-POST consumer services, the default first, then by index.
    pub acs_urls: Vec<String>,
    /// The single logout service, preferring the Redirect binding.
    pub slo: Option<(String, bool)>,
    /// base64 DER certificates for signatures (and for both uses when a
    /// `KeyDescriptor` has no `use`).
    pub signing_certificates: Vec<String>,
    pub encryption_certificate: Option<String>,
    pub name_id_formats: Vec<String>,
    pub authn_requests_signed: bool,
}

/// Read an SP's `EntityDescriptor` (or an `EntitiesDescriptor` holding
/// exactly one SP).
pub fn parse_sp_metadata(text: &str) -> SamlResult<SpMetadata> {
    let doc = xml::parse(text)?;
    let root = doc.root_element();
    let entity = if is(root, ns::METADATA, "EntityDescriptor") {
        root
    } else if is(root, ns::METADATA, "EntitiesDescriptor") {
        let mut sps = root.descendants().filter(|n| {
            is(*n, ns::METADATA, "EntityDescriptor")
                && children(*n, ns::METADATA, "SPSSODescriptor")
                    .next()
                    .is_some()
        });
        let one = sps
            .next()
            .ok_or_else(|| SamlError::malformed("the metadata describes no service provider"))?;
        if sps.next().is_some() {
            return Err(SamlError::malformed(
                "the metadata describes several service providers; import one EntityDescriptor",
            ));
        }
        one
    } else {
        return Err(SamlError::malformed("not SAML metadata"));
    };
    let entity_id = entity
        .attribute("entityID")
        .filter(|e| !e.trim().is_empty())
        .ok_or_else(|| SamlError::malformed("entityID is missing"))?
        .trim()
        .to_string();
    let sp = xml::child(entity, ns::METADATA, "SPSSODescriptor")?
        .ok_or_else(|| SamlError::malformed("the entity is not a service provider"))?;
    if !sp
        .attribute("protocolSupportEnumeration")
        .unwrap_or_default()
        .split_whitespace()
        .any(|p| p == ns::PROTOCOL)
    {
        return Err(SamlError::malformed(
            "the service provider does not speak SAML 2.0",
        ));
    }

    let mut acs: Vec<(bool, u32, String)> = children(sp, ns::METADATA, "AssertionConsumerService")
        .filter(|a| a.attribute("Binding") == Some(ns::BINDING_POST))
        .filter_map(|a| {
            let url = a.attribute("Location")?.trim().to_string();
            let index = a
                .attribute("index")
                .and_then(|i| i.parse().ok())
                .unwrap_or(u32::MAX);
            let default = a.attribute("isDefault") == Some("true");
            Some((!default, index, url))
        })
        .collect();
    acs.sort();
    let acs_urls: Vec<String> = acs.into_iter().map(|(_, _, u)| u).collect();
    if acs_urls.is_empty() {
        return Err(SamlError::malformed(
            "the service provider has no HTTP-POST assertion consumer service",
        ));
    }

    let slo_services: Vec<(String, bool)> = children(sp, ns::METADATA, "SingleLogoutService")
        .filter_map(|s| {
            let url = s.attribute("Location")?.trim().to_string();
            match s.attribute("Binding")? {
                ns::BINDING_REDIRECT => Some((url, true)),
                ns::BINDING_POST => Some((url, false)),
                _ => None,
            }
        })
        .collect();
    let slo = slo_services
        .iter()
        .find(|(_, redirect)| *redirect)
        .or_else(|| slo_services.first())
        .cloned();

    let mut signing_certificates = vec![];
    let mut encryption_certificate = None;
    for kd in children(sp, ns::METADATA, "KeyDescriptor") {
        let Some(cert) = kd
            .descendants()
            .find(|n| is(*n, ns::DSIG, "X509Certificate"))
            .map(text_of)
        else {
            continue;
        };
        let cert = Certificate::parse(&cert)?.to_base64();
        match kd.attribute("use") {
            Some("signing") => signing_certificates.push(cert),
            Some("encryption") => {
                encryption_certificate.get_or_insert(cert);
            }
            None => {
                signing_certificates.push(cert.clone());
                encryption_certificate.get_or_insert(cert);
            }
            Some(_) => {}
        }
    }
    signing_certificates.dedup();

    Ok(SpMetadata {
        entity_id,
        acs_urls,
        slo,
        signing_certificates,
        encryption_certificate,
        name_id_formats: children(sp, ns::METADATA, "NameIDFormat")
            .map(text_of)
            .collect(),
        authn_requests_signed: sp.attribute("AuthnRequestsSigned") == Some("true"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::saml::testkit::{other_rsa_cert, rsa_cert};

    #[test]
    fn idp_metadata_lists_endpoints_and_keys() {
        let certs = [rsa_cert(), other_rsa_cert()];
        let xml = idp_metadata(&IdpMetadata {
            entity_id: "https://idp/t/acme",
            sso_url: "https://idp/t/acme/saml/sso",
            slo_url: "https://idp/t/acme/saml/slo",
            certificates: &certs,
            name_id_formats: &[ns::nameid::PERSISTENT],
        });
        let doc = xml::parse(&xml).unwrap();
        let root = doc.root_element();
        assert_eq!(root.attribute("entityID"), Some("https://idp/t/acme"));
        let keys = root
            .descendants()
            .filter(|n| is(*n, ns::METADATA, "KeyDescriptor"))
            .count();
        assert_eq!(keys, 2);
        // Schema order: keys, logout, formats, then sign-on.
        let names: Vec<&str> = root
            .first_element_child()
            .unwrap()
            .children()
            .filter(|c| c.is_element())
            .map(|c| c.tag_name().name())
            .collect();
        assert_eq!(
            names,
            [
                "KeyDescriptor",
                "KeyDescriptor",
                "SingleLogoutService",
                "SingleLogoutService",
                "NameIDFormat",
                "SingleSignOnService",
                "SingleSignOnService"
            ]
        );
    }

    fn sp_metadata(extra: &str) -> String {
        format!(
            r#"<md:EntityDescriptor xmlns:md="{md}" xmlns:ds="{ds}" entityID=" https://sp.example ">
  <md:SPSSODescriptor protocolSupportEnumeration="{p}" AuthnRequestsSigned="true">
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>
{sign}
    </ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{enc}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleLogoutService Binding="{post}" Location="https://sp.example/slo-post"/>
    <md:SingleLogoutService Binding="{redirect}" Location="https://sp.example/slo"/>
    <md:NameIDFormat>{email}</md:NameIDFormat>
    <md:AssertionConsumerService Binding="{post}" Location="https://sp.example/acs1" index="1"/>
    <md:AssertionConsumerService Binding="{redirect}" Location="https://sp.example/nope" index="0"/>
    <md:AssertionConsumerService Binding="{post}" Location="https://sp.example/acs2" index="2" isDefault="true"/>
    {extra}
  </md:SPSSODescriptor>
</md:EntityDescriptor>"#,
            md = ns::METADATA,
            ds = ns::DSIG,
            p = ns::PROTOCOL,
            sign = rsa_cert().to_base64(),
            enc = other_rsa_cert().to_base64(),
            post = ns::BINDING_POST,
            redirect = ns::BINDING_REDIRECT,
            email = ns::nameid::EMAIL,
        )
    }

    #[test]
    fn sp_metadata_is_read() {
        let m = parse_sp_metadata(&sp_metadata("")).unwrap();
        assert_eq!(m.entity_id, "https://sp.example");
        assert_eq!(
            m.acs_urls,
            ["https://sp.example/acs2", "https://sp.example/acs1"]
        );
        assert_eq!(m.slo, Some(("https://sp.example/slo".into(), true)));
        assert_eq!(m.signing_certificates, [rsa_cert().to_base64()]);
        assert_eq!(m.encryption_certificate, Some(other_rsa_cert().to_base64()));
        assert_eq!(m.name_id_formats, [ns::nameid::EMAIL]);
        assert!(m.authn_requests_signed);
    }

    #[test]
    fn bad_sp_metadata_is_refused() {
        let broken = sp_metadata("").replace(&rsa_cert().to_base64(), "AAAA");
        assert!(parse_sp_metadata(&broken).is_err());
        let two = format!(
            r#"<md:EntitiesDescriptor xmlns:md="{}">{}{}</md:EntitiesDescriptor>"#,
            ns::METADATA,
            sp_metadata(""),
            sp_metadata("")
        );
        assert!(
            parse_sp_metadata(&two)
                .unwrap_err()
                .to_string()
                .contains("several")
        );
        let one = format!(
            r#"<md:EntitiesDescriptor xmlns:md="{}">{}</md:EntitiesDescriptor>"#,
            ns::METADATA,
            sp_metadata("")
        );
        assert_eq!(
            parse_sp_metadata(&one).unwrap().entity_id,
            "https://sp.example"
        );
        assert!(parse_sp_metadata("<html/>").is_err());
    }
}
