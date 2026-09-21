//! XML-DSig enveloped signatures, the one shape SAML uses: a `ds:Signature`
//! child of the signed element, one `Reference` to that element's `ID`,
//! the enveloped-signature and exclusive-C14N transforms.
//!
//! Verification accepts exactly that shape and nothing else. The reference
//! must name the element being verified, that `ID` must occur once in the
//! document, and the key comes from the caller's registered certificates,
//! never from the message's `KeyInfo`. Callers then use the verified element
//! itself, so a signature over some other part of the document (signature
//! wrapping) proves nothing about what they read.

use aws_lc_rs::digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use roxmltree::{Document, Node};

use super::c14n::canonicalize;
use super::cert::{Certificate, SignatureAlg};
use super::error::{SamlError, SamlResult};
use super::ns::{self, alg};
use super::xml::{self, El, base64_content, child, children, is, text_of};

/// The IdP's signing key and the certificate published for it.
pub struct Signer {
    key: RsaKeyPair,
    cert_b64: String,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer").finish_non_exhaustive()
    }
}

impl Signer {
    /// An RSA key (PKCS#8 DER) and its certificate (DER).
    pub fn new(pkcs8: &[u8], cert_der: &[u8]) -> SamlResult<Self> {
        let key = RsaKeyPair::from_pkcs8(pkcs8)
            .map_err(|e| SamlError::Crypto(format!("signing key: {e}")))?;
        Ok(Self {
            key,
            cert_b64: STANDARD.encode(cert_der),
        })
    }

    pub fn alg(&self) -> SignatureAlg {
        SignatureAlg::RsaSha256
    }

    /// RSA-SHA256 over `data`.
    pub fn sign(&self, data: &[u8]) -> SamlResult<Vec<u8>> {
        let mut sig = vec![0u8; self.key.public_modulus_len()];
        self.key
            .sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), data, &mut sig)
            .map_err(|_| SamlError::Crypto("signing failed".into()))?;
        Ok(sig)
    }

    /// Sign `el` (which must carry an `ID`), inserting the `ds:Signature`
    /// as its child at `position` — after the `Issuer`, where the SAML
    /// schema puts it.
    pub fn sign_enveloped(&self, el: &mut El, position: usize) -> SamlResult<()> {
        let id = el
            .attribute("ID")
            .ok_or_else(|| SamlError::Crypto("element to sign has no ID".into()))?
            .to_string();
        let serialized = el.to_string();
        let doc = xml::parse(&serialized)?;
        let digest = digest::digest(
            &digest::SHA256,
            canonicalize(doc.root_element(), None, &[]).as_bytes(),
        );

        let signed_info = |with_ns: bool| {
            El::new("ds:SignedInfo")
                .attr_opt("xmlns:ds", with_ns.then_some(ns::DSIG))
                .child(El::new("ds:CanonicalizationMethod").attr("Algorithm", alg::EXC_C14N))
                .child(El::new("ds:SignatureMethod").attr("Algorithm", alg::RSA_SHA256))
                .child(
                    El::new("ds:Reference")
                        .attr("URI", format!("#{id}"))
                        .child(
                            El::new("ds:Transforms")
                                .child(El::new("ds:Transform").attr("Algorithm", alg::ENVELOPED))
                                .child(El::new("ds:Transform").attr("Algorithm", alg::EXC_C14N)),
                        )
                        .child(El::new("ds:DigestMethod").attr("Algorithm", alg::SHA256))
                        .child(El::new("ds:DigestValue").text(STANDARD.encode(digest.as_ref()))),
                )
        };
        // Exclusive C14N renders `SignedInfo` the same standalone as inside
        // `ds:Signature`, so it is canonicalized on its own.
        let standalone = signed_info(true).to_string();
        let si_doc = xml::parse(&standalone)?;
        let sig = self.sign(canonicalize(si_doc.root_element(), None, &[]).as_bytes())?;

        let signature = El::new("ds:Signature")
            .attr("xmlns:ds", ns::DSIG)
            .child(signed_info(false))
            .child(El::new("ds:SignatureValue").text(STANDARD.encode(sig)))
            .child(
                El::new("ds:KeyInfo").child(
                    El::new("ds:X509Data")
                        .child(El::new("ds:X509Certificate").text(self.cert_b64.clone())),
                ),
            );
        el.insert(position, signature);
        Ok(())
    }
}

/// The `ds:Signature` child of `element`, if it has one (two are refused).
pub fn signature_of<'a, 'i>(element: Node<'a, 'i>) -> SamlResult<Option<Node<'a, 'i>>> {
    child(element, ns::DSIG, "Signature")
}

fn one<'a, 'i>(node: Node<'a, 'i>, local: &'static str) -> SamlResult<Node<'a, 'i>> {
    child(node, ns::DSIG, local)?.ok_or_else(|| SamlError::signature(format!("{local} is missing")))
}

fn algorithm<'a>(node: Node<'a, '_>) -> SamlResult<&'a str> {
    node.attribute("Algorithm")
        .ok_or_else(|| SamlError::signature("an Algorithm attribute is missing"))
}

/// The `InclusiveNamespaces PrefixList` of an exclusive-C14N method.
fn prefix_list(method: Node) -> Vec<String> {
    method
        .children()
        .find(|c| c.is_element() && c.tag_name().name() == "InclusiveNamespaces")
        .and_then(|n| n.attribute("PrefixList"))
        .map(|l| l.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Verify the enveloped signature on `element` against one of `certs`.
/// A missing signature is an error; callers that allow unsigned messages
/// check [`signature_of`] first.
pub fn verify_enveloped(doc: &Document, element: Node, certs: &[Certificate]) -> SamlResult<()> {
    if certs.is_empty() {
        return Err(SamlError::signature(
            "no certificate is registered to verify with",
        ));
    }
    let signature = signature_of(element)?.ok_or_else(|| SamlError::signature("not signed"))?;
    let signed_info = one(signature, "SignedInfo")?;

    let c14n_method = one(signed_info, "CanonicalizationMethod")?;
    if algorithm(c14n_method)? != alg::EXC_C14N {
        return Err(SamlError::signature(
            "only exclusive canonicalization without comments is accepted",
        ));
    }
    let si_prefixes = prefix_list(c14n_method);
    let sig_alg = SignatureAlg::from_uri(algorithm(one(signed_info, "SignatureMethod")?)?)?;

    let mut references = children(signed_info, ns::DSIG, "Reference");
    let reference = references
        .next()
        .ok_or_else(|| SamlError::signature("Reference is missing"))?;
    if references.next().is_some() {
        return Err(SamlError::signature("exactly one Reference is accepted"));
    }

    // The reference must be to this very element, by an ID nothing else has.
    let id = element
        .attribute("ID")
        .ok_or_else(|| SamlError::signature("the signed element has no ID"))?;
    if reference.attribute("URI") != Some(format!("#{id}").as_str()) {
        return Err(SamlError::signature(
            "the signature does not reference this element",
        ));
    }
    let with_id = xml::elements_with_id(doc, id);
    if with_id.len() != 1 || with_id[0].id() != element.id() {
        return Err(SamlError::signature(
            "the signed ID is not unique in the document",
        ));
    }

    let mut ref_prefixes = vec![];
    if let Some(transforms) = child(reference, ns::DSIG, "Transforms")? {
        let mut saw_c14n = false;
        for t in children(transforms, ns::DSIG, "Transform") {
            match algorithm(t)? {
                alg::ENVELOPED => {}
                alg::EXC_C14N if !saw_c14n => {
                    saw_c14n = true;
                    ref_prefixes = prefix_list(t);
                }
                _ => return Err(SamlError::signature("unsupported transform")),
            }
        }
        if transforms
            .children()
            .any(|c| c.is_element() && !is(c, ns::DSIG, "Transform"))
        {
            return Err(SamlError::signature("unexpected element in Transforms"));
        }
    }
    let digest_alg = match algorithm(one(reference, "DigestMethod")?)? {
        alg::SHA256 => &digest::SHA256,
        alg::SHA384 => &digest::SHA384,
        alg::SHA512 => &digest::SHA512,
        alg::SHA1 => return Err(SamlError::signature("SHA-1 digests are not accepted")),
        _ => return Err(SamlError::signature("unsupported digest algorithm")),
    };
    let expected = base64_content(&text_of(one(reference, "DigestValue")?))?;
    let canonical = canonicalize(element, Some(signature.id()), &ref_prefixes);
    let actual = digest::digest(digest_alg, canonical.as_bytes());
    if actual.as_ref() != expected.as_slice() {
        return Err(SamlError::signature(
            "digest mismatch: the element was altered",
        ));
    }

    let sig = base64_content(&text_of(one(signature, "SignatureValue")?))?;
    let signed = canonicalize(signed_info, None, &si_prefixes);
    if certs
        .iter()
        .any(|c| c.verify(sig_alg, signed.as_bytes(), &sig))
    {
        Ok(())
    } else {
        Err(SamlError::signature(
            "the signature does not verify with a registered certificate",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::saml::testkit::{other_rsa_cert, rsa_cert, rsa_pkcs8};

    fn signer() -> Signer {
        Signer::new(&rsa_pkcs8(), &rsa_cert().der).unwrap()
    }

    fn signed_request() -> String {
        let mut el = El::new("samlp:AuthnRequest")
            .attr("xmlns:samlp", ns::PROTOCOL)
            .attr("xmlns:saml", ns::ASSERTION)
            .attr("ID", "_abc")
            .attr("Version", "2.0")
            .child(El::new("saml:Issuer").text("https://sp.example"))
            .child(El::new("samlp:NameIDPolicy").attr("AllowCreate", "true"));
        signer().sign_enveloped(&mut el, 1).unwrap();
        el.to_document()
    }

    fn verify(xml: &str) -> SamlResult<()> {
        let doc = xml::parse(xml)?;
        verify_enveloped(&doc, doc.root_element(), &[rsa_cert()])
    }

    #[test]
    fn a_signature_round_trips() {
        let xml = signed_request();
        verify(&xml).unwrap();
        // Signature position: right after the Issuer.
        let doc = xml::parse(&xml).unwrap();
        let names: Vec<&str> = doc
            .root_element()
            .children()
            .filter(|c| c.is_element())
            .map(|c| c.tag_name().name())
            .collect();
        assert_eq!(names, ["Issuer", "Signature", "NameIDPolicy"]);
    }

    #[test]
    fn a_signature_survives_being_moved_into_another_document() {
        // Exclusive C14N: the element's canonical form ignores the context.
        let xml = signed_request();
        let inner = xml.trim_start_matches("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        let wrapped = format!(r#"<outer xmlns="urn:other" xmlns:x="urn:x">{inner}</outer>"#);
        let doc = xml::parse(&wrapped).unwrap();
        let el = doc.root_element().first_element_child().unwrap();
        verify_enveloped(&doc, el, &[rsa_cert()]).unwrap();
    }

    #[test]
    fn any_change_breaks_the_signature() {
        let xml = signed_request();
        let altered = xml.replace("https://sp.example", "https://evil.example");
        assert!(matches!(verify(&altered), Err(SamlError::Signature(_))));
        let altered = xml.replace("AllowCreate=\"true\"", "AllowCreate=\"false\"");
        assert!(verify(&altered).is_err());
    }

    #[test]
    fn only_registered_keys_count() {
        let xml = signed_request();
        let doc = xml::parse(&xml).unwrap();
        let err = verify_enveloped(&doc, doc.root_element(), &[other_rsa_cert()]).unwrap_err();
        assert!(err.to_string().contains("registered certificate"), "{err}");
        assert!(verify_enveloped(&doc, doc.root_element(), &[]).is_err());
        // Several registered: any of them may have signed (key rollover).
        verify_enveloped(&doc, doc.root_element(), &[other_rsa_cert(), rsa_cert()]).unwrap();
    }

    #[test]
    fn an_unsigned_element_is_refused() {
        let xml = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="{}" ID="_x"/>"#,
            ns::PROTOCOL
        );
        assert!(verify(&xml).is_err());
    }

    #[test]
    fn a_signature_referencing_another_element_is_refused() {
        // Signature wrapping: a genuinely signed element is moved aside and
        // the root carries its signature under a new ID.
        let xml = signed_request();
        let doc = xml::parse(&xml).unwrap();
        let sig = signature_of(doc.root_element()).unwrap().unwrap();
        let sig_xml = &xml[sig.range()];
        let forged = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="{}" xmlns:saml="{}" ID="_evil" Version="2.0"><saml:Issuer>https://evil.example</saml:Issuer>{sig_xml}</samlp:AuthnRequest>"#,
            ns::PROTOCOL,
            ns::ASSERTION
        );
        let err = verify(&forged).unwrap_err();
        assert!(err.to_string().contains("reference"), "{err}");

        // Same ID twice: the forged root and the original tucked inside.
        let inner = xml.trim_start_matches("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        let forged = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="{}" xmlns:saml="{}" ID="_abc" Version="2.0"><saml:Issuer>https://evil.example</saml:Issuer>{sig_xml}<samlp:Extensions>{inner}</samlp:Extensions></samlp:AuthnRequest>"#,
            ns::PROTOCOL,
            ns::ASSERTION
        );
        let err = verify(&forged).unwrap_err();
        assert!(err.to_string().contains("unique"), "{err}");
    }

    #[test]
    fn weak_or_unknown_algorithms_are_refused() {
        let xml = signed_request();
        let sha1_digest = xml.replace(alg::SHA256, alg::SHA1);
        assert!(
            verify(&sha1_digest)
                .unwrap_err()
                .to_string()
                .contains("SHA-1")
        );
        let sha1_sig = xml.replace(alg::RSA_SHA256, alg::RSA_SHA1);
        assert!(verify(&sha1_sig).unwrap_err().to_string().contains("SHA-1"));
        let with_comments = xml.replacen(
            &format!("Algorithm=\"{}\"", alg::EXC_C14N),
            &format!("Algorithm=\"{}\"", alg::EXC_C14N_WITH_COMMENTS),
            1,
        );
        assert!(verify(&with_comments).is_err());
        let xslt = xml.replace(
            alg::ENVELOPED,
            "http://www.w3.org/TR/1999/REC-xslt-19991116",
        );
        assert!(verify(&xslt).unwrap_err().to_string().contains("transform"));
    }

    #[test]
    fn xmlsec1_verifies_our_signatures_and_we_verify_its() {
        use crate::saml::testkit::{rsa_key_pem, scratch, xmlsec1, xmlsec1_lax};
        let Some(tool) = xmlsec1() else {
            eprintln!("xmlsec1 not installed; interop not checked");
            return;
        };
        let dir = scratch("dsig");
        let cert = dir.join("cert.pem");
        std::fs::write(&cert, rsa_cert().to_pem()).unwrap();
        let id_node = format!("{}:AuthnRequest", ns::PROTOCOL);

        // Ours, checked by xmlsec1. Put it inside another element first, so
        // exclusive canonicalization is exercised on both sides.
        let signed = signed_request();
        let inner = signed.trim_start_matches("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        let wrapped = format!(r#"<outer xmlns="urn:o" xmlns:x="urn:x">{inner}</outer>"#);
        let ours = dir.join("ours.xml");
        std::fs::write(&ours, &wrapped).unwrap();
        let out = std::process::Command::new(&tool)
            .arg("--verify")
            .args(xmlsec1_lax())
            .arg("--pubkey-cert-pem")
            .arg(&cert)
            .arg("--id-attr:ID")
            .arg(&id_node)
            .arg(&ours)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "xmlsec1 rejected our signature in {}: {}",
            ours.display(),
            String::from_utf8_lossy(&out.stderr)
        );

        // xmlsec1's, from a template, checked by us.
        let template = format!(
            r##"<samlp:AuthnRequest xmlns:samlp="{p}" xmlns:saml="{a}" ID="_t1" Version="2.0">
  <saml:Issuer>https://sp.example</saml:Issuer>
  <ds:Signature xmlns:ds="{d}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{c}"/><ds:SignatureMethod Algorithm="{s}"/><ds:Reference URI="#_t1"><ds:Transforms><ds:Transform Algorithm="{e}"/><ds:Transform Algorithm="{c}"/></ds:Transforms><ds:DigestMethod Algorithm="{h}"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature>
  <!-- a comment, which exclusive c14n drops -->
  <samlp:NameIDPolicy AllowCreate="true" Format="urn:x"/>
</samlp:AuthnRequest>"##,
            p = ns::PROTOCOL,
            a = ns::ASSERTION,
            d = ns::DSIG,
            c = alg::EXC_C14N,
            s = alg::RSA_SHA256,
            e = alg::ENVELOPED,
            h = alg::SHA256,
        );
        let tmpl = dir.join("template.xml");
        let key = dir.join("key.pem");
        std::fs::write(&tmpl, template).unwrap();
        std::fs::write(&key, rsa_key_pem()).unwrap();
        let out = std::process::Command::new(&tool)
            .arg("--sign")
            .args(xmlsec1_lax())
            .arg("--privkey-pem")
            .arg(&key)
            .arg("--id-attr:ID")
            .arg(&id_node)
            .arg(&tmpl)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let theirs = String::from_utf8(out.stdout).unwrap();
        verify(&theirs).unwrap();
        let altered = theirs.replace("AllowCreate=\"true\"", "AllowCreate=\"false\"");
        assert!(verify(&altered).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
