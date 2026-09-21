//! Exclusive XML Canonicalization 1.0, without comments
//! (<https://www.w3.org/TR/xml-exc-c14n/>): the byte form an XML signature's
//! digest and signature are computed over.
//!
//! It renders one element and its descendants: comments dropped, attributes
//! sorted by namespace URI then local name, and only the namespace
//! declarations the output actually uses ("visibly utilized"), each once,
//! where it is first needed. That makes a signed element's bytes independent
//! of the document it sits in, which is why SAML signs with it.

use std::collections::BTreeMap;

use roxmltree::{Node, NodeId, NodeType};

use super::xml::{attribute_qname, element_prefix, element_qname, escape_attr, escape_text};

/// Canonical form of `node`. `exclude` is a descendant left out entirely
/// (the enveloped signature); `inclusive` is the `InclusiveNamespaces`
/// `PrefixList`, whose prefixes are rendered the inclusive way
/// (`#default` names the default namespace).
pub fn canonicalize(node: Node, exclude: Option<NodeId>, inclusive: &[String]) -> String {
    let mut out = String::new();
    let rendered = BTreeMap::new();
    render(node, exclude, inclusive, &rendered, &mut out);
    out
}

fn render(
    node: Node,
    exclude: Option<NodeId>,
    inclusive: &[String],
    rendered: &BTreeMap<String, String>,
    out: &mut String,
) {
    if Some(node.id()) == exclude {
        return;
    }
    match node.node_type() {
        NodeType::Element => {}
        NodeType::Text => {
            out.push_str(&escape_text(node.text().unwrap_or_default()));
            return;
        }
        NodeType::PI => {
            if let Some(pi) = node.pi() {
                out.push_str("<?");
                out.push_str(pi.target);
                if let Some(v) = pi.value {
                    out.push(' ');
                    out.push_str(v);
                }
                out.push_str("?>");
            }
            return;
        }
        NodeType::Comment | NodeType::Root => return,
    }

    // Namespaces this element visibly uses: its own prefix (the default
    // namespace when unprefixed) and those of its prefixed attributes.
    let mut used: BTreeMap<String, String> = BTreeMap::new();
    match element_prefix(node) {
        Some(p) => {
            used.insert(
                p.to_string(),
                node.lookup_namespace_uri(Some(p))
                    .unwrap_or_default()
                    .to_string(),
            );
        }
        None => {
            used.insert(
                String::new(),
                node.tag_name().namespace().unwrap_or_default().to_string(),
            );
        }
    }
    for attr in node.attributes() {
        let qname = attribute_qname(node, &attr);
        if let Some((p, _)) = qname.split_once(':')
            && p != "xml"
        {
            used.insert(
                p.to_string(),
                attr.namespace().unwrap_or_default().to_string(),
            );
        }
    }
    for p in inclusive {
        if p == "#default" {
            if let Some(uri) = node.default_namespace() {
                used.entry(String::new()).or_insert_with(|| uri.to_string());
            }
        } else if let Some(uri) = node.lookup_namespace_uri(Some(p.as_str())) {
            used.entry(p.clone()).or_insert_with(|| uri.to_string());
        }
    }

    let mut scope = rendered.clone();
    let mut decls: Vec<(String, String)> = vec![];
    for (prefix, uri) in used {
        let current = rendered.get(&prefix).map(String::as_str);
        let needed = if prefix.is_empty() {
            // `xmlns=""` only undoes a non-empty default rendered above.
            current.unwrap_or_default() != uri
        } else {
            current != Some(uri.as_str())
        };
        if needed {
            scope.insert(prefix.clone(), uri.clone());
            decls.push((prefix, uri));
        }
    }

    let mut attrs: Vec<(&str, &str, &str, &str)> = node
        .attributes()
        .map(|a| {
            (
                a.namespace().unwrap_or_default(),
                a.name(),
                attribute_qname(node, &a),
                a.value(),
            )
        })
        .collect();
    attrs.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));

    let qname = element_qname(node);
    out.push('<');
    out.push_str(qname);
    for (prefix, uri) in &decls {
        if prefix.is_empty() {
            out.push_str(" xmlns=\"");
        } else {
            out.push_str(" xmlns:");
            out.push_str(prefix);
            out.push_str("=\"");
        }
        out.push_str(&escape_attr(uri));
        out.push('"');
    }
    for (_, _, q, v) in attrs {
        out.push(' ');
        out.push_str(q);
        out.push_str("=\"");
        out.push_str(&escape_attr(v));
        out.push('"');
    }
    out.push('>');
    for child in node.children() {
        render(child, exclude, inclusive, &scope, out);
    }
    out.push_str("</");
    out.push_str(qname);
    out.push('>');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::saml::xml::parse;

    fn c14n_of(doc: &str, path: &[&str]) -> String {
        let d = parse(doc).unwrap();
        let mut n = d.root_element();
        for name in path {
            n = n
                .children()
                .find(|c| c.is_element() && c.tag_name().name() == *name)
                .unwrap();
        }
        canonicalize(n, None, &[])
    }

    #[test]
    fn only_used_namespaces_are_rendered() {
        // After the exc-c14n spec, §2.2: the ancestor's `n0` is not rendered,
        // and `n3` is declared where it is used.
        let doc = r#"<n0:local xmlns:n0="foo:bar" xmlns:n3="ftp://example.org"><n1:elem2 xmlns:n1="http://example.net" xml:lang="en"><n3:stuff xmlns:n3="ftp://example.org"/></n1:elem2></n0:local>"#;
        assert_eq!(
            c14n_of(doc, &["elem2"]),
            r#"<n1:elem2 xmlns:n1="http://example.net" xml:lang="en"><n3:stuff xmlns:n3="ftp://example.org"></n3:stuff></n1:elem2>"#
        );
    }

    #[test]
    fn attributes_are_sorted_and_empty_elements_expanded() {
        let doc = r#"<a xmlns:b="urn:b" xmlns:c="urn:a" z="1" b:y="2" c:x="3" a="4"/>"#;
        // Unqualified first (by local name), then by namespace URI:
        // urn:a (c:x) before urn:b (b:y).
        assert_eq!(
            c14n_of(doc, &[]),
            r#"<a xmlns:b="urn:b" xmlns:c="urn:a" a="4" z="1" c:x="3" b:y="2"></a>"#
        );
    }

    #[test]
    fn default_namespaces_are_declared_and_undeclared() {
        let doc = r#"<a xmlns="urn:d"><b><c xmlns=""/></b></a>"#;
        assert_eq!(
            c14n_of(doc, &["b"]),
            r#"<b xmlns="urn:d"><c xmlns=""></c></b>"#
        );
        // An unprefixed element in no namespace under nothing rendered needs
        // no declaration at all.
        assert_eq!(c14n_of(r#"<a><b/></a>"#, &[]), "<a><b></b></a>");
    }

    #[test]
    fn text_and_attribute_values_are_escaped() {
        let doc = "<a t=\"&quot;&#9;&#xA;&lt;&gt;\">x &amp; &lt; &gt; <![CDATA[<y>]]><!-- gone --><?p d?></a>";
        assert_eq!(
            c14n_of(doc, &[]),
            "<a t=\"&quot;&#x9;&#xA;&lt;>\">x &amp; &lt; &gt; &lt;y&gt;<?p d?></a>"
        );
    }

    #[test]
    fn an_excluded_node_is_left_out() {
        let d = parse(r#"<a><s><x/></s><b/></a>"#).unwrap();
        let root = d.root_element();
        let s = root.first_element_child().unwrap();
        assert_eq!(canonicalize(root, Some(s.id()), &[]), "<a><b></b></a>");
    }

    #[test]
    fn inclusive_prefixes_are_kept() {
        let doc = r#"<a xmlns:x="urn:x" xmlns:y="urn:y"><b/></a>"#;
        let d = parse(doc).unwrap();
        let b = d.root_element().first_element_child().unwrap();
        assert_eq!(
            canonicalize(b, None, &["x".into()]),
            r#"<b xmlns:x="urn:x"></b>"#
        );
    }
}
