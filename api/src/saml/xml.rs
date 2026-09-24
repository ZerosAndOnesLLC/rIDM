//! XML in and out. Input goes through `roxmltree` with DTDs refused, so no
//! entity is ever expanded and no external resource is ever fetched; output
//! is built with [`El`], which writes no insignificant whitespace, so what
//! rIDM signs is exactly what it sends.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use roxmltree::{Document, Node, ParsingOptions};

use super::error::{SamlError, SamlResult};

/// Largest XML document accepted, after base64 and DEFLATE are undone.
pub const MAX_DOCUMENT_BYTES: usize = 256 * 1024;
/// Largest number of nodes in one document: a real AuthnRequest or
/// metadata file has a few hundred.
const MAX_NODES: u32 = 20_000;
/// Deepest element nesting accepted; SAML protocol messages stay under ten.
const MAX_DEPTH: usize = 64;

/// Parse an untrusted document: size-capped, DTD refused, node count and
/// nesting bounded.
pub fn parse(text: &str) -> SamlResult<Document<'_>> {
    if text.len() > MAX_DOCUMENT_BYTES {
        return Err(SamlError::malformed("document too large"));
    }
    let opts = ParsingOptions {
        allow_dtd: false,
        nodes_limit: MAX_NODES,
        ..ParsingOptions::default()
    };
    let doc = Document::parse_with_options(text, opts)
        .map_err(|e| SamlError::malformed(format!("not well-formed XML ({e})")))?;
    if too_deep(&doc) {
        return Err(SamlError::malformed("elements nested too deeply"));
    }
    Ok(doc)
}

/// Whether an element sits more than [`MAX_DEPTH`] nodes deep (counting it
/// and the document node). One walk that carries the depth down, rather
/// than counting every element's ancestors: the input is untrusted, and
/// that would be nodes × depth.
fn too_deep(doc: &Document<'_>) -> bool {
    let mut stack = vec![(doc.root(), 1usize)];
    while let Some((node, depth)) = stack.pop() {
        if node.is_element() && depth > MAX_DEPTH {
            return true;
        }
        stack.extend(
            node.children()
                .filter(Node::is_element)
                .map(|c| (c, depth + 1)),
        );
    }
    false
}

/// The prefix an element was written with (`None`: unprefixed). `roxmltree`
/// resolves names but keeps no prefixes, so they are read back from the
/// source text, which canonicalization needs.
pub fn element_prefix<'a>(node: Node<'a, '_>) -> Option<&'a str> {
    let text = node.document().input_text();
    let start = node.range().start + 1;
    let rest = &text[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
        .unwrap_or(rest.len());
    rest[..end].split_once(':').map(|(p, _)| p)
}

/// The qualified name an element was written with.
pub fn element_qname<'a>(node: Node<'a, '_>) -> &'a str {
    let text = node.document().input_text();
    let start = node.range().start + 1;
    let rest = &text[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
        .unwrap_or(rest.len());
    &rest[..end]
}

/// The qualified name an attribute was written with.
pub fn attribute_qname<'a>(node: Node<'a, '_>, attr: &roxmltree::Attribute<'a, '_>) -> &'a str {
    &node.document().input_text()[attr.range_qname()]
}

/// Whether `node` is the element `ns`:`local`.
pub fn is(node: Node, ns: &str, local: &str) -> bool {
    node.is_element() && node.tag_name().name() == local && node.tag_name().namespace() == Some(ns)
}

/// The child elements named `ns`:`local`.
pub fn children<'a, 'i>(
    node: Node<'a, 'i>,
    ns: &'a str,
    local: &'a str,
) -> impl Iterator<Item = Node<'a, 'i>> {
    node.children().filter(move |c| is(*c, ns, local))
}

/// The only child element named `ns`:`local`, if there is one; two are an
/// error, since the schema allows at most one of everything this is used for.
pub fn child<'a, 'i>(
    node: Node<'a, 'i>,
    ns: &'a str,
    local: &'a str,
) -> SamlResult<Option<Node<'a, 'i>>> {
    let mut it = children(node, ns, local);
    let first = it.next();
    if it.next().is_some() {
        return Err(SamlError::malformed(format!(
            "more than one {local} element"
        )));
    }
    Ok(first)
}

/// The text of an element made of text only (whitespace trimmed).
pub fn text_of(node: Node) -> String {
    node.children()
        .filter(Node::is_text)
        .filter_map(|t| t.text())
        .collect::<String>()
        .trim()
        .to_string()
}

/// base64 content of an element: XML signatures and certificates wrap it,
/// so whitespace is dropped before decoding.
pub fn base64_content(s: &str) -> SamlResult<Vec<u8>> {
    let compact: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    STANDARD
        .decode(compact)
        .map_err(|_| SamlError::malformed("invalid base64 content"))
}

/// Every element in the document whose `ID` attribute is `id`. SAML names
/// its identifier attribute `ID`; more than one match means the document is
/// trying to confuse a signature check.
pub fn elements_with_id<'a, 'i>(doc: &'a Document<'i>, id: &str) -> Vec<Node<'a, 'i>> {
    doc.descendants()
        .filter(|n| n.is_element() && n.attribute("ID") == Some(id))
        .collect()
}

/// Escape character data for output.
pub fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape an attribute value for output (double-quoted).
pub fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(c),
        }
    }
    out
}

/// An element being built for output.
#[derive(Debug, Clone, PartialEq)]
pub struct El {
    name: String,
    attrs: Vec<(String, String)>,
    children: Vec<Child>,
}

#[derive(Debug, Clone, PartialEq)]
enum Child {
    El(El),
    Text(String),
}

impl El {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            attrs: vec![],
            children: vec![],
        }
    }

    pub fn attr(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.attrs.push((name.into(), value.into()));
        self
    }

    pub fn attr_opt(self, name: impl Into<String>, value: Option<impl Into<String>>) -> Self {
        match value {
            Some(v) => self.attr(name, v),
            None => self,
        }
    }

    pub fn child(mut self, el: El) -> Self {
        self.children.push(Child::El(el));
        self
    }

    pub fn child_opt(self, el: Option<El>) -> Self {
        match el {
            Some(el) => self.child(el),
            None => self,
        }
    }

    pub fn text(mut self, s: impl Into<String>) -> Self {
        self.children.push(Child::Text(s.into()));
        self
    }

    /// Insert a child element at `index` among the children.
    pub fn insert(&mut self, index: usize, el: El) {
        let at = index.min(self.children.len());
        self.children.insert(at, Child::El(el));
    }

    /// Replace the child element named `name`, if there is one.
    pub fn replace_child(&mut self, name: &str, with: El) -> bool {
        for c in &mut self.children {
            if let Child::El(e) = c
                && e.name == name
            {
                *e = with;
                return true;
            }
        }
        false
    }

    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn write(&self, out: &mut String) {
        out.push('<');
        out.push_str(&self.name);
        for (k, v) in &self.attrs {
            out.push(' ');
            out.push_str(k);
            out.push_str("=\"");
            out.push_str(&escape_attr(v));
            out.push('"');
        }
        if self.children.is_empty() {
            out.push_str("/>");
            return;
        }
        out.push('>');
        for c in &self.children {
            match c {
                Child::El(e) => e.write(out),
                Child::Text(t) => out.push_str(&escape_text(t)),
            }
        }
        out.push_str("</");
        out.push_str(&self.name);
        out.push('>');
    }

    /// The element as a document, with the XML declaration.
    pub fn to_document(&self) -> String {
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        self.write(&mut out);
        out
    }
}

impl std::fmt::Display for El {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        self.write(&mut s);
        f.write_str(&s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dtds_are_refused() {
        let xxe = r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>"#;
        assert!(parse(xxe).is_err());
        let laughs = r#"<!DOCTYPE r [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><r>&b;</r>"#;
        assert!(parse(laughs).is_err());
    }

    #[test]
    fn size_and_depth_are_bounded() {
        let big = format!("<r>{}</r>", "a".repeat(MAX_DOCUMENT_BYTES));
        assert!(parse(&big).is_err());
        // The limit counts the document node: 63 nested elements pass, 64
        // do not.
        let nested = |n: usize| format!("{}{}", "<a>".repeat(n), "</a>".repeat(n));
        assert!(parse(&nested(MAX_DEPTH - 1)).is_ok());
        assert!(parse(&nested(MAX_DEPTH)).is_err());
        let deep = format!("{}{}", "<a>".repeat(100), "</a>".repeat(100));
        assert!(parse(&deep).is_err());
        let fine = format!("{}{}", "<a>".repeat(20), "</a>".repeat(20));
        assert!(parse(&fine).is_ok());
    }

    #[test]
    fn prefixes_are_read_from_the_source() {
        let doc = parse(r#"<p:a xmlns:p="urn:x" xmlns:q="urn:y" q:b="1"><c/></p:a>"#).unwrap();
        let root = doc.root_element();
        assert_eq!(element_prefix(root), Some("p"));
        assert_eq!(element_qname(root), "p:a");
        let attr = root.attributes().next().unwrap();
        assert_eq!(attribute_qname(root, &attr), "q:b");
        let c = root.first_element_child().unwrap();
        assert_eq!(element_prefix(c), None);
    }

    #[test]
    fn built_elements_escape_their_content() {
        let el = El::new("a")
            .attr("x", "1\"<&\n")
            .child(El::new("b").text("x<y&z>"))
            .child(El::new("c"));
        assert_eq!(
            el.to_string(),
            "<a x=\"1&quot;&lt;&amp;&#xA;\"><b>x&lt;y&amp;z&gt;</b><c/></a>"
        );
    }
}
