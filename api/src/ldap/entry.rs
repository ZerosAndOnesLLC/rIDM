//! Search entries, read without trusting the directory: `ldap3`'s own
//! `SearchEntry::construct` panics on a malformed entry, so a hostile or
//! broken server could take a request down with it. [`Entry::parse`] reads
//! the same structure and gives up quietly instead.

use std::collections::HashMap;

use ldap3::ResultEntry;
use ldap3::asn1::StructureTag;
use serde_json::{Map, Value};

/// A directory entry: its DN and attributes, names lower-cased (LDAP
/// attribute names are case-insensitive). Values that are not UTF-8 are
/// kept apart, as bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    pub dn: String,
    pub attrs: HashMap<String, Vec<String>>,
    pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}

/// At most this many values are kept per attribute (a group's `member`
/// can be long; a user's attributes never are).
pub const MAX_VALUES: usize = 100_000;

impl Entry {
    /// Read a search result entry; `None` when it is malformed.
    pub fn parse(re: ResultEntry) -> Option<Entry> {
        Self::from_tag(re.0)
    }

    fn from_tag(tag: StructureTag) -> Option<Entry> {
        let mut tags = tag.match_id(4)?.expect_constructed()?.into_iter();
        let dn = String::from_utf8(tags.next()?.expect_primitive()?).ok()?;
        let mut entry = Entry {
            dn,
            ..Default::default()
        };
        for partial in tags.next()?.expect_constructed()? {
            let mut parts = partial.expect_constructed()?.into_iter();
            let name = String::from_utf8(parts.next()?.expect_primitive()?)
                .ok()?
                .to_ascii_lowercase();
            let mut text = vec![];
            let mut bin = vec![];
            for v in parts
                .next()?
                .expect_constructed()?
                .into_iter()
                .take(MAX_VALUES)
            {
                let raw = v.expect_primitive()?;
                match String::from_utf8(raw) {
                    Ok(s) => text.push(s),
                    Err(e) => bin.push(e.into_bytes()),
                }
            }
            if bin.is_empty() {
                entry.attrs.insert(name, text);
            } else {
                // Like ldap3: one binary value makes the whole attribute binary.
                bin.extend(text.into_iter().map(String::into_bytes));
                entry.bin_attrs.insert(name, bin);
            }
        }
        Some(entry)
    }

    /// Every text value of an attribute.
    pub fn values(&self, attribute: &str) -> &[String] {
        self.attrs
            .get(&attribute.to_ascii_lowercase())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// The first text value of an attribute.
    pub fn first(&self, attribute: &str) -> Option<&str> {
        self.values(attribute).first().map(String::as_str)
    }

    /// The entry's stable identifier from `attribute`: a text value as it
    /// is (`entryUUID`), or a 16-byte binary value as a GUID string
    /// (`objectGUID`).
    pub fn uuid(&self, attribute: &str) -> Option<String> {
        let key = attribute.to_ascii_lowercase();
        if let Some(bytes) = self.bin_attrs.get(&key).and_then(|v| v.first()) {
            return guid_string(bytes);
        }
        // A GUID whose 16 bytes happen to be valid UTF-8 lands among the
        // text values.
        let text = self.first(attribute)?;
        if key == "objectguid" && text.len() == 16 {
            return guid_string(text.as_bytes());
        }
        let t = text.trim();
        (!t.is_empty() && t.len() <= 512).then(|| t.to_string())
    }

    /// Active Directory's "account disabled" flag (`userAccountControl`
    /// bit 2).
    pub fn ad_disabled(&self) -> bool {
        self.first("userAccountControl")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .is_some_and(|flags| flags & 2 != 0)
    }

    /// The named attributes as claims for the mappers: each under the name
    /// asked for (whatever case the directory used), one value as a
    /// string, several as an array.
    pub fn claims<'a>(&self, names: impl IntoIterator<Item = &'a str>) -> Map<String, Value> {
        let mut out = Map::new();
        for name in names {
            let values = self.values(name);
            let v = match values {
                [] => continue,
                [one] => Value::String(one.clone()),
                many => Value::Array(many.iter().cloned().map(Value::String).collect()),
            };
            out.insert(name.to_string(), v);
        }
        out
    }
}

/// Active Directory writes a GUID's first three fields little-endian.
pub fn guid_string(bytes: &[u8]) -> Option<String> {
    let b: [u8; 16] = bytes.try_into().ok()?;
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[3],
        b[2],
        b[1],
        b[0],
        b[5],
        b[4],
        b[7],
        b[6],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    ))
}

/// The bytes of a GUID string as Active Directory stores them (the inverse
/// of [`guid_string`]).
pub fn guid_bytes(guid: &str) -> Option<[u8; 16]> {
    let hex: String = guid.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut raw = [0u8; 16];
    for (i, byte) in raw.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some([
        raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9], raw[10],
        raw[11], raw[12], raw[13], raw[14], raw[15],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldap3::asn1::{ASNTag as _, OctetString, Sequence, Set, Tag, TagClass};

    fn octets(v: &[u8]) -> Tag {
        Tag::OctetString(OctetString {
            inner: v.to_vec(),
            ..Default::default()
        })
    }

    fn entry_tag(dn: &str, attrs: &[(&str, Vec<&[u8]>)]) -> StructureTag {
        let attrs = attrs
            .iter()
            .map(|(name, values)| {
                Tag::Sequence(Sequence {
                    inner: vec![
                        octets(name.as_bytes()),
                        Tag::Set(Set {
                            inner: values.iter().map(|v| octets(v)).collect(),
                            ..Default::default()
                        }),
                    ],
                    ..Default::default()
                })
            })
            .collect();
        Tag::Sequence(Sequence {
            id: 4,
            class: TagClass::Application,
            inner: vec![
                octets(dn.as_bytes()),
                Tag::Sequence(Sequence {
                    inner: attrs,
                    ..Default::default()
                }),
            ],
        })
        .into_structure()
    }

    #[test]
    fn entries_are_read_with_lowercased_names_and_binary_values_apart() {
        let guid: &[u8] = &[
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
            0x56, 0xff,
        ];
        let tag = entry_tag(
            "uid=alice,ou=people,dc=example,dc=org",
            &[
                ("uid", vec![b"alice"]),
                ("mail", vec![b"a@example.org", b"alice@example.org"]),
                ("objectGUID", vec![guid]),
                ("userAccountControl", vec![b"514"]),
            ],
        );
        let e = Entry::from_tag(tag).unwrap();
        assert_eq!(e.dn, "uid=alice,ou=people,dc=example,dc=org");
        assert_eq!(e.first("UID"), Some("alice"));
        assert_eq!(e.values("mail").len(), 2);
        assert_eq!(
            e.uuid("objectGUID").as_deref(),
            Some("12345678-1234-5678-9abc-def0123456ff")
        );
        assert_eq!(e.uuid("uid").as_deref(), Some("alice"));
        assert!(e.ad_disabled());
        let claims = e.claims(["uid", "mail", "missing"]);
        assert_eq!(claims["uid"], "alice");
        assert_eq!(claims["mail"].as_array().unwrap().len(), 2);
        assert!(!claims.contains_key("missing"));
    }

    #[test]
    fn a_malformed_entry_is_refused_not_a_panic() {
        let not_an_entry = octets(b"hello").into_structure();
        assert!(Entry::from_tag(not_an_entry).is_none());
        let no_attrs = Tag::Sequence(Sequence {
            id: 4,
            class: TagClass::Application,
            inner: vec![octets(b"cn=x")],
        })
        .into_structure();
        assert!(Entry::from_tag(no_attrs).is_none());
        let mut bad = entry_tag("", &[]);
        if let ldap3::asn1::PL::C(ref mut inner) = bad.payload {
            inner[0] = octets(&[0xff, 0xfe]).into_structure();
        }
        assert!(Entry::from_tag(bad).is_none());
    }

    #[test]
    fn guids_round_trip() {
        let s = "12345678-1234-5678-9abc-def0123456ff";
        let b = guid_bytes(s).unwrap();
        assert_eq!(guid_string(&b).as_deref(), Some(s));
        assert!(guid_bytes("nope").is_none());
        assert!(guid_string(&[1, 2, 3]).is_none());
    }
}
