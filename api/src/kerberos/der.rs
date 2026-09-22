//! The little DER the Kerberos acceptor needs: a bounds-checked reader of
//! tag-length-value items (single-byte tags, definite lengths) and an
//! encoder for the few messages rIDM writes. Nothing here recurses on the
//! input, so a deeply nested token costs nothing.

use chrono::{DateTime, NaiveDate, TimeZone as _, Utc};

pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const OID: u8 = 0x06;
pub const ENUMERATED: u8 = 0x0a;
pub const GENERALIZED_TIME: u8 = 0x18;
pub const GENERAL_STRING: u8 = 0x1b;
pub const SEQUENCE: u8 = 0x30;

/// `[n]` constructed, context-specific.
pub const fn ctx(n: u8) -> u8 {
    0xa0 | n
}

/// `[APPLICATION n]` constructed.
pub const fn app(n: u8) -> u8 {
    0x60 | n
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("malformed DER: {0}")]
pub struct DerError(pub &'static str);

pub type DerResult<T> = Result<T, DerError>;

/// Reads consecutive items out of a byte slice.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// What is left unread.
    pub fn rest(&self) -> &'a [u8] {
        self.buf
    }

    /// The tag of the next item, without reading it.
    pub fn peek_tag(&self) -> Option<u8> {
        self.buf.first().copied()
    }

    /// The next item: its tag and content.
    pub fn item(&mut self) -> DerResult<(u8, &'a [u8])> {
        let (&tag, rest) = self.buf.split_first().ok_or(DerError("truncated"))?;
        if tag & 0x1f == 0x1f {
            return Err(DerError("multi-byte tag"));
        }
        let (&first, mut rest) = rest.split_first().ok_or(DerError("truncated length"))?;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 {
                return Err(DerError("indefinite length"));
            }
            if n > 3 || rest.len() < n {
                return Err(DerError("length out of range"));
            }
            let mut len = 0usize;
            for &b in &rest[..n] {
                len = (len << 8) | usize::from(b);
            }
            rest = &rest[n..];
            len
        };
        if rest.len() < len {
            return Err(DerError("content runs past the end"));
        }
        let (content, after) = rest.split_at(len);
        self.buf = after;
        Ok((tag, content))
    }

    /// The next item, which must carry `tag`.
    pub fn expect(&mut self, tag: u8) -> DerResult<&'a [u8]> {
        match self.item()? {
            (t, content) if t == tag => Ok(content),
            _ => Err(DerError("unexpected tag")),
        }
    }

    /// The next item when it carries `tag`; nothing is read otherwise.
    pub fn optional(&mut self, tag: u8) -> DerResult<Option<&'a [u8]>> {
        if self.peek_tag() == Some(tag) {
            self.expect(tag).map(Some)
        } else {
            Ok(None)
        }
    }

    /// `[n] EXPLICIT <inner>`: the inner item's content.
    pub fn explicit(&mut self, n: u8, inner: u8) -> DerResult<&'a [u8]> {
        let wrapped = self.expect(ctx(n))?;
        single(wrapped, inner)
    }

    /// An optional `[n] EXPLICIT <inner>`.
    pub fn explicit_opt(&mut self, n: u8, inner: u8) -> DerResult<Option<&'a [u8]>> {
        match self.optional(ctx(n))? {
            Some(wrapped) => single(wrapped, inner).map(Some),
            None => Ok(None),
        }
    }

    /// Skip optional `[n]` fields up to (not including) `[until]`.
    pub fn skip_until(&mut self, until: u8) -> DerResult<()> {
        while let Some(tag) = self.peek_tag() {
            if tag >= ctx(until) || tag & 0xe0 != 0xa0 {
                break;
            }
            self.item()?;
        }
        Ok(())
    }
}

/// The content of the one item `buf` holds, which must carry `tag`.
pub fn single(buf: &[u8], tag: u8) -> DerResult<&[u8]> {
    let mut r = Reader::new(buf);
    let content = r.expect(tag)?;
    if !r.is_empty() {
        return Err(DerError("trailing data"));
    }
    Ok(content)
}

/// An INTEGER's content as an `i64` (Kerberos never needs more).
pub fn int(content: &[u8]) -> DerResult<i64> {
    if content.is_empty() || content.len() > 8 {
        return Err(DerError("integer out of range"));
    }
    let mut v: i64 = if content[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in content {
        v = (v << 8) | i64::from(b);
    }
    Ok(v)
}

/// A KerberosString. RFC 4120 says IA5; Active Directory and MIT carry
/// UTF-8 in practice, so that is what is accepted.
pub fn string(content: &[u8]) -> DerResult<String> {
    if content.len() > 1024 {
        return Err(DerError("string too long"));
    }
    String::from_utf8(content.to_vec()).map_err(|_| DerError("string is not UTF-8"))
}

/// A KerberosTime: `YYYYMMDDHHMMSSZ`, no fractions.
pub fn time(content: &[u8]) -> DerResult<DateTime<Utc>> {
    let bad = DerError("bad KerberosTime");
    if content.len() != 15 || content[14] != b'Z' || !content[..14].iter().all(u8::is_ascii_digit) {
        return Err(bad);
    }
    let n = |a: usize, b: usize| -> u32 {
        content[a..b]
            .iter()
            .fold(0u32, |acc, d| acc * 10 + u32::from(d - b'0'))
    };
    let date =
        NaiveDate::from_ymd_opt(n(0, 4) as i32, n(4, 6), n(6, 8)).ok_or(DerError("bad date"))?;
    let at = date
        .and_hms_opt(n(8, 10), n(10, 12), n(12, 14))
        .ok_or(DerError("bad time"))?;
    Ok(Utc.from_utc_datetime(&at))
}

/// Bit `i` of a BIT STRING's content (bit 0 is the first byte's top bit).
pub fn bit(content: &[u8], i: usize) -> bool {
    content
        .get(1 + i / 8)
        .is_some_and(|b| b & (0x80 >> (i % 8)) != 0)
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// One item.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// Several items one after another.
pub fn concat(items: &[Vec<u8>]) -> Vec<u8> {
    items.concat()
}

pub fn enc_int(v: i64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let (b, next) = (bytes[start], bytes[start + 1]);
        if (b == 0x00 && next & 0x80 == 0) || (b == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    tlv(INTEGER, &bytes[start..])
}

pub fn enc_time(t: DateTime<Utc>) -> Vec<u8> {
    tlv(
        GENERALIZED_TIME,
        t.format("%Y%m%d%H%M%SZ").to_string().as_bytes(),
    )
}

/// `[n] EXPLICIT` around an encoded item.
pub fn enc_explicit(n: u8, inner: Vec<u8>) -> Vec<u8> {
    tlv(ctx(n), &inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_and_integers_round_trip() {
        for v in [0i64, 1, 127, 128, 255, 256, -1, -128, -129, 65535, i64::MAX] {
            let enc = enc_int(v);
            assert_eq!(int(single(&enc, INTEGER).unwrap()).unwrap(), v, "{v}");
        }
        let long = vec![7u8; 70_000];
        let enc = tlv(OCTET_STRING, &long);
        assert_eq!(single(&enc, OCTET_STRING).unwrap(), &long[..]);
    }

    #[test]
    fn malformed_items_are_errors_not_panics() {
        for bad in [
            &[][..],
            &[0x30],
            &[0x30, 0x80],
            &[0x30, 0x84, 1, 0, 0, 0],
            &[0x30, 0x05, 1],
            &[0x1f, 0x01, 0x00],
        ] {
            assert!(Reader::new(bad).item().is_err(), "{bad:?}");
        }
        assert!(int(&[]).is_err());
        assert!(int(&[0; 9]).is_err());
        assert!(time(b"20260922120000").is_err());
        assert!(time(b"20261322120000Z").is_err());
        assert!(!bit(&[0], 3));
    }

    #[test]
    fn kerberos_time() {
        let t = time(b"20260922123456Z").unwrap();
        assert_eq!(t.to_rfc3339(), "2026-09-22T12:34:56+00:00");
        assert_eq!(
            single(&enc_time(t), GENERALIZED_TIME).unwrap(),
            b"20260922123456Z"
        );
    }
}
