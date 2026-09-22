//! MIT keytab files (format 0x0502, which `ktutil`, `kadmin ktadd` and
//! Windows' `ktpass` all write): the service's long-term keys, one entry
//! per principal, key version and encryption type.

use serde::Serialize;
use zeroize::Zeroizing;

use super::Principal;

/// Largest keytab accepted.
pub const MAX_KEYTAB_BYTES: usize = 64 * 1024;
const MAX_ENTRIES: usize = 256;

/// `aes128-cts-hmac-sha1-96`.
pub const ETYPE_AES128: i32 = 17;
/// `aes256-cts-hmac-sha1-96`.
pub const ETYPE_AES256: i32 = 18;

/// Whether rIDM decrypts tickets of this encryption type. RC4 and the DES
/// family are refused: they are broken, and Active Directory issues AES
/// tickets to an account whose `msDS-SupportedEncryptionTypes` allow it.
pub fn etype_supported(etype: i32) -> bool {
    matches!(etype, ETYPE_AES128 | ETYPE_AES256)
}

/// The key length an encryption type needs.
pub fn etype_key_len(etype: i32) -> Option<usize> {
    match etype {
        ETYPE_AES128 => Some(16),
        ETYPE_AES256 => Some(32),
        _ => None,
    }
}

pub fn etype_name(etype: i32) -> String {
    match etype {
        1 => "des-cbc-crc".into(),
        3 => "des-cbc-md5".into(),
        16 => "des3-cbc-sha1".into(),
        ETYPE_AES128 => "aes128-cts-hmac-sha1-96".into(),
        ETYPE_AES256 => "aes256-cts-hmac-sha1-96".into(),
        19 => "aes128-cts-hmac-sha256-128".into(),
        20 => "aes256-cts-hmac-sha384-192".into(),
        23 => "rc4-hmac".into(),
        24 => "rc4-hmac-exp".into(),
        25 => "camellia128-cts-cmac".into(),
        26 => "camellia256-cts-cmac".into(),
        other => format!("etype {other}"),
    }
}

/// One key.
#[derive(Clone)]
pub struct KeytabEntry {
    pub principal: Principal,
    pub kvno: u32,
    pub etype: i32,
    pub key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for KeytabEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeytabEntry")
            .field("principal", &self.principal.to_string())
            .field("kvno", &self.kvno)
            .field("etype", &self.etype)
            .finish_non_exhaustive()
    }
}

/// What a keytab entry says, without its key: what the admin API shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct KeytabEntryInfo {
    pub principal: String,
    pub kvno: u32,
    pub etype: i32,
    /// e.g. `aes256-cts-hmac-sha1-96`.
    pub etype_name: String,
    /// rIDM can use this key (AES).
    pub supported: bool,
}

impl KeytabEntry {
    pub fn info(&self) -> KeytabEntryInfo {
        KeytabEntryInfo {
            principal: self.principal.to_string(),
            kvno: self.kvno,
            etype: self.etype,
            etype_name: etype_name(self.etype),
            supported: etype_supported(self.etype),
        }
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.buf.len() < n {
            return Err("truncated entry".into());
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn counted(&mut self) -> Result<&'a [u8], String> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }

    fn text(&mut self) -> Result<String, String> {
        let raw = self.counted()?;
        if raw.is_empty() || raw.len() > 255 {
            return Err("a principal name part is empty or too long".into());
        }
        String::from_utf8(raw.to_vec()).map_err(|_| "a principal name is not UTF-8".into())
    }
}

/// Every entry of a keytab file. Deleted entries (holes) are skipped.
pub fn parse_keytab(bytes: &[u8]) -> Result<Vec<KeytabEntry>, String> {
    if bytes.len() > MAX_KEYTAB_BYTES {
        return Err(format!(
            "a keytab is at most {} KiB",
            MAX_KEYTAB_BYTES / 1024
        ));
    }
    match bytes {
        [0x05, 0x02, ..] => {}
        [0x05, 0x01, ..] => {
            return Err("keytab format 0x0501 (native byte order) is not supported".into());
        }
        _ => return Err("not a keytab file".into()),
    }
    let mut rest = &bytes[2..];
    let mut out = vec![];
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err("truncated entry".into());
        }
        let size = i32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
        rest = &rest[4..];
        if size == 0 {
            break;
        }
        let len = size.unsigned_abs() as usize;
        if len > rest.len() {
            return Err("an entry runs past the end of the file".into());
        }
        let (record, after) = rest.split_at(len);
        rest = after;
        if size < 0 {
            continue;
        }
        if out.len() == MAX_ENTRIES {
            return Err(format!("a keytab holds at most {MAX_ENTRIES} keys"));
        }
        out.push(parse_entry(record)?);
    }
    Ok(out)
}

fn parse_entry(record: &[u8]) -> Result<KeytabEntry, String> {
    let mut c = Cursor { buf: record };
    let count = c.u16()?;
    if count == 0 || count > 8 {
        return Err("a principal has no or too many name parts".into());
    }
    let realm = c.text()?;
    let mut components = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        components.push(c.text()?);
    }
    let _name_type = c.u32()?;
    let _timestamp = c.u32()?;
    let vno8 = c.u8()?;
    let etype = i32::from(c.u16()?);
    let key = c.counted()?;
    if key.is_empty() || key.len() > 64 {
        return Err("a key has an impossible length".into());
    }
    let key = Zeroizing::new(key.to_vec());
    // A 32-bit version follows when the record has room for it; zero
    // means "use the 8-bit one".
    let kvno = match c.buf.len() {
        n if n >= 4 => match c.u32()? {
            0 => u32::from(vno8),
            v => v,
        },
        _ => u32::from(vno8),
    };
    if let Some(want) = etype_key_len(etype)
        && key.len() != want
    {
        return Err(format!("a {} key must be {want} bytes", etype_name(etype)));
    }
    Ok(KeytabEntry {
        principal: Principal { components, realm },
        kvno,
        etype,
        key,
    })
}

/// Encode entries as a keytab file (format 0x0502): the inverse of
/// [`parse_keytab`], used by tests and by the tooling that builds one.
pub fn write_keytab(entries: &[KeytabEntry]) -> Vec<u8> {
    let mut out = vec![0x05, 0x02];
    for e in entries {
        let mut rec = vec![];
        let counted = |rec: &mut Vec<u8>, b: &[u8]| {
            rec.extend_from_slice(&(b.len() as u16).to_be_bytes());
            rec.extend_from_slice(b);
        };
        rec.extend_from_slice(&(e.principal.components.len() as u16).to_be_bytes());
        counted(&mut rec, e.principal.realm.as_bytes());
        for comp in &e.principal.components {
            counted(&mut rec, comp.as_bytes());
        }
        rec.extend_from_slice(&1u32.to_be_bytes());
        rec.extend_from_slice(&0u32.to_be_bytes());
        rec.push((e.kvno & 0xff) as u8);
        rec.extend_from_slice(&(e.etype as u16).to_be_bytes());
        counted(&mut rec, &e.key);
        rec.extend_from_slice(&e.kvno.to_be_bytes());
        out.extend_from_slice(&(rec.len() as i32).to_be_bytes());
        out.extend_from_slice(&rec);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(p: &str, kvno: u32, etype: i32, len: usize) -> KeytabEntry {
        KeytabEntry {
            principal: Principal::parse(p).unwrap(),
            kvno,
            etype,
            key: Zeroizing::new(vec![7; len]),
        }
    }

    #[test]
    fn round_trips_and_skips_holes() {
        let entries = [
            entry("HTTP/sso.example.com@EXAMPLE.COM", 3, ETYPE_AES256, 32),
            entry("HTTP/sso.example.com@EXAMPLE.COM", 300, ETYPE_AES128, 16),
            entry("host/x@EXAMPLE.COM", 1, 23, 16),
        ];
        let mut bytes = write_keytab(&entries);
        // A hole of 5 bytes after the header.
        let mut holed = bytes[..2].to_vec();
        holed.extend_from_slice(&(-5i32).to_be_bytes());
        holed.extend_from_slice(&[0; 5]);
        holed.extend_from_slice(&bytes[2..]);
        bytes = holed;
        let parsed = parse_keytab(&bytes).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(
            parsed[0].principal.to_string(),
            "HTTP/sso.example.com@EXAMPLE.COM"
        );
        assert_eq!(
            parsed[1].kvno, 300,
            "the 32-bit kvno wins over the 8-bit one"
        );
        assert_eq!(parsed[1].etype, ETYPE_AES128);
        assert!(!parsed[2].info().supported);
        assert_eq!(parsed[2].info().etype_name, "rc4-hmac");
    }

    #[test]
    fn refuses_what_is_not_a_keytab() {
        assert!(parse_keytab(b"").is_err());
        assert!(parse_keytab(b"\x05\x01").is_err());
        assert!(parse_keytab(b"hello").is_err());
        let good = write_keytab(&[entry("a@R", 1, ETYPE_AES256, 32)]);
        for cut in 3..good.len() {
            assert!(parse_keytab(&good[..cut]).is_err(), "cut at {cut}");
        }
        assert!(parse_keytab(&write_keytab(&[entry("a@R", 1, ETYPE_AES256, 16)])).is_err());
        assert!(parse_keytab(&vec![5u8; MAX_KEYTAB_BYTES + 1]).is_err());
    }
}
