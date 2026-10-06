//! The little CBOR (RFC 8949) WebAuthn needs: the attestation object, COSE
//! keys and authenticator extension maps. A bounds-checked reader of definite
//! lengths, depth-limited, that never trusts a length it can't back with
//! bytes. Floats and tags are skipped over (as [`Value::Other`]): nothing
//! rIDM reads uses them.

/// A decoded item.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
    /// A float, a tagged item or another simple value.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("malformed CBOR: {0}")]
pub struct CborError(pub &'static str);

const MAX_DEPTH: usize = 16;

impl Value {
    /// The entry under integer key `k` of a map.
    pub fn get_int(&self, k: i128) -> Option<&Value> {
        self.entries()?
            .iter()
            .find(|(key, _)| *key == Value::Int(k))
            .map(|(_, v)| v)
    }

    /// The entry under text key `k` of a map.
    pub fn get_text(&self, k: &str) -> Option<&Value> {
        self.entries()?
            .iter()
            .find(|(key, _)| matches!(key, Value::Text(t) if t == k))
            .map(|(_, v)| v)
    }

    pub fn entries(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i128> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }
}

/// Decode one item from the start of `input`; returns it and what follows.
pub fn decode(input: &[u8]) -> Result<(Value, &[u8]), CborError> {
    let mut r = Reader { buf: input };
    let v = r.item(0)?;
    Ok((v, r.buf))
}

/// Decode exactly one item: trailing bytes are an error.
pub fn decode_exact(input: &[u8]) -> Result<Value, CborError> {
    let (v, rest) = decode(input)?;
    if !rest.is_empty() {
        return Err(CborError("trailing data"));
    }
    Ok(v)
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        if n > self.buf.len() {
            return Err(CborError("truncated"));
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, CborError> {
        Ok(self.take(1)?[0])
    }

    /// The argument of a head: `info` 0-23 inline, 24-27 the next 1/2/4/8 bytes.
    fn argument(&mut self, info: u8) -> Result<u64, CborError> {
        Ok(match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.byte()?),
            25 => u64::from(u16::from_be_bytes(self.take(2)?.try_into().unwrap())),
            26 => u64::from(u32::from_be_bytes(self.take(4)?.try_into().unwrap())),
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
            _ => return Err(CborError("indefinite or reserved length")),
        })
    }

    /// A length, which must fit in what is left (each element takes at
    /// least one byte, so a count can be checked the same way).
    fn length(&mut self, info: u8) -> Result<usize, CborError> {
        let n = self.argument(info)?;
        usize::try_from(n)
            .ok()
            .filter(|n| *n <= self.buf.len())
            .ok_or(CborError("length past the end"))
    }

    fn item(&mut self, depth: usize) -> Result<Value, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError("nested too deeply"));
        }
        let head = self.byte()?;
        let (major, info) = (head >> 5, head & 0x1f);
        Ok(match major {
            0 => Value::Int(i128::from(self.argument(info)?)),
            1 => Value::Int(-1 - i128::from(self.argument(info)?)),
            2 => {
                let n = self.length(info)?;
                Value::Bytes(self.take(n)?.to_vec())
            }
            3 => {
                let n = self.length(info)?;
                let text = std::str::from_utf8(self.take(n)?)
                    .map_err(|_| CborError("text is not UTF-8"))?;
                Value::Text(text.to_string())
            }
            4 => {
                let n = self.length(info)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.item(depth + 1)?);
                }
                Value::Array(items)
            }
            5 => {
                let n = self.length(info)?;
                let mut entries = Vec::with_capacity(n);
                for _ in 0..n {
                    let k = self.item(depth + 1)?;
                    let v = self.item(depth + 1)?;
                    entries.push((k, v));
                }
                Value::Map(entries)
            }
            6 => {
                // A tag, then the item it tags.
                self.argument(info)?;
                self.item(depth + 1)?;
                Value::Other
            }
            _ => match info {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 => Value::Null,
                23 => Value::Other,
                24 => {
                    self.byte()?;
                    Value::Other
                }
                25 => {
                    self.take(2)?;
                    Value::Other
                }
                26 => {
                    self.take(4)?;
                    Value::Other
                }
                27 => {
                    self.take(8)?;
                    Value::Other
                }
                0..=19 => Value::Other,
                _ => return Err(CborError("indefinite or reserved simple value")),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// RFC 8949 appendix A examples.
    #[test]
    fn decodes_the_rfc_8949_examples() {
        assert_eq!(decode_exact(&h("00")).unwrap(), Value::Int(0));
        assert_eq!(decode_exact(&h("1903e8")).unwrap(), Value::Int(1000));
        assert_eq!(
            decode_exact(&h("1bffffffffffffffff")).unwrap(),
            Value::Int(18_446_744_073_709_551_615)
        );
        assert_eq!(decode_exact(&h("3863")).unwrap(), Value::Int(-100));
        assert_eq!(
            decode_exact(&h("4401020304")).unwrap(),
            Value::Bytes(vec![1, 2, 3, 4])
        );
        assert_eq!(
            decode_exact(&h("6449455446")).unwrap(),
            Value::Text("IETF".into())
        );
        assert_eq!(
            decode_exact(&h("a201020304")).unwrap(),
            Value::Map(vec![
                (Value::Int(1), Value::Int(2)),
                (Value::Int(3), Value::Int(4))
            ])
        );
        assert_eq!(decode_exact(&h("f5")).unwrap(), Value::Bool(true));
        assert_eq!(decode_exact(&h("f6")).unwrap(), Value::Null);
        assert_eq!(
            decode_exact(&h("fb3ff199999999999a")).unwrap(),
            Value::Other
        );
        assert_eq!(decode_exact(&h("c11a514b67b0")).unwrap(), Value::Other);
    }

    #[test]
    fn refuses_what_it_cannot_back_with_bytes() {
        assert!(decode_exact(&h("")).is_err());
        assert!(decode_exact(&h("44010203")).is_err(), "short byte string");
        assert!(
            decode_exact(&h("5bffffffffffffffff")).is_err(),
            "huge length"
        );
        assert!(
            decode_exact(&h("9bffffffffffffffff")).is_err(),
            "huge array"
        );
        assert!(decode_exact(&h("5f")).is_err(), "indefinite length");
        assert!(decode_exact(&h("0000")).is_err(), "trailing data");
        assert!(decode_exact(&h("62c328")).is_err(), "bad UTF-8");
        let deep = vec![0x81u8; 64];
        assert!(decode(&deep).is_err(), "depth limit");
        // Never panics on arbitrary input.
        for len in 0..64 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let _ = decode(&bytes);
        }
    }
}
