//! Kerberos principal names: `alice@EXAMPLE.COM`,
//! `HTTP/sso.example.com@EXAMPLE.COM`.

use std::fmt;

/// A principal: its name components and realm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub components: Vec<String>,
    pub realm: String,
}

/// Longest principal accepted anywhere (text form).
const MAX_LEN: usize = 512;

impl Principal {
    /// Parse `a/b@REALM` (MIT's escapes `\/`, `\@` and `\\` understood).
    /// The realm is required.
    pub fn parse(raw: &str) -> Result<Principal, String> {
        let raw = raw.trim();
        if raw.is_empty() || raw.len() > MAX_LEN {
            return Err("must be 1-512 characters".into());
        }
        let mut components = vec![String::new()];
        let mut realm: Option<String> = None;
        let mut chars = raw.chars();
        while let Some(c) = chars.next() {
            let ch = match c {
                '\\' => chars.next().ok_or("ends with a lone backslash")?,
                '/' if realm.is_none() => {
                    components.push(String::new());
                    continue;
                }
                '@' if realm.is_none() => {
                    realm = Some(String::new());
                    continue;
                }
                '@' => return Err("has more than one unescaped @".into()),
                c => c,
            };
            if ch.is_control() {
                return Err("contains a control character".into());
            }
            match &mut realm {
                Some(r) => r.push(ch),
                None => components.last_mut().expect("never empty").push(ch),
            }
        }
        let realm = realm.ok_or("needs a realm: name@REALM")?;
        if realm.is_empty() {
            return Err("has an empty realm".into());
        }
        if components.iter().any(String::is_empty) {
            return Err("has an empty name component".into());
        }
        Ok(Principal { components, realm })
    }

    /// The name without the realm, components joined by `/`.
    pub fn name(&self) -> String {
        self.components.join("/")
    }

    /// Case-insensitive comparison (Active Directory's rule; MIT is
    /// case-sensitive, but an acceptor matching its own service name
    /// loosely lets nothing extra in: the ticket must still decrypt with
    /// that service's key).
    pub fn eq_ignore_case(&self, other: &Principal) -> bool {
        self.realm.eq_ignore_ascii_case(&other.realm)
            && self.components.len() == other.components.len()
            && self
                .components
                .iter()
                .zip(&other.components)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

fn escape(out: &mut fmt::Formatter<'_>, s: &str) -> fmt::Result {
    for c in s.chars() {
        if matches!(c, '/' | '@' | '\\') {
            out.write_str("\\")?;
        }
        write!(out, "{c}")?;
    }
    Ok(())
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, c) in self.components.iter().enumerate() {
            if i > 0 {
                f.write_str("/")?;
            }
            escape(f, c)?;
        }
        f.write_str("@")?;
        escape(f, &self.realm)
    }
}

/// Check and normalize a realm name as an administrator types it: realms
/// are compared case-insensitively and shown upper-case.
pub fn normalize_realm(raw: &str) -> Result<String, String> {
    let r = raw.trim();
    if r.is_empty() || r.len() > 255 {
        return Err("realms are 1-255 characters".into());
    }
    if r.chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '@' | '/' | '\\'))
    {
        return Err(format!("`{r}` is not a realm name"));
    }
    Ok(r.to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_prints() {
        let p = Principal::parse("HTTP/sso.example.com@EXAMPLE.COM").unwrap();
        assert_eq!(p.components, ["HTTP", "sso.example.com"]);
        assert_eq!(p.realm, "EXAMPLE.COM");
        assert_eq!(p.to_string(), "HTTP/sso.example.com@EXAMPLE.COM");
        assert_eq!(p.name(), "HTTP/sso.example.com");

        let e = Principal::parse(r"a\/b\@c@R").unwrap();
        assert_eq!(e.components, ["a/b@c"]);
        assert_eq!(e.to_string(), r"a\/b\@c@R");
        assert_eq!(Principal::parse(&e.to_string()).unwrap(), e);

        assert!(
            Principal::parse("http/SSO.example.com@example.com")
                .unwrap()
                .eq_ignore_case(&p)
        );
    }

    #[test]
    fn refuses_bad_names() {
        for bad in [
            "", "alice", "alice@", "@R", "a//b@R", "a@b@R", "a\\", "a\u{7}@R",
        ] {
            assert!(Principal::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(normalize_realm(" example.com ").unwrap(), "EXAMPLE.COM");
        assert!(normalize_realm("EX AMPLE").is_err());
        assert!(normalize_realm("").is_err());
    }
}
