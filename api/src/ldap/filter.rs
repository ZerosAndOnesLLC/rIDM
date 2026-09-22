//! Search filters and the names in them. Every value a user or a directory
//! supplies goes into a filter through [`eq`] (RFC 4515 escaping), so an
//! identifier such as `*` or `x)(uid=*` matches only itself. Filters and
//! attribute names an administrator writes are checked when they are saved.

/// An equality assertion `(attr=value)` with the value escaped.
pub fn eq(attribute: &str, value: &str) -> String {
    format!("({attribute}={})", ldap3::ldap_escape(value))
}

/// An equality assertion on a binary value (an `objectGUID`): every byte
/// escaped as `\xx`.
pub fn eq_bytes(attribute: &str, value: &[u8]) -> String {
    let mut out = format!("({attribute}=");
    for b in value {
        out.push_str(&format!("\\{b:02x}"));
    }
    out.push(')');
    out
}

/// `(&a b …)`; a single part is returned as it is.
pub fn and(parts: &[String]) -> String {
    match parts {
        [one] => one.clone(),
        _ => format!("(&{})", parts.concat()),
    }
}

/// `(|a b …)`; a single part is returned as it is.
pub fn or(parts: &[String]) -> String {
    match parts {
        [one] => one.clone(),
        _ => format!("(|{})", parts.concat()),
    }
}

/// `(attr>=value)` with the value escaped (incremental sync).
pub fn ge(attribute: &str, value: &str) -> String {
    format!("({attribute}>={})", ldap3::ldap_escape(value))
}

/// A filter an administrator wrote: parenthesized, at most 1024 bytes, and
/// well-formed by the client's own parser.
pub fn check_filter(filter: &str) -> Result<(), String> {
    let f = filter.trim();
    if f.is_empty() || f.len() > 1024 {
        return Err("must be 1-1024 characters".into());
    }
    if !(f.starts_with('(') && f.ends_with(')')) {
        return Err("must be enclosed in parentheses, like `(objectClass=person)`".into());
    }
    ldap3::parse_filter(f)
        .map(|_| ())
        .map_err(|_| "is not a valid LDAP filter".into())
}

/// An attribute description: a name (`givenName`, `sAMAccountName`) or a
/// numeric OID, as RFC 4512 allows.
pub fn check_attribute(name: &str) -> Result<(), String> {
    let ok_name = name.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    let ok_oid = !name.is_empty()
        && name
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.len() <= 10);
    if name.len() <= 64 && (ok_name || ok_oid) {
        Ok(())
    } else {
        Err(format!("`{name}` is not an LDAP attribute name"))
    }
}

/// A distinguished name an administrator wrote: 1-1024 characters, no
/// control characters. (The directory itself says whether it exists.)
pub fn check_dn(dn: &str) -> Result<(), String> {
    let d = dn.trim();
    if d.is_empty() || d.len() > 1024 {
        return Err("must be 1-1024 characters".into());
    }
    if d.chars().any(char::is_control) || !d.contains('=') {
        return Err("is not a distinguished name, like `ou=people,dc=example,dc=org`".into());
    }
    Ok(())
}

/// The sortable part of a generalized time (`20260922120000Z`,
/// `20260922120000.0Z`): its 14 digits, or `None` when it has none.
pub fn generalized_time_key(value: &str) -> Option<&str> {
    let digits = value.get(..14)?;
    digits.bytes().all(|b| b.is_ascii_digit()).then_some(digits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_escaped_so_an_identifier_matches_only_itself() {
        assert_eq!(eq("uid", "alice"), "(uid=alice)");
        assert_eq!(eq("uid", "*"), "(uid=\\2a)");
        assert_eq!(eq("uid", "x)(uid=*"), "(uid=x\\29\\28uid=\\2a)");
        assert_eq!(eq("cn", "a\\b"), "(cn=a\\5cb)");
        assert_eq!(eq("cn", "nul\0"), "(cn=nul\\00)");
        assert_eq!(
            eq_bytes("objectGUID", &[0x0f, 0xa0]),
            "(objectGUID=\\0f\\a0)"
        );
    }

    #[test]
    fn composition() {
        let one = vec![eq("uid", "a")];
        assert_eq!(and(&one), "(uid=a)");
        assert_eq!(or(&[eq("uid", "a"), eq("mail", "a")]), "(|(uid=a)(mail=a))");
        assert_eq!(
            and(&[
                "(objectClass=person)".into(),
                ge("modifyTimestamp", "20260101000000Z")
            ]),
            "(&(objectClass=person)(modifyTimestamp>=20260101000000Z))"
        );
    }

    #[test]
    fn administrator_input_is_checked() {
        assert!(check_filter("(objectClass=inetOrgPerson)").is_ok());
        assert!(check_filter("(&(objectCategory=person)(objectClass=user))").is_ok());
        assert!(check_filter("objectClass=person").is_err());
        assert!(check_filter("(objectClass=person").is_err());
        assert!(check_filter("").is_err());
        assert!(check_attribute("sAMAccountName").is_ok());
        assert!(check_attribute("2.5.4.3").is_ok());
        assert!(check_attribute("given name").is_err());
        assert!(check_attribute("uid)(x").is_err());
        assert!(check_attribute("").is_err());
        assert!(check_dn("ou=people,dc=example,dc=org").is_ok());
        assert!(check_dn("people").is_err());
        assert!(check_dn("ou=a\nb").is_err());
    }

    #[test]
    fn generalized_times_sort_by_their_digits() {
        assert_eq!(
            generalized_time_key("20260922120000.0Z"),
            Some("20260922120000")
        );
        assert_eq!(
            generalized_time_key("20260922120000Z"),
            Some("20260922120000")
        );
        assert_eq!(generalized_time_key("garbage"), None);
    }
}
