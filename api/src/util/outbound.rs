//! Outbound requests to URLs someone other than the operator chose (webhook
//! targets, back-channel logout URIs, client `jwks_uri`s, upstream identity
//! providers, a tenant's HTTP email/SMS gateway, SMTP server or CAPTCHA
//! endpoint) must not reach this server's own network (SSRF).
//!
//! Checking the URL when it is saved is not enough: a public name can resolve
//! to a private address at delivery time (DNS rebinding). So the check sits
//! where the connection is made:
//!
//! * names go through [`PublicResolver`], a reqwest DNS resolver that drops
//!   every non-public address and fails when none is left;
//! * IP literals never reach a resolver, so [`check_url`] refuses private
//!   ones before the request is sent;
//! * connections made outside reqwest (a tenant's SMTP server) resolve with
//!   [`resolve_public`] and connect to the address it vetted.
//!
//! Loopback stays allowed when it is named as such (`localhost`, `127.0.0.0/8`,
//! `::1`): the development allowance the URL validators already make for
//! plain-http loopback targets. Any other name that resolves to loopback is
//! refused like any other private address.
//!
//! The operator can open private networks with `OUTBOUND_ALLOW_NETWORKS`
//! ([`allow_networks`], called once at startup): an internal application's
//! back-channel logout endpoint or an internal webhook receiver lives on one.
//! Addresses inside those networks are treated as public, literal or resolved.
//!
//! Clients built here ignore `HTTP(S)_PROXY`: a proxy would resolve the target
//! itself, out of this check's sight.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};

use ipnet::IpNet;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Networks the operator opened (`OUTBOUND_ALLOW_NETWORKS`).
static ALLOWED_NETWORKS: OnceLock<Vec<IpNet>> = OnceLock::new();

/// Open `networks` to outbound requests for the life of the process. The
/// first call wins: the configuration is read once, at startup.
pub fn allow_networks(networks: &[IpNet]) {
    let _ = ALLOWED_NETWORKS.set(networks.to_vec());
}

/// May a request to someone else's URL reach `ip`? A public address, or one
/// inside a network the operator opened.
pub fn is_permitted(ip: IpAddr) -> bool {
    permitted_in(ip, ALLOWED_NETWORKS.get().map_or(&[], Vec::as_slice))
}

fn permitted_in(ip: IpAddr, opened: &[IpNet]) -> bool {
    is_public(ip) || opened.iter().any(|n| n.contains(&ip))
}

/// Is `ip` an address on the public internet? Private, loopback,
/// link-local, unspecified, multicast, broadcast, carrier-grade NAT,
/// unique-local, documentation, benchmarking and reserved ranges are not,
/// nor is an IPv6 address that embeds one of them (IPv4-mapped,
/// IPv4-compatible, NAT64 and 6to4 forms).
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        // 100.64.0.0/10, carrier-grade NAT (RFC 6598).
        || (a == 100 && (64..128).contains(&b))
        // 192.0.0.0/24, IETF protocol assignments (RFC 6890).
        || (a == 192 && b == 0 && c == 0)
        // 198.18.0.0/15, benchmarking (RFC 2544).
        || (a == 198 && (b == 18 || b == 19))
        // 240.0.0.0/4, reserved.
        || a >= 240)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = embedded_v4(ip) {
        return is_public_v4(v4);
    }
    let s = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        // fc00::/7, unique local.
        || (s[0] & 0xfe00) == 0xfc00
        // fe80::/10, link-local; fec0::/10, deprecated site-local.
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xffc0) == 0xfec0
        // 2001:db8::/32, documentation.
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        // 100::/64, discard only.
        || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0))
}

/// The IPv4 address an IPv6 address stands for, when it is one of the forms
/// that reach an IPv4 host: IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible
/// (`::a.b.c.d`), NAT64 (`64:ff9b::a.b.c.d`) and 6to4 (`2002:ab:cd::`).
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = ip.segments();
    let low =
        |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
    if s[..6].iter().all(|x| *x == 0) && !(s[6] == 0 && s[7] <= 1) {
        return Some(low(s[6], s[7]));
    }
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6].iter().all(|x| *x == 0) {
        return Some(low(s[6], s[7]));
    }
    if s[0] == 0x2002 {
        return Some(low(s[1], s[2]));
    }
    None
}

/// The loopback development allowance: a host literally named `localhost`
/// may resolve to loopback, and loopback literals are allowed as they are.
fn is_loopback_name(host: &str) -> bool {
    host.trim_end_matches('.').eq_ignore_ascii_case("localhost")
}

/// Keep the addresses a connection to `host` may use: permitted ones
/// ([`is_permitted`]), plus loopback when `host` is `localhost`.
pub fn allowed_addrs(host: &str, addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let loopback_ok = is_loopback_name(host);
    addrs
        .into_iter()
        .filter(|a| is_permitted(a.ip()) || (loopback_ok && a.ip().is_loopback()))
        .collect()
}

/// Refuse a URL whose host is an IP literal [`is_permitted`] refuses
/// (loopback excepted).
/// Hostnames pass here; [`PublicResolver`] checks what they resolve to.
pub fn check_url(raw: &str) -> Result<(), String> {
    let u = url::Url::parse(raw).map_err(|_| format!("`{raw}` is not a valid URL"))?;
    let ip = match u.host() {
        Some(url::Host::Ipv4(v4)) => IpAddr::V4(v4),
        Some(url::Host::Ipv6(v6)) => IpAddr::V6(v6),
        Some(url::Host::Domain(_)) => return Ok(()),
        None => return Err(format!("`{raw}` has no host")),
    };
    if is_permitted(ip) || ip.is_loopback() {
        Ok(())
    } else {
        Err(format!(
            "`{ip}` is a private, link-local or reserved address"
        ))
    }
}

/// Is `host` (a bare hostname or IP literal, as an SMTP host is configured)
/// refused outright? Only non-public IP literals are, loopback excepted, the
/// same rule [`check_url`] applies to a URL's host.
pub fn check_host(host: &str) -> Result<(), String> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<IpAddr>() {
        Ok(ip) if !(is_permitted(ip) || ip.is_loopback()) => Err(format!(
            "`{ip}` is a private, link-local or reserved address"
        )),
        _ => Ok(()),
    }
}

/// Resolve `host:port` for a connection that is not made through reqwest
/// (a tenant's SMTP server) and return one address the policy allows: an IP
/// literal must pass [`check_host`], a name keeps what [`allowed_addrs`]
/// keeps. The caller connects to the returned address itself, so a second
/// lookup cannot swap in a private one (DNS rebinding).
pub async fn resolve_public(host: &str, port: u16) -> Result<SocketAddr, String> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        check_host(bare)?;
        return Ok(SocketAddr::new(ip, port));
    }
    let resolved = tokio::net::lookup_host((bare, port))
        .await
        .map_err(|e| format!("cannot resolve `{bare}`: {e}"))?;
    allowed_addrs(bare, resolved)
        .into_iter()
        .next()
        .ok_or_else(|| format!("`{bare}` resolves only to private, loopback or reserved addresses"))
}

/// A reqwest resolver that resolves with the system resolver (through tokio)
/// and hands the connector only addresses [`allowed_addrs`] keeps.
#[derive(Debug, Clone, Copy, Default)]
pub struct PublicResolver;

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let kept = allowed_addrs(&host, resolved);
            if kept.is_empty() {
                return Err(format!(
                    "`{host}` resolves only to private, loopback or reserved addresses"
                )
                .into());
            }
            let addrs: Addrs = Box::new(kept.into_iter());
            Ok(addrs)
        })
    }
}

/// A client builder for requests to someone else's URL: public addresses
/// only, no redirects (a redirect would be a second, unchecked target), no
/// environment proxy.
pub fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .dns_resolver(Arc::new(PublicResolver))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
}

/// A request error with its causes: reqwest's own message names the URL
/// only, the reason (a refused resolution, a TLS failure) is in the chain.
pub fn describe(err: &reqwest::Error) -> String {
    let mut out = err.to_string();
    let mut source = std::error::Error::source(err);
    while let Some(e) = source {
        let text = e.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = e.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn private_and_reserved_addresses_are_not_public() {
        for s in [
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "127.0.0.1",
            "127.8.9.10",
            "169.254.169.254",
            "0.0.0.0",
            "0.1.2.3",
            "255.255.255.255",
            "224.0.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "198.18.0.1",
            "240.0.0.1",
            "::",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::10.0.0.1",
            "64:ff9b::a00:1",
            "2002:c0a8:101::",
            "2002:7f00:1::",
        ] {
            assert!(!is_public(ip(s)), "{s} must not count as public");
        }
    }

    #[test]
    fn public_addresses_are_public() {
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "100.63.255.255",
            "100.128.0.1",
            "172.32.0.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:808:808::",
        ] {
            assert!(is_public(ip(s)), "{s} is public");
        }
    }

    #[test]
    fn opened_networks_are_permitted_and_nothing_else() {
        let opened: Vec<IpNet> = vec![
            "10.1.0.0/16".parse().unwrap(),
            "fd00::1/128".parse().unwrap(),
        ];
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(permitted_in(ip("10.1.1.130"), &opened));
        assert!(permitted_in(ip("fd00::1"), &opened));
        assert!(!permitted_in(ip("10.2.0.1"), &opened));
        assert!(!permitted_in(ip("fd00::2"), &opened));
        assert!(!permitted_in(ip("10.1.1.130"), &[]));
        assert!(permitted_in(ip("93.184.215.14"), &[]));
    }

    #[test]
    fn only_localhost_may_resolve_to_loopback() {
        let addrs = |list: &[&str]| -> Vec<SocketAddr> {
            list.iter().map(|s| SocketAddr::new(ip(s), 443)).collect()
        };
        let mixed = addrs(&["127.0.0.1", "::1", "10.0.0.5", "93.184.216.34"]);
        assert_eq!(
            allowed_addrs("example.com", mixed.clone()),
            addrs(&["93.184.216.34"])
        );
        assert_eq!(
            allowed_addrs("localhost", mixed.clone()),
            addrs(&["127.0.0.1", "::1", "93.184.216.34"])
        );
        assert_eq!(allowed_addrs("LocalHost.", addrs(&["127.0.0.1"])).len(), 1);
        // A name that only looks local is judged by where it points.
        assert!(allowed_addrs("foo.localhost", addrs(&["127.0.0.1"])).is_empty());
        assert!(allowed_addrs("localtest.me", addrs(&["127.0.0.1"])).is_empty());
        // Private addresses stay out even for localhost.
        assert!(allowed_addrs("localhost", addrs(&["10.0.0.5"])).is_empty());
    }

    #[test]
    fn literal_urls_are_checked_before_sending() {
        assert!(check_url("https://93.184.216.34/hook").is_ok());
        assert!(check_url("https://hooks.example.com/x").is_ok());
        assert!(check_url("http://127.0.0.1:8080/x").is_ok());
        assert!(check_url("http://[::1]:8080/x").is_ok());
        for bad in [
            "https://10.0.0.1/x",
            "https://169.254.169.254/latest/meta-data",
            "https://[fd00::1]/x",
            "https://[::ffff:10.0.0.1]/x",
            "https://0.0.0.0/x",
            "https://100.64.0.1/x",
        ] {
            assert!(check_url(bad).is_err(), "{bad} must be refused");
        }
        assert!(check_url("not a url").is_err());
    }

    #[tokio::test]
    async fn localhost_keeps_the_development_allowance() {
        let addrs = PublicResolver
            .resolve("localhost".parse().unwrap())
            .await
            .expect("localhost resolves");
        let addrs: Vec<SocketAddr> = addrs.collect();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.ip().is_loopback()));
    }
}
