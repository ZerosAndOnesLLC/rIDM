//! The client's IP address behind an optional reverse proxy.
//!
//! `X-Forwarded-For` and `Forwarded` are honoured only when the TCP peer is
//! one of `TRUSTED_PROXIES`; otherwise the peer address is the client.
//!
//! The chain is read from the right, discarding entries that are themselves
//! trusted proxies, and the first address that is not is the client. A proxy
//! that appends rather than overwrites — which is what an AWS load balancer
//! and nginx's `$proxy_add_x_forwarded_for` both do — leaves whatever the
//! caller sent in the leftmost position, so taking that one would let any
//! caller choose the address that IP rules match, that rate-limit buckets
//! count against and that the audit trail records.

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;

use crate::state::AppState;

/// Client IP honouring forwarding headers only from trusted proxies.
pub fn client_ip(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Option<String> {
    client_ip_addr(state, headers, peer).map(|ip| ip.to_string())
}

pub fn client_ip_addr(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Option<IpAddr> {
    let peer_ip = peer.map(|p| p.ip());
    let trusted = peer_ip.is_some_and(|ip| {
        state
            .config
            .trusted_proxies
            .iter()
            .any(|net| net.contains(&ip))
    });
    if trusted {
        let is_proxy = |ip: &IpAddr| state.config.trusted_proxies.iter().any(|n| n.contains(ip));
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| rightmost_untrusted(forwarded_for_list(v), &is_proxy))
        {
            return Some(ip);
        }
        if let Some(ip) = headers
            .get("forwarded")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| rightmost_untrusted(forwarded_list(v), &is_proxy))
        {
            return Some(ip);
        }
    }
    peer_ip
}

/// The last address of a forwarded chain that is not itself a trusted proxy.
///
/// Every hop appends the address it received the request from, so the chain
/// reads client first and the nearest proxy last. Walking back over our own
/// proxies leaves the address the outermost one saw, which is the furthest
/// point an attacker cannot forge. An unparsable entry ends the walk: the
/// chain beyond it cannot be trusted to mean what it says.
fn rightmost_untrusted(
    chain: Vec<Option<IpAddr>>,
    is_proxy: &impl Fn(&IpAddr) -> bool,
) -> Option<IpAddr> {
    let mut last = None;
    for entry in chain.into_iter().rev() {
        let ip = entry?;
        if is_proxy(&ip) {
            last = Some(ip);
            continue;
        }
        return Some(ip);
    }
    // Every hop was a proxy of ours: the outermost is the best we know.
    last
}

/// The addresses of an `X-Forwarded-For` list, in order, unparsable ones as `None`.
fn forwarded_for_list(value: &str) -> Vec<Option<IpAddr>> {
    value.split(',').map(|s| parse_node(s.trim())).collect()
}

/// The `for=` parameter of each element of an RFC 7239 `Forwarded` header.
fn forwarded_list(value: &str) -> Vec<Option<IpAddr>> {
    value
        .split(',')
        .map(|element| {
            element.split(';').find_map(|pair| {
                let (k, v) = pair.trim().split_once('=')?;
                if !k.trim().eq_ignore_ascii_case("for") {
                    return None;
                }
                parse_node(v.trim().trim_matches('"'))
            })
        })
        .collect()
}

/// An address as it appears in forwarding headers: bare, `[v6]`, or with a port.
fn parse_node(node: &str) -> Option<IpAddr> {
    if let Ok(ip) = node.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Some(rest) = node.strip_prefix('[') {
        let end = rest.find(']')?;
        return rest[..end].parse().ok();
    }
    // `host:port` for IPv4.
    let (host, _port) = node.rsplit_once(':')?;
    host.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for `TRUSTED_PROXIES`: the 10/8 hops are ours.
    fn ours(ip: &IpAddr) -> bool {
        matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 10)
    }

    #[test]
    fn forwarded_header_forms() {
        let one = |v: &str| rightmost_untrusted(forwarded_list(v), &ours);
        assert_eq!(
            one("for=192.0.2.60;proto=http;by=203.0.113.43"),
            Some("192.0.2.60".parse().unwrap())
        );
        assert_eq!(
            one("for=\"[2001:db8::1]:4711\""),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(one("proto=https"), None);
        assert_eq!(one("for=_hidden"), None);
        // The last element is one of ours, so the one before it is the client.
        assert_eq!(
            one("For=198.51.100.17:1234, for=10.0.0.1"),
            Some("198.51.100.17".parse().unwrap())
        );
    }

    #[test]
    fn the_client_is_the_rightmost_address_that_is_not_ours() {
        let one = |v: &str| rightmost_untrusted(forwarded_for_list(v), &ours);
        // One proxy, appending: the caller's own entry comes first and loses.
        assert_eq!(
            one("203.0.113.9, 198.51.100.7"),
            Some("198.51.100.7".parse().unwrap())
        );
        // Our own hops are walked back over.
        assert_eq!(
            one("198.51.100.7, 10.0.0.2, 10.0.0.3"),
            Some("198.51.100.7".parse().unwrap())
        );
        // A single entry from our proxy is the client.
        assert_eq!(one("203.0.113.9"), Some("203.0.113.9".parse().unwrap()));
        // Nothing but our own hops: the outermost is the best we know.
        assert_eq!(one("10.0.0.2, 10.0.0.3"), Some("10.0.0.2".parse().unwrap()));
        // An unparsable entry ends the walk rather than letting the chain
        // beyond it speak: a caller could otherwise hide behind junk.
        assert_eq!(one("203.0.113.9, unknown"), None);
        assert_eq!(one("unknown"), None);
        assert_eq!(one(""), None);
    }
}
