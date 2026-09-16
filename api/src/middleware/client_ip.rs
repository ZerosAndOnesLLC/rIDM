//! The client's IP address behind an optional reverse proxy.
//!
//! `X-Forwarded-For` and `Forwarded` are honoured only when the TCP peer is
//! one of `TRUSTED_PROXIES`; otherwise the peer address is the client. The
//! first (leftmost) forwarded address is taken, so the proxy must overwrite
//! or reset the header rather than append to a client-supplied one.

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
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(first_forwarded_for)
        {
            return Some(ip);
        }
        if let Some(ip) = headers
            .get("forwarded")
            .and_then(|v| v.to_str().ok())
            .and_then(forwarded_for)
        {
            return Some(ip);
        }
    }
    peer_ip
}

/// Leftmost address of an `X-Forwarded-For` list.
fn first_forwarded_for(value: &str) -> Option<IpAddr> {
    value.split(',').next().and_then(|s| parse_node(s.trim()))
}

/// The `for=` parameter of the first element of an RFC 7239 `Forwarded` header.
fn forwarded_for(value: &str) -> Option<IpAddr> {
    let first = value.split(',').next()?;
    first.split(';').find_map(|pair| {
        let (k, v) = pair.trim().split_once('=')?;
        if !k.trim().eq_ignore_ascii_case("for") {
            return None;
        }
        parse_node(v.trim().trim_matches('"'))
    })
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

    #[test]
    fn forwarded_header_forms() {
        assert_eq!(
            forwarded_for("for=192.0.2.60;proto=http;by=203.0.113.43"),
            Some("192.0.2.60".parse().unwrap())
        );
        assert_eq!(
            forwarded_for("for=\"[2001:db8::1]:4711\""),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            forwarded_for("For=198.51.100.17:1234, for=10.0.0.1"),
            Some("198.51.100.17".parse().unwrap())
        );
        assert_eq!(forwarded_for("proto=https"), None);
        assert_eq!(forwarded_for("for=_hidden"), None);
    }

    #[test]
    fn x_forwarded_for_takes_the_first_address() {
        assert_eq!(
            first_forwarded_for("203.0.113.9, 10.0.0.2"),
            Some("203.0.113.9".parse().unwrap())
        );
        assert_eq!(first_forwarded_for("unknown, 10.0.0.2"), None);
    }
}
