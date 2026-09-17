//! Redirect URI matching (OAuth 2.0 Security BCP §4.1.3, RFC 8252 §7.3).
//! Lines before the first blank line are the registered URIs; the rest is the
//! requested one. A match must be exact, except for a native client's
//! loopback port.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ridm_api::models::ClientType;
use ridm_api::oidc::redirect_uri;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let (head, requested) = s.split_once("\n\n").unwrap_or((s, ""));
    let mut registered: Vec<String> = head.lines().map(str::to_owned).collect();
    if registered.is_empty() {
        // The shapes a real client registers, so the requested URI is matched
        // against something even when the input carries no registration.
        registered = vec![
            "https://app.example/cb".into(),
            "http://127.0.0.1/cb".into(),
            "com.example.app:/oauth".into(),
        ];
    }
    for client_type in [
        ClientType::Spa,
        ClientType::Web,
        ClientType::Native,
        ClientType::Machine,
        ClientType::Device,
    ] {
        let matched = redirect_uri::matches(&registered, requested, client_type);
        // Anything but a native loopback redirect matches only by string.
        let exact = registered.iter().any(|r| r == requested);
        if client_type != ClientType::Native {
            assert_eq!(matched, exact);
        } else if matched && !exact {
            // The one inexact match RFC 8252 §7.3 allows: a native client's
            // loopback redirect, where only the port may differ.
            let parsed = url::Url::parse(requested).expect("an inexact match must be a URL");
            assert_eq!(
                parsed.scheme(),
                "http",
                "non-http redirect matched without an exact registration: {requested}"
            );
            assert!(
                matches!(parsed.host_str(), Some("127.0.0.1" | "::1" | "[::1]" | "localhost")),
                "non-loopback redirect matched without an exact registration: {requested}"
            );
        }
    }
    // No registration matches nothing.
    assert!(!redirect_uri::matches(&[], requested, ClientType::Native));
});
