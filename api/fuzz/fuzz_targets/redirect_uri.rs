#![no_main]
//! Redirect URI matching must never panic, and must never match a URI that
//! is not byte-identical to a registration for non-native clients.
use libfuzzer_sys::fuzz_target;
use ridm_api::models::ClientType;
use ridm_api::oidc::redirect_uri;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let registered = vec!["https://app.example/cb".to_string(), "http://127.0.0.1/cb".to_string(), "com.example.app:/oauth".to_string()];
    for ct in [ClientType::Web, ClientType::Spa, ClientType::Native, ClientType::Machine, ClientType::Device] {
        let m = redirect_uri::matches(&registered, s, ct);
        if ct != ClientType::Native {
            assert_eq!(m, registered.iter().any(|r| r == s), "non-native must be exact: {s:?}");
        }
    }
});
