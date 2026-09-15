#![no_main]
//! The raw authorization-request parser must never panic on any query string.
use libfuzzer_sys::fuzz_target;
use ridm_api::oidc::authorize::RawParams;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let p = RawParams::parse(s);
        for name in ["client_id", "redirect_uri", "scope", "state", "nonce", "prompt", "claims", "resource", "request", "request_uri", "code_challenge", "code_challenge_method", "response_mode", "max_age"] {
            let _ = p.one(name);
            let _ = p.many(name);
        }
        let _ = ridm_api::services::scopes::parse_scope_param(s);
        let _ = ridm_api::services::login_flows::ResponseMode::parse(s);
    }
});
