//! `/authorize` query and form parsing: anything a browser can put in a URL
//! reaches `RawParams`, and the error page escapes whatever comes back out.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ridm_api::oidc::authorize::{RawParams, html_escape};

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    let params = RawParams::parse(raw);
    for name in [
        "client_id",
        "redirect_uri",
        "response_type",
        "response_mode",
        "scope",
        "state",
        "nonce",
        "prompt",
        "display",
        "max_age",
        "ui_locales",
        "acr_values",
        "login_hint",
        "id_token_hint",
        "code_challenge",
        "code_challenge_method",
        "request",
        "request_uri",
        "claims",
    ] {
        // Repeated parameters are an error, never a panic.
        let _ = params.one(name);
    }
    let _ = params.many("resource");
    // The values that get parsed further on their own.
    let _ = ridm_api::services::scopes::parse_scope_param(raw);
    let _ = ridm_api::services::login_flows::ResponseMode::parse(raw);
    // Whatever is echoed back reaches the error page escaped.
    let escaped = html_escape(raw);
    assert!(!escaped.contains('<'));
    assert!(!escaped.contains('>'));
});
