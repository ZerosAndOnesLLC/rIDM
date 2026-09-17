//! SCIM filter parsing and evaluation (RFC 7644 §3.4.2.2): a provisioning
//! client's filter string reaches the parser, and the parsed filter is
//! evaluated over a SCIM document.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ridm_api::services::scim;
use serde_json::json;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(filter) = scim::parse_filter(s) else {
        return;
    };
    let doc = json!({
        "id": "6f1c1d4e-0000-4000-8000-000000000000",
        "userName": "BJensen",
        "externalId": "ext-1",
        "active": true,
        "name": { "givenName": "Barbara", "familyName": "Jensen" },
        "emails": [
            { "value": "bj@example.com", "type": "work", "primary": true },
            { "value": "barb@example.org", "type": "home" }
        ],
        "members": [{ "value": "1" }, { "value": "2" }],
        "meta": { "resourceType": "User" }
    });
    let _ = scim::matches(&filter, &doc);
    // An empty document answers every filter without panicking.
    let _ = scim::matches(&filter, &json!({}));
});
