#![no_main]
//! JOSE header parsing and the master-key blob parser must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ridm_core::providers::Encrypted::from_bytes(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = jsonwebtoken::decode_header(s);
        let _ = ridm_api::util::cursor::Cursor::decode(s);
        let _ = ridm_api::services::password::legacy::verify(b"pw", s);
    }
});
