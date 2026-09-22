//! Kerberos / SPNEGO: whatever a browser (or anyone) sends in an
//! `Authorization: Negotiate` header, and the keytab an administrator
//! uploads. Nothing may panic. Raw input is never a ticket rIDM accepts:
//! it is checked against a service key nobody else has. The first byte may
//! instead ask for a real ticket from that key with the rest of the input
//! spliced into it; whatever of that is accepted must still name the
//! client the ticket was issued to.
#![no_main]

use std::sync::OnceLock;

use chrono::{Duration, Utc};
use libfuzzer_sys::fuzz_target;
use ridm_api::kerberos::testing::Kdc;
use ridm_api::kerberos::{self, Acceptor, Principal, spnego};

const SERVICE: &str = "HTTP/sso.example.com@EXAMPLE.COM";

fn kdc() -> &'static (Kdc, Vec<u8>) {
    static KDC: OnceLock<(Kdc, Vec<u8>)> = OnceLock::new();
    KDC.get_or_init(|| {
        let kdc = Kdc::new(SERVICE);
        let mut req = kdc.request("alice@EXAMPLE.COM");
        req.end_time = Utc::now() + Duration::days(3650);
        req.ctime = Utc::now();
        let token = kdc.negotiate_token(&req).expect("token").0;
        (kdc, token)
    })
}

fn accept(ap_req: &[u8]) -> Option<String> {
    let (kdc, _) = kdc();
    let keys = [kdc.entry()];
    let realms = ["EXAMPLE.COM".to_string()];
    Acceptor {
        keys: &keys,
        service: &kdc.service,
        realms: &realms,
        // Wide enough that the spliced ticket's authenticator stays fresh
        // for the whole run.
        max_skew: Duration::days(3650),
        now: Utc::now(),
    }
    .accept(ap_req)
    .ok()
    .map(|a| a.client.to_string())
}

fn token(data: &[u8]) -> Option<String> {
    match spnego::parse(data) {
        Ok(spnego::Negotiated::Kerberos(offer)) => {
            let _ = kerberos::service_of(&offer.ap_req);
            let _ = spnego::answer(&offer, Some(&offer.ap_req));
            accept(&offer.ap_req)
        }
        _ => None,
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = kerberos::parse_keytab(data);
    let _ = Principal::parse(&String::from_utf8_lossy(data));
    let _ = spnego::ap_rep_of_answer(data);
    match data.split_first() {
        Some((0xfe, rest)) if rest.len() >= 2 => {
            // Splice the rest into a real token at the offset it names.
            let (_, real) = kdc();
            let at = usize::from(u16::from_be_bytes([rest[0], rest[1]])) % real.len();
            let mut t = real.clone();
            let patch = &rest[2..];
            let end = (at + patch.len()).min(t.len());
            t[at..end].copy_from_slice(&patch[..end - at]);
            if let Some(who) = token(&t) {
                assert_eq!(
                    who, "alice@EXAMPLE.COM",
                    "a changed ticket named another client"
                );
            }
        }
        _ => {
            assert!(token(data).is_none(), "raw input was accepted as a ticket");
            assert!(
                accept(data).is_none(),
                "raw input was accepted as an AP-REQ"
            );
        }
    }
});
