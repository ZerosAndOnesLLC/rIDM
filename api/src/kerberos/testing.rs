//! A Kerberos key distribution center in miniature, for tests and the fuzz
//! target: it knows a service key and issues AP-REQs for that service the
//! way a real KDC plus client would (a ticket in the service key, an
//! authenticator in the session key), with every field adjustable so tests
//! can build the bad ones too. Nothing in the server calls it.

use chrono::{DateTime, Duration, Utc};
use zeroize::Zeroizing;

use super::Principal;
use super::acceptor::{USAGE_AP_REP, USAGE_AUTHENTICATOR, USAGE_TICKET};
use super::crypto::{self, CryptoError};
use super::der::{self, Reader};
use super::keytab::{ETYPE_AES256, KeytabEntry, write_keytab};
use super::spnego::{self, Mech};

/// A service with its long-term key.
#[derive(Clone)]
pub struct Kdc {
    pub service: Principal,
    pub kvno: u32,
    pub etype: i32,
    pub key: Zeroizing<Vec<u8>>,
}

/// Everything about one AP-REQ; [`Kdc::request`] fills in the defaults.
#[derive(Clone)]
pub struct Request {
    pub client: Principal,
    /// The client the authenticator names (the ticket's by default).
    pub authenticator_client: Option<Principal>,
    pub auth_time: DateTime<Utc>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: DateTime<Utc>,
    pub ctime: DateTime<Utc>,
    /// Ask for mutual authentication in the GSS checksum.
    pub mutual: bool,
    /// Ticket flag INVALID.
    pub invalid: bool,
    /// Encrypt the ticket under this key instead of the service's.
    pub ticket_key: Option<Vec<u8>>,
    /// The service the ticket names (the KDC's by default).
    pub sname: Option<Principal>,
    pub kvno: Option<u32>,
}

/// A request's AP-REQ and the session key the client holds.
pub struct Issued {
    pub ap_req: Vec<u8>,
    pub session_key: Vec<u8>,
    pub ctime: DateTime<Utc>,
}

fn principal_name(p: &Principal) -> Vec<u8> {
    let names: Vec<Vec<u8>> = p
        .components
        .iter()
        .map(|c| der::tlv(der::GENERAL_STRING, c.as_bytes()))
        .collect();
    der::tlv(
        der::SEQUENCE,
        &der::concat(&[
            der::enc_explicit(0, der::enc_int(if p.components.len() > 1 { 2 } else { 1 })),
            der::enc_explicit(1, der::tlv(der::SEQUENCE, &der::concat(&names))),
        ]),
    )
}

fn encrypted(etype: i32, kvno: Option<u32>, cipher: &[u8]) -> Vec<u8> {
    let mut fields = vec![der::enc_explicit(0, der::enc_int(i64::from(etype)))];
    if let Some(v) = kvno {
        fields.push(der::enc_explicit(1, der::enc_int(i64::from(v))));
    }
    fields.push(der::enc_explicit(2, der::tlv(der::OCTET_STRING, cipher)));
    der::tlv(der::SEQUENCE, &der::concat(&fields))
}

fn bits(first: u8) -> Vec<u8> {
    der::tlv(der::BIT_STRING, &[0, first, 0, 0, 0])
}

impl Kdc {
    /// A service with a random AES-256 key.
    pub fn new(service: &str) -> Kdc {
        let mut key = vec![0u8; 32];
        rand::fill(&mut key[..]);
        Kdc {
            service: Principal::parse(service).expect("service principal"),
            kvno: 2,
            etype: ETYPE_AES256,
            key: Zeroizing::new(key),
        }
    }

    pub fn entry(&self) -> KeytabEntry {
        KeytabEntry {
            principal: self.service.clone(),
            kvno: self.kvno,
            etype: self.etype,
            key: self.key.clone(),
        }
    }

    /// The service's keytab file.
    pub fn keytab(&self) -> Vec<u8> {
        write_keytab(&[self.entry()])
    }

    /// A good request from `client` (`alice@EXAMPLE.COM`).
    pub fn request(&self, client: &str) -> Request {
        let now = Utc::now();
        Request {
            client: Principal::parse(client).expect("client principal"),
            authenticator_client: None,
            auth_time: now - Duration::minutes(5),
            start_time: None,
            end_time: now + Duration::hours(8),
            ctime: now,
            mutual: true,
            invalid: false,
            ticket_key: None,
            sname: None,
            kvno: Some(self.kvno),
        }
    }

    /// Build the AP-REQ.
    pub fn issue(&self, req: &Request) -> Result<Issued, CryptoError> {
        let mut session_key = vec![0u8; 32];
        rand::fill(&mut session_key[..]);
        let mut part = vec![
            der::enc_explicit(0, bits(if req.invalid { 0x01 } else { 0x40 })),
            der::enc_explicit(
                1,
                der::tlv(
                    der::SEQUENCE,
                    &der::concat(&[
                        der::enc_explicit(0, der::enc_int(i64::from(ETYPE_AES256))),
                        der::enc_explicit(1, der::tlv(der::OCTET_STRING, &session_key)),
                    ]),
                ),
            ),
            der::enc_explicit(
                2,
                der::tlv(der::GENERAL_STRING, req.client.realm.as_bytes()),
            ),
            der::enc_explicit(3, principal_name(&req.client)),
            der::enc_explicit(
                4,
                der::tlv(
                    der::SEQUENCE,
                    &der::concat(&[
                        der::enc_explicit(0, der::enc_int(1)),
                        der::enc_explicit(1, der::tlv(der::OCTET_STRING, b"")),
                    ]),
                ),
            ),
            der::enc_explicit(5, der::enc_time(req.auth_time)),
        ];
        if let Some(s) = req.start_time {
            part.push(der::enc_explicit(6, der::enc_time(s)));
        }
        part.push(der::enc_explicit(7, der::enc_time(req.end_time)));
        let enc_part = der::tlv(der::app(3), &der::tlv(der::SEQUENCE, &der::concat(&part)));
        let ticket_key = req.ticket_key.as_deref().unwrap_or(&self.key);
        let ticket_cipher = crypto::encrypt(self.etype, ticket_key, USAGE_TICKET, &enc_part)?;
        let sname = req.sname.as_ref().unwrap_or(&self.service);
        let ticket = der::tlv(
            der::app(1),
            &der::tlv(
                der::SEQUENCE,
                &der::concat(&[
                    der::enc_explicit(0, der::enc_int(5)),
                    der::enc_explicit(1, der::tlv(der::GENERAL_STRING, sname.realm.as_bytes())),
                    der::enc_explicit(2, principal_name(sname)),
                    der::enc_explicit(3, encrypted(self.etype, req.kvno, &ticket_cipher)),
                ]),
            ),
        );

        let who = req.authenticator_client.as_ref().unwrap_or(&req.client);
        let mut checksum = vec![16, 0, 0, 0];
        checksum.extend_from_slice(&[0; 16]);
        let flags: u32 = 0x20 | 0x10 | if req.mutual { 0x02 } else { 0 };
        checksum.extend_from_slice(&flags.to_le_bytes());
        let authenticator = der::tlv(
            der::app(2),
            &der::tlv(
                der::SEQUENCE,
                &der::concat(&[
                    der::enc_explicit(0, der::enc_int(5)),
                    der::enc_explicit(1, der::tlv(der::GENERAL_STRING, who.realm.as_bytes())),
                    der::enc_explicit(2, principal_name(who)),
                    der::enc_explicit(
                        3,
                        der::tlv(
                            der::SEQUENCE,
                            &der::concat(&[
                                der::enc_explicit(0, der::enc_int(0x8003)),
                                der::enc_explicit(1, der::tlv(der::OCTET_STRING, &checksum)),
                            ]),
                        ),
                    ),
                    der::enc_explicit(4, der::enc_int(123_456)),
                    der::enc_explicit(5, der::enc_time(req.ctime)),
                    der::enc_explicit(7, der::enc_int(42)),
                ]),
            ),
        );
        let auth_cipher = crypto::encrypt(
            ETYPE_AES256,
            &session_key,
            USAGE_AUTHENTICATOR,
            &authenticator,
        )?;
        let ap_req = der::tlv(
            der::app(14),
            &der::tlv(
                der::SEQUENCE,
                &der::concat(&[
                    der::enc_explicit(0, der::enc_int(5)),
                    der::enc_explicit(1, der::enc_int(14)),
                    der::enc_explicit(2, bits(0)),
                    der::enc_explicit(3, ticket),
                    der::enc_explicit(4, encrypted(ETYPE_AES256, None, &auth_cipher)),
                ]),
            ),
        );
        Ok(Issued {
            ap_req,
            session_key,
            ctime: req.ctime,
        })
    }

    /// The `Authorization: Negotiate` token a browser would send.
    pub fn negotiate_token(&self, req: &Request) -> Result<(Vec<u8>, Issued), CryptoError> {
        let issued = self.issue(req)?;
        Ok((
            spnego::wrap_ap_req(&issued.ap_req, Mech::MsKrb5, true),
            issued,
        ))
    }
}

/// Check an acceptor's AP-REP the way the client does: it decrypts under
/// the session key and echoes the authenticator's time.
pub fn verify_ap_rep(ap_rep: &[u8], issued: &Issued) -> bool {
    let check = || -> Option<bool> {
        let rep = der::single(ap_rep, der::app(15)).ok()?;
        let mut r = Reader::new(der::single(rep, der::SEQUENCE).ok()?);
        r.explicit(0, der::INTEGER).ok()?;
        r.explicit(1, der::INTEGER).ok()?;
        let mut e = Reader::new(r.explicit(2, der::SEQUENCE).ok()?);
        let etype = der::int(e.explicit(0, der::INTEGER).ok()?).ok()? as i32;
        e.explicit_opt(1, der::INTEGER).ok()?;
        let cipher = e.explicit(2, der::OCTET_STRING).ok()?;
        let plain = crypto::decrypt(etype, &issued.session_key, USAGE_AP_REP, cipher).ok()?;
        let part = der::single(&plain, der::app(27)).ok()?;
        let mut p = Reader::new(der::single(part, der::SEQUENCE).ok()?);
        let ctime = der::time(p.explicit(0, der::GENERALIZED_TIME).ok()?).ok()?;
        let cusec = der::int(p.explicit(1, der::INTEGER).ok()?).ok()?;
        Some(
            ctime.format("%Y%m%d%H%M%S").to_string()
                == issued.ctime.format("%Y%m%d%H%M%S").to_string()
                && cusec == 123_456,
        )
    };
    check().unwrap_or(false)
}
