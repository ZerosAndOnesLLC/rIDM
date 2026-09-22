//! Accepting a Kerberos AP-REQ (RFC 4120 §3.2.3): the ticket must be for
//! the configured service and decrypt under one of its keytab keys, be
//! valid now, come from an allowed realm, and carry an authenticator that
//! decrypts under the ticket's session key, names the same client and is
//! fresh. The caller keeps the replay cache ([`Accepted::replay_key`]).

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest as _, Sha256};

use super::Principal;
use super::crypto::{self, CryptoError};
use super::der::{self, DerError, Reader};
use super::keytab::{KeytabEntry, etype_key_len, etype_supported};

/// RFC 4120 §7.5.1 key usages.
pub const USAGE_TICKET: i32 = 2;
pub const USAGE_AUTHENTICATOR: i32 = 11;
pub const USAGE_AP_REP: i32 = 12;

/// The GSS-API authenticator checksum type (RFC 4121 §4.1.1).
const CKSUM_GSSAPI: i64 = 0x8003;
const GSS_C_MUTUAL_FLAG: u32 = 0x02;

/// What the ticket has to satisfy.
pub struct Acceptor<'a> {
    /// The service's keys (entries for other principals are ignored).
    pub keys: &'a [KeytabEntry],
    /// `HTTP/host@REALM`.
    pub service: &'a Principal,
    /// Client realms accepted, upper-case.
    pub realms: &'a [String],
    pub max_skew: Duration,
    pub now: DateTime<Utc>,
}

/// A client the ticket proves.
#[derive(Debug, Clone)]
pub struct Accepted {
    pub client: Principal,
    /// When the client authenticated to the KDC.
    pub auth_time: DateTime<Utc>,
    /// When the ticket ends.
    pub end_time: DateTime<Utc>,
    /// Identifies the authenticator: a second request carrying it is a
    /// replay.
    pub replay_key: [u8; 32],
    /// The DER-encoded AP-REP, when the client asked for mutual
    /// authentication.
    pub ap_rep: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AcceptError {
    #[error(transparent)]
    Malformed(#[from] DerError),
    #[error("not a Kerberos version 5 AP-REQ")]
    Version,
    #[error("user-to-user authentication is not supported")]
    UserToUser,
    #[error("the ticket is for {0}, not this service")]
    WrongService(String),
    #[error("the keytab has no {etype} key (version {kvno:?}) for the service")]
    NoKey { etype: String, kvno: Option<i64> },
    #[error("ticket: {0}")]
    Ticket(CryptoError),
    #[error("authenticator: {0}")]
    Authenticator(CryptoError),
    #[error("the ticket is not valid yet")]
    NotYetValid,
    #[error("the ticket has expired")]
    Expired,
    #[error("the ticket is marked invalid")]
    Invalid,
    #[error("the client's realm {0} is not accepted")]
    Realm(String),
    #[error("the authenticator names another client than the ticket")]
    ClientMismatch,
    #[error("the authenticator's time is outside the allowed clock skew")]
    Skew,
}

struct EncryptedData<'a> {
    etype: i32,
    kvno: Option<i64>,
    cipher: &'a [u8],
}

fn encrypted_data(content: &[u8]) -> Result<EncryptedData<'_>, DerError> {
    let mut r = Reader::new(content);
    let etype = der::int(r.explicit(0, der::INTEGER)?)?;
    let kvno = r.explicit_opt(1, der::INTEGER)?.map(der::int).transpose()?;
    let cipher = r.explicit(2, der::OCTET_STRING)?;
    Ok(EncryptedData {
        etype: i32::try_from(etype).map_err(|_| DerError("etype out of range"))?,
        kvno,
        cipher,
    })
}

/// `PrincipalName` plus the realm it lives in.
fn principal(content: &[u8], realm: &str) -> Result<Principal, DerError> {
    let mut r = Reader::new(content);
    r.explicit(0, der::INTEGER)?;
    let mut names = Reader::new(r.explicit(1, der::SEQUENCE)?);
    let mut components = vec![];
    while !names.is_empty() {
        if components.len() == 8 {
            return Err(DerError("too many name components"));
        }
        let c = der::string(names.expect(der::GENERAL_STRING)?)?;
        if c.is_empty() {
            return Err(DerError("empty name component"));
        }
        components.push(c);
    }
    if components.is_empty() || realm.is_empty() {
        return Err(DerError("empty principal name"));
    }
    Ok(Principal {
        components,
        realm: realm.to_string(),
    })
}

struct Key {
    etype: i32,
    value: zeroize::Zeroizing<Vec<u8>>,
}

fn encryption_key(content: &[u8]) -> Result<Key, DerError> {
    let mut r = Reader::new(content);
    let etype = der::int(r.explicit(0, der::INTEGER)?)?;
    let value = r.explicit(1, der::OCTET_STRING)?;
    Ok(Key {
        etype: i32::try_from(etype).map_err(|_| DerError("key type out of range"))?,
        value: zeroize::Zeroizing::new(value.to_vec()),
    })
}

/// The service an AP-REQ's ticket is for (read before any key is chosen,
/// to pick the provider whose keytab should open it). Nothing is checked.
pub fn service_of(ap_req: &[u8]) -> Result<Principal, DerError> {
    let mut r = Reader::new(der::single(
        der::single(ap_req, der::app(14))?,
        der::SEQUENCE,
    )?);
    r.skip_until(3)?;
    let ticket = der::single(r.expect(der::ctx(3))?, der::app(1))?;
    let mut t = Reader::new(der::single(ticket, der::SEQUENCE)?);
    t.explicit(0, der::INTEGER)?;
    let realm = der::string(t.explicit(1, der::GENERAL_STRING)?)?;
    principal(t.explicit(2, der::SEQUENCE)?, &realm)
}

impl Acceptor<'_> {
    /// Check an AP-REQ (DER).
    pub fn accept(&self, ap_req: &[u8]) -> Result<Accepted, AcceptError> {
        let mut r = Reader::new(der::single(
            der::single(ap_req, der::app(14))?,
            der::SEQUENCE,
        )?);
        if der::int(r.explicit(0, der::INTEGER)?)? != 5
            || der::int(r.explicit(1, der::INTEGER)?)? != 14
        {
            return Err(AcceptError::Version);
        }
        let options = r.explicit(2, der::BIT_STRING)?;
        // use-session-key: a ticket encrypted in another ticket's key.
        if der::bit(options, 1) {
            return Err(AcceptError::UserToUser);
        }
        let mutual_required = der::bit(options, 2);
        let ticket = der::single(r.expect(der::ctx(3))?, der::app(1))?;
        let authenticator = encrypted_data(r.explicit(4, der::SEQUENCE)?)?;

        // The ticket, for this service.
        let mut t = Reader::new(der::single(ticket, der::SEQUENCE)?);
        if der::int(t.explicit(0, der::INTEGER)?)? != 5 {
            return Err(AcceptError::Version);
        }
        let srealm = der::string(t.explicit(1, der::GENERAL_STRING)?)?;
        let sname = principal(t.explicit(2, der::SEQUENCE)?, &srealm)?;
        if !sname.eq_ignore_case(self.service) {
            return Err(AcceptError::WrongService(sname.to_string()));
        }
        let enc = encrypted_data(t.explicit(3, der::SEQUENCE)?)?;
        let candidates: Vec<&KeytabEntry> = self
            .keys
            .iter()
            .filter(|k| {
                k.etype == enc.etype
                    && k.principal.eq_ignore_case(self.service)
                    && enc.kvno.is_none_or(|v| i64::from(k.kvno) == v)
            })
            .collect();
        if candidates.is_empty() || !etype_supported(enc.etype) {
            return Err(AcceptError::NoKey {
                etype: super::keytab::etype_name(enc.etype),
                kvno: enc.kvno,
            });
        }
        let mut plain = Err(CryptoError::Integrity);
        for k in candidates {
            plain = crypto::decrypt(enc.etype, &k.key, USAGE_TICKET, enc.cipher);
            if plain.is_ok() {
                break;
            }
        }
        let plain = zeroize::Zeroizing::new(plain.map_err(AcceptError::Ticket)?);

        // EncTicketPart.
        let mut p = Reader::new(der::single(
            der::single(&plain, der::app(3))?,
            der::SEQUENCE,
        )?);
        let flags = p.explicit(0, der::BIT_STRING)?;
        let session = encryption_key(p.explicit(1, der::SEQUENCE)?)?;
        let crealm = der::string(p.explicit(2, der::GENERAL_STRING)?)?;
        let client = principal(p.explicit(3, der::SEQUENCE)?, &crealm)?;
        p.expect(der::ctx(4))?;
        let auth_time = der::time(p.explicit(5, der::GENERALIZED_TIME)?)?;
        let start_time = p
            .explicit_opt(6, der::GENERALIZED_TIME)?
            .map(der::time)
            .transpose()?;
        let end_time = der::time(p.explicit(7, der::GENERALIZED_TIME)?)?;
        // Ticket flag 7: INVALID (a postdated ticket not yet validated).
        if der::bit(flags, 7) {
            return Err(AcceptError::Invalid);
        }
        if start_time.unwrap_or(auth_time) - self.max_skew > self.now {
            return Err(AcceptError::NotYetValid);
        }
        if end_time + self.max_skew < self.now {
            return Err(AcceptError::Expired);
        }
        if !self
            .realms
            .iter()
            .any(|r| r.eq_ignore_ascii_case(&client.realm))
        {
            return Err(AcceptError::Realm(client.realm));
        }
        if !etype_supported(session.etype)
            || etype_key_len(session.etype) != Some(session.value.len())
            || authenticator.etype != session.etype
        {
            return Err(AcceptError::Authenticator(CryptoError::Etype(
                authenticator.etype,
            )));
        }

        // The authenticator, under the session key.
        let auth_plain = crypto::decrypt(
            session.etype,
            &session.value,
            USAGE_AUTHENTICATOR,
            authenticator.cipher,
        )
        .map_err(AcceptError::Authenticator)?;
        let mut a = Reader::new(der::single(
            der::single(&auth_plain, der::app(2))?,
            der::SEQUENCE,
        )?);
        if der::int(a.explicit(0, der::INTEGER)?)? != 5 {
            return Err(AcceptError::Version);
        }
        let a_realm = der::string(a.explicit(1, der::GENERAL_STRING)?)?;
        let a_client = principal(a.explicit(2, der::SEQUENCE)?, &a_realm)?;
        if a_client != client {
            return Err(AcceptError::ClientMismatch);
        }
        let mut gss_flags = 0u32;
        if let Some(cksum) = a.explicit_opt(3, der::SEQUENCE)? {
            let mut c = Reader::new(cksum);
            let kind = der::int(c.explicit(0, der::INTEGER)?)?;
            let value = c.explicit(1, der::OCTET_STRING)?;
            if kind == CKSUM_GSSAPI {
                // Lgth (16) | Bnd (16 bytes) | Flags, little-endian.
                if value.len() < 24 || value[..4] != [16, 0, 0, 0] {
                    return Err(DerError("malformed GSS-API checksum").into());
                }
                gss_flags = u32::from_le_bytes([value[20], value[21], value[22], value[23]]);
            }
        }
        let cusec = der::int(a.explicit(4, der::INTEGER)?)?;
        if !(0..=999_999).contains(&cusec) {
            return Err(DerError("microseconds out of range").into());
        }
        let ctime_raw = a.explicit(5, der::GENERALIZED_TIME)?;
        let ctime = der::time(ctime_raw)?;
        if (ctime - self.now).abs() > self.max_skew {
            return Err(AcceptError::Skew);
        }

        let mutual = mutual_required || gss_flags & GSS_C_MUTUAL_FLAG != 0;
        let ap_rep = if mutual {
            Some(ap_rep(&session, ctime_raw, cusec).map_err(AcceptError::Authenticator)?)
        } else {
            None
        };
        Ok(Accepted {
            client,
            auth_time,
            end_time,
            replay_key: Sha256::digest(authenticator.cipher).into(),
            ap_rep,
        })
    }
}

/// `AP-REP` echoing the authenticator's time, encrypted in the session key.
fn ap_rep(session: &Key, ctime_raw: &[u8], cusec: i64) -> Result<Vec<u8>, CryptoError> {
    let seq_number = i64::from(rand::random::<u32>() & 0x3fff_ffff);
    let part = der::tlv(
        der::app(27),
        &der::tlv(
            der::SEQUENCE,
            &der::concat(&[
                der::enc_explicit(0, der::tlv(der::GENERALIZED_TIME, ctime_raw)),
                der::enc_explicit(1, der::enc_int(cusec)),
                der::enc_explicit(3, der::enc_int(seq_number)),
            ]),
        ),
    );
    let cipher = crypto::encrypt(session.etype, &session.value, USAGE_AP_REP, &part)?;
    let enc = der::tlv(
        der::SEQUENCE,
        &der::concat(&[
            der::enc_explicit(0, der::enc_int(i64::from(session.etype))),
            der::enc_explicit(2, der::tlv(der::OCTET_STRING, &cipher)),
        ]),
    );
    Ok(der::tlv(
        der::app(15),
        &der::tlv(
            der::SEQUENCE,
            &der::concat(&[
                der::enc_explicit(0, der::enc_int(5)),
                der::enc_explicit(1, der::enc_int(15)),
                der::enc_explicit(2, enc),
            ]),
        ),
    ))
}

#[cfg(all(test, feature = "kerberos"))]
mod tests {
    use super::*;
    use crate::kerberos::spnego::{self, Negotiated};
    use crate::kerberos::testing::{Kdc, verify_ap_rep};

    const SERVICE: &str = "HTTP/sso.example.com@EXAMPLE.COM";

    fn accept(kdc: &Kdc, ap_req: &[u8], realms: &[&str]) -> Result<Accepted, AcceptError> {
        let keys = [kdc.entry()];
        let realms: Vec<String> = realms.iter().map(|r| r.to_string()).collect();
        Acceptor {
            keys: &keys,
            service: &kdc.service,
            realms: &realms,
            max_skew: Duration::minutes(5),
            now: Utc::now(),
        }
        .accept(ap_req)
    }

    #[test]
    fn a_good_ticket_is_accepted_with_a_mutual_answer() {
        let kdc = Kdc::new(SERVICE);
        let (token, issued) = kdc
            .negotiate_token(&kdc.request("alice@EXAMPLE.COM"))
            .unwrap();
        let Negotiated::Kerberos(offer) = spnego::parse(&token).unwrap() else {
            panic!("not kerberos");
        };
        let ok = accept(&kdc, &offer.ap_req, &["EXAMPLE.COM"]).unwrap();
        assert_eq!(ok.client.to_string(), "alice@EXAMPLE.COM");
        let rep = ok.ap_rep.expect("mutual authentication was asked for");
        assert!(verify_ap_rep(&rep, &issued));
        // Without the mutual flag there is no AP-REP.
        let mut req = kdc.request("bob@EXAMPLE.COM");
        req.mutual = false;
        let issued = kdc.issue(&req).unwrap();
        assert!(
            accept(&kdc, &issued.ap_req, &["EXAMPLE.COM"])
                .unwrap()
                .ap_rep
                .is_none()
        );
        // A non-ASCII name (AD allows them).
        let issued = kdc.issue(&kdc.request("jürgen@EXAMPLE.COM")).unwrap();
        assert_eq!(
            accept(&kdc, &issued.ap_req, &["EXAMPLE.COM"])
                .unwrap()
                .client
                .name(),
            "jürgen"
        );
    }

    #[test]
    fn bad_tickets_are_refused() {
        let kdc = Kdc::new(SERVICE);
        let now = Utc::now();
        let refused = |edit: &dyn Fn(&mut crate::kerberos::testing::Request)| {
            let mut req = kdc.request("alice@EXAMPLE.COM");
            edit(&mut req);
            accept(&kdc, &kdc.issue(&req).unwrap().ap_req, &["EXAMPLE.COM"]).unwrap_err()
        };
        assert_eq!(
            refused(&|r| r.end_time = now - Duration::minutes(10)),
            AcceptError::Expired
        );
        assert_eq!(
            refused(&|r| r.start_time = Some(now + Duration::minutes(10))),
            AcceptError::NotYetValid
        );
        assert_eq!(refused(&|r| r.invalid = true), AcceptError::Invalid);
        assert_eq!(
            refused(&|r| r.ctime = now - Duration::minutes(6)),
            AcceptError::Skew
        );
        assert_eq!(
            refused(&|r| r.ctime = now + Duration::minutes(6)),
            AcceptError::Skew
        );
        assert_eq!(
            refused(&|r| r.authenticator_client =
                Some(Principal::parse("mallory@EXAMPLE.COM").unwrap())),
            AcceptError::ClientMismatch
        );
        assert_eq!(
            refused(&|r| r.ticket_key = Some(vec![1; 32])),
            AcceptError::Ticket(CryptoError::Integrity)
        );
        assert!(matches!(
            refused(&|r| r.kvno = Some(9)),
            AcceptError::NoKey { .. }
        ));
        assert!(matches!(
            refused(&|r| r.sname = Some(Principal::parse("HTTP/other@EXAMPLE.COM").unwrap())),
            AcceptError::WrongService(_)
        ));
        assert_eq!(
            refused(&|r| r.client = Principal::parse("eve@EVIL.COM").unwrap()),
            AcceptError::Realm("EVIL.COM".into())
        );
        // Without a kvno every key of the right type is tried.
        let mut req = kdc.request("alice@EXAMPLE.COM");
        req.kvno = None;
        assert!(accept(&kdc, &kdc.issue(&req).unwrap().ap_req, &["EXAMPLE.COM"]).is_ok());
        // Another service's keytab never opens the ticket.
        let other = Kdc::new(SERVICE);
        let issued = kdc.issue(&kdc.request("alice@EXAMPLE.COM")).unwrap();
        assert_eq!(
            accept(&other, &issued.ap_req, &["EXAMPLE.COM"]).unwrap_err(),
            AcceptError::Ticket(CryptoError::Integrity)
        );
    }

    #[test]
    fn tampering_anywhere_is_refused_and_never_panics() {
        let kdc = Kdc::new(SERVICE);
        let issued = kdc.issue(&kdc.request("alice@EXAMPLE.COM")).unwrap();
        for i in 0..issued.ap_req.len() {
            let mut t = issued.ap_req.clone();
            t[i] ^= 0x01;
            if let Ok(ok) = accept(&kdc, &t, &["EXAMPLE.COM"]) {
                // Only a change the ciphertexts do not cover (the outer
                // framing's flags) may pass, and it names the same client.
                assert_eq!(ok.client.to_string(), "alice@EXAMPLE.COM", "byte {i}");
            }
        }
        for cut in 0..issued.ap_req.len() {
            assert!(accept(&kdc, &issued.ap_req[..cut], &["EXAMPLE.COM"]).is_err());
        }
    }
}
