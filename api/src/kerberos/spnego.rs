//! HTTP Negotiate (RFC 4559) tokens: SPNEGO (RFC 4178) around a Kerberos
//! GSS-API token (RFC 4121), or a bare Kerberos token. Only the initiator's
//! first token is read (Kerberos completes in one round trip), and only
//! when Kerberos is the initiator's first choice, so no `mechListMIC` is
//! needed in either direction.

use super::der::{self, DerResult, Reader};

/// SPNEGO, 1.3.6.1.5.5.2.
const OID_SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
/// Kerberos 5, 1.2.840.113554.1.2.2.
const OID_KRB5: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
/// Microsoft's mis-encoded Kerberos OID, 1.2.840.48018.1.2.2, which
/// Windows lists first.
const OID_MS_KRB5: &[u8] = &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02];
/// NTLM, 1.3.6.1.4.1.311.2.2.10.
const OID_NTLM: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

/// Kerberos token ids (RFC 4121 §4.1).
const TOK_AP_REQ: [u8; 2] = [0x01, 0x00];
const TOK_AP_REP: [u8; 2] = [0x02, 0x00];

/// The OID the initiator named Kerberos by, echoed in the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mech {
    Krb5,
    MsKrb5,
}

impl Mech {
    fn oid(self) -> &'static [u8] {
        match self {
            Self::Krb5 => OID_KRB5,
            Self::MsKrb5 => OID_MS_KRB5,
        }
    }
}

/// A Kerberos AP-REQ the browser offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// The DER-encoded AP-REQ.
    pub ap_req: Vec<u8>,
    pub mech: Mech,
    /// Wrapped in SPNEGO (the answer must be too).
    pub spnego: bool,
}

/// What an `Authorization: Negotiate` token holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Negotiated {
    Kerberos(Offer),
    /// NTLM: the browser had no Kerberos ticket for this host (no SPN, a
    /// machine off the domain, or a name the KDC does not know).
    Ntlm,
    /// Anything else (NegoEx, an unknown mechanism, no optimistic token).
    Unsupported(&'static str),
}

/// Read the initiator's token.
pub fn parse(token: &[u8]) -> DerResult<Negotiated> {
    if token.starts_with(b"NTLMSSP\0") {
        return Ok(Negotiated::Ntlm);
    }
    let (oid, inner) = gss_frame(token)?;
    if oid == OID_SPNEGO {
        return parse_spnego(inner);
    }
    match mech_of(oid) {
        Some(mech) => Ok(Negotiated::Kerberos(Offer {
            ap_req: ap_req_of(inner)?.to_vec(),
            mech,
            spnego: false,
        })),
        None if oid == OID_NTLM => Ok(Negotiated::Ntlm),
        None => Ok(Negotiated::Unsupported(
            "the token is not SPNEGO or Kerberos",
        )),
    }
}

fn mech_of(oid: &[u8]) -> Option<Mech> {
    if oid == OID_KRB5 {
        Some(Mech::Krb5)
    } else if oid == OID_MS_KRB5 {
        Some(Mech::MsKrb5)
    } else {
        None
    }
}

/// `[APPLICATION 0] IMPLICIT SEQUENCE { thisMech OID, innerToken ANY }`.
fn gss_frame(token: &[u8]) -> DerResult<(&[u8], &[u8])> {
    let content = der::single(token, der::app(0))?;
    let mut r = Reader::new(content);
    let oid = r.expect(der::OID)?;
    Ok((oid, r.rest()))
}

/// The AP-REQ inside a Kerberos GSS token's inner part.
fn ap_req_of(inner: &[u8]) -> DerResult<&[u8]> {
    match inner.split_first_chunk::<2>() {
        Some((id, rest)) if *id == TOK_AP_REQ => {
            // Exactly one AP-REQ, nothing after it.
            der::single(rest, der::app(14))?;
            Ok(rest)
        }
        _ => Err(der::DerError("not a Kerberos AP-REQ token")),
    }
}

/// `NegotiationToken ::= CHOICE { negTokenInit [0] NegTokenInit, ... }`.
fn parse_spnego(inner: &[u8]) -> DerResult<Negotiated> {
    let init = der::single(inner, der::ctx(0))?;
    let mut r = Reader::new(der::single(init, der::SEQUENCE)?);
    let mech_list = r.explicit(0, der::SEQUENCE)?;
    let mut mechs = Reader::new(mech_list);
    let first = mechs.expect(der::OID)?;
    // reqFlags [1], then the optimistic token for the first mechanism [2].
    r.optional(der::ctx(1))?;
    let token = r.explicit_opt(2, der::OCTET_STRING)?;
    let Some(mech) = mech_of(first) else {
        return Ok(if first == OID_NTLM {
            Negotiated::Ntlm
        } else {
            Negotiated::Unsupported("Kerberos is not the browser's first choice")
        });
    };
    let Some(token) = token else {
        return Ok(Negotiated::Unsupported("no Kerberos token was sent"));
    };
    let (oid, inner) = gss_frame(token)?;
    if mech_of(oid).is_none() {
        return Ok(Negotiated::Unsupported(
            "the token is not for the mechanism it was offered as",
        ));
    }
    Ok(Negotiated::Kerberos(Offer {
        ap_req: ap_req_of(inner)?.to_vec(),
        mech,
        spnego: true,
    }))
}

/// The acceptor's answer: `accept-completed`, with the AP-REP when the
/// initiator asked for mutual authentication. `None` when there is
/// nothing to send (a bare Kerberos initiator that did not ask).
pub fn answer(offer: &Offer, ap_rep: Option<&[u8]>) -> Option<Vec<u8>> {
    let krb_token = ap_rep.map(|rep| {
        let mut inner = der::tlv(der::OID, OID_KRB5);
        inner.extend_from_slice(&TOK_AP_REP);
        inner.extend_from_slice(rep);
        der::tlv(der::app(0), &inner)
    });
    if !offer.spnego {
        return krb_token;
    }
    let mut fields = vec![
        der::enc_explicit(0, der::tlv(der::ENUMERATED, &[0])),
        der::enc_explicit(1, der::tlv(der::OID, offer.mech.oid())),
    ];
    if let Some(t) = krb_token {
        fields.push(der::enc_explicit(2, der::tlv(der::OCTET_STRING, &t)));
    }
    let seq = der::tlv(der::SEQUENCE, &der::concat(&fields));
    Some(der::tlv(der::ctx(1), &seq))
}

/// Wrap an AP-REQ the way a browser does (SPNEGO, Kerberos listed by
/// `mech` first): for tests and tooling that play the initiator.
pub fn wrap_ap_req(ap_req: &[u8], mech: Mech, spnego: bool) -> Vec<u8> {
    let mut inner = der::tlv(der::OID, OID_KRB5);
    inner.extend_from_slice(&TOK_AP_REQ);
    inner.extend_from_slice(ap_req);
    let krb = der::tlv(der::app(0), &inner);
    if !spnego {
        return krb;
    }
    let mut mechs = der::tlv(der::OID, mech.oid());
    mechs.extend(der::tlv(der::OID, OID_KRB5));
    mechs.extend(der::tlv(der::OID, OID_NTLM));
    let init = der::tlv(
        der::SEQUENCE,
        &der::concat(&[
            der::enc_explicit(0, der::tlv(der::SEQUENCE, &mechs)),
            der::enc_explicit(2, der::tlv(der::OCTET_STRING, &krb)),
        ]),
    );
    let mut outer = der::tlv(der::OID, OID_SPNEGO);
    outer.extend(der::tlv(der::ctx(0), &init));
    der::tlv(der::app(0), &outer)
}

/// The AP-REP inside an acceptor's answer (the initiator's side of
/// [`answer`]), for tests.
pub fn ap_rep_of_answer(answer: &[u8]) -> DerResult<Option<Vec<u8>>> {
    let krb = if answer.first() == Some(&der::ctx(1)) {
        let resp = der::single(answer, der::ctx(1))?;
        let mut r = Reader::new(der::single(resp, der::SEQUENCE)?);
        let state = r.explicit(0, der::ENUMERATED)?;
        if state != [0] {
            return Err(der::DerError("negotiation not complete"));
        }
        r.optional(der::ctx(1))?;
        match r.explicit_opt(2, der::OCTET_STRING)? {
            Some(t) => t,
            None => return Ok(None),
        }
    } else {
        answer
    };
    let (oid, inner) = gss_frame(krb)?;
    if mech_of(oid).is_none() {
        return Err(der::DerError("not a Kerberos token"));
    }
    match inner.split_first_chunk::<2>() {
        Some((id, rest)) if *id == TOK_AP_REP => Ok(Some(rest.to_vec())),
        _ => Err(der::DerError("not an AP-REP token")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_ap_req() -> Vec<u8> {
        der::tlv(der::app(14), &der::tlv(der::SEQUENCE, &[]))
    }

    #[test]
    fn spnego_and_bare_tokens() {
        for mech in [Mech::Krb5, Mech::MsKrb5] {
            let t = wrap_ap_req(&fake_ap_req(), mech, true);
            let Negotiated::Kerberos(offer) = parse(&t).unwrap() else {
                panic!("not kerberos");
            };
            assert_eq!(offer.mech, mech);
            assert!(offer.spnego);
            assert_eq!(offer.ap_req, fake_ap_req());
            let ans = answer(&offer, Some(b"rep")).unwrap();
            assert_eq!(ap_rep_of_answer(&ans).unwrap().unwrap(), b"rep");
            assert_eq!(
                ap_rep_of_answer(&answer(&offer, None).unwrap()).unwrap(),
                None
            );
        }
        let bare = wrap_ap_req(&fake_ap_req(), Mech::Krb5, false);
        let Negotiated::Kerberos(offer) = parse(&bare).unwrap() else {
            panic!("not kerberos");
        };
        assert!(!offer.spnego);
        assert!(answer(&offer, None).is_none());
        assert_eq!(
            ap_rep_of_answer(&answer(&offer, Some(b"x")).unwrap())
                .unwrap()
                .unwrap(),
            b"x"
        );
    }

    #[test]
    fn ntlm_and_others() {
        assert_eq!(parse(b"NTLMSSP\0\x01\0\0\0").unwrap(), Negotiated::Ntlm);
        // SPNEGO listing NTLM first.
        let init = der::tlv(
            der::SEQUENCE,
            &der::enc_explicit(0, der::tlv(der::SEQUENCE, &der::tlv(der::OID, OID_NTLM))),
        );
        let mut outer = der::tlv(der::OID, OID_SPNEGO);
        outer.extend(der::tlv(der::ctx(0), &init));
        assert_eq!(
            parse(&der::tlv(der::app(0), &outer)).unwrap(),
            Negotiated::Ntlm
        );
        // Kerberos first but no optimistic token.
        let init = der::tlv(
            der::SEQUENCE,
            &der::enc_explicit(0, der::tlv(der::SEQUENCE, &der::tlv(der::OID, OID_KRB5))),
        );
        let mut outer = der::tlv(der::OID, OID_SPNEGO);
        outer.extend(der::tlv(der::ctx(0), &init));
        assert!(matches!(
            parse(&der::tlv(der::app(0), &outer)).unwrap(),
            Negotiated::Unsupported(_)
        ));
        // Garbage.
        assert!(parse(b"").is_err());
        assert!(parse(&[0x60, 0x02, 0x06, 0x00]).is_ok());
        // Trailing bytes after the AP-REQ.
        let mut t = fake_ap_req();
        t.push(0);
        assert!(parse(&wrap_ap_req(&t, Mech::Krb5, false)).is_err());
    }
}
