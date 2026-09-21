//! The audit log's hash chain, shared by the server that writes it and the
//! tools that check it without trusting the server.
//!
//! Every tenant's audit rows form one chain (global events form another,
//! under the nil UUID). A row's hash is `SHA-256(prev_hash || canonical row)`,
//! where the canonical row is
//!
//! ```text
//! id|chain|seq|occurred_at|name|actor_type|actor_id|subject_id|ip|user_agent|payload
//! ```
//!
//! with `occurred_at` in RFC 3339 UTC with six fractional digits, absent
//! values empty, the payload as compact JSON with sorted keys, and
//! `|impersonator:<uuid>` appended only for a row that has an impersonator
//! (so rows written before that field existed hash exactly as they did).

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

/// The chain a tenant's rows belong to: its id, or the nil UUID for the
/// global chain.
pub fn chain_id(tenant_id: Option<Uuid>) -> Uuid {
    tenant_id.unwrap_or(Uuid::nil())
}

/// The fields of a row the hash covers.
#[derive(Debug, Clone, Copy)]
pub struct CanonicalRow<'a> {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub seq: i64,
    pub occurred_at: DateTime<Utc>,
    pub name: &'a str,
    pub actor_type: &'a str,
    pub actor_id: Option<Uuid>,
    pub subject_id: Option<Uuid>,
    pub impersonator_id: Option<Uuid>,
    pub ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub payload: &'a Value,
}

/// The bytes the hash covers.
pub fn canonical(row: &CanonicalRow<'_>) -> Vec<u8> {
    let opt = |u: Option<Uuid>| u.map(|u| u.to_string()).unwrap_or_default();
    let mut bytes = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        row.id,
        chain_id(row.tenant_id),
        row.seq,
        row.occurred_at
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        row.name,
        row.actor_type,
        opt(row.actor_id),
        opt(row.subject_id),
        row.ip.unwrap_or_default(),
        row.user_agent.unwrap_or_default(),
        row.payload,
    )
    .into_bytes();
    if let Some(imp) = row.impersonator_id {
        bytes.extend_from_slice(format!("|impersonator:{imp}").as_bytes());
    }
    bytes
}

/// `SHA-256(prev || canonical(row))`.
pub fn hash(prev: Option<&[u8]>, row: &CanonicalRow<'_>) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(prev.unwrap_or(&[]));
    h.update(canonical(row));
    h.finalize().to_vec()
}

/// Where and why a chain stopped verifying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Break {
    pub seq: i64,
    pub reason: String,
}

/// Checks rows one at a time, oldest first.
///
/// The first row's `prev_hash` is taken on trust (it may point at a row the
/// retention job purged) unless the verifier was started [`Verifier::after`]
/// a row already known good; from there on every row must follow the one
/// before it and hash to what it says.
#[derive(Debug, Clone, Default)]
pub struct Verifier {
    chain: Option<Uuid>,
    prev: Option<(i64, Vec<u8>)>,
    pub checked: u64,
    pub first_seq: Option<i64>,
    pub last_seq: Option<i64>,
    pub last_hash: Option<Vec<u8>>,
}

impl Verifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Continue after row `seq` of `chain`, whose hash is `hash`.
    pub fn after(chain: Uuid, seq: i64, hash: Vec<u8>) -> Self {
        Self {
            chain: Some(chain),
            prev: Some((seq, hash)),
            ..Self::default()
        }
    }

    pub fn check(
        &mut self,
        row: &CanonicalRow<'_>,
        prev_hash: Option<&[u8]>,
        row_hash: &[u8],
    ) -> Result<(), Break> {
        let fail = |reason: String| {
            Err(Break {
                seq: row.seq,
                reason,
            })
        };
        let chain = chain_id(row.tenant_id);
        match self.chain {
            Some(c) if c != chain => return fail("the row belongs to another chain".into()),
            _ => self.chain = Some(chain),
        }
        if let Some((seq, hash)) = &self.prev {
            if row.seq != seq + 1 {
                return fail(format!("gap in chain after seq {seq}"));
            }
            if prev_hash != Some(hash.as_slice()) {
                return fail("prev_hash does not link to the previous row".into());
            }
        }
        if hash(prev_hash, row) != row_hash {
            return fail("row hash does not match its contents".into());
        }
        self.checked += 1;
        self.first_seq.get_or_insert(row.seq);
        self.last_seq = Some(row.seq);
        self.last_hash = Some(row_hash.to_vec());
        self.prev = Some((row.seq, row_hash.to_vec()));
        Ok(())
    }
}

/// One row as the audit export (`…/audit/export?format=json`) writes it.
#[derive(Debug, Clone, Deserialize)]
pub struct ExportedRow {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub seq: i64,
    pub occurred_at: DateTime<Utc>,
    pub name: String,
    pub actor_type: String,
    pub actor_id: Option<Uuid>,
    pub subject_id: Option<Uuid>,
    #[serde(default)]
    pub impersonator_id: Option<Uuid>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub payload: Value,
    #[serde(deserialize_with = "hex_opt")]
    pub prev_hash: Option<Vec<u8>>,
    #[serde(deserialize_with = "hex_req")]
    pub hash: Vec<u8>,
}

impl ExportedRow {
    pub fn canonical(&self) -> CanonicalRow<'_> {
        CanonicalRow {
            id: self.id,
            tenant_id: self.tenant_id,
            seq: self.seq,
            occurred_at: self.occurred_at,
            name: &self.name,
            actor_type: &self.actor_type,
            actor_id: self.actor_id,
            subject_id: self.subject_id,
            impersonator_id: self.impersonator_id,
            ip: self.ip.as_deref(),
            user_agent: self.user_agent.as_deref(),
            payload: &self.payload,
        }
    }
}

fn hex_opt<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
    Option::<String>::deserialize(d)?
        .map(|s| hex::decode(s).map_err(serde::de::Error::custom))
        .transpose()
}

fn hex_req<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `(id, seq, payload, prev_hash, hash)` of a valid chain.
    type Row = (Uuid, i64, Value, Option<Vec<u8>>, Vec<u8>);

    fn rows(n: i64) -> Vec<Row> {
        let mut out = vec![];
        let mut prev: Option<Vec<u8>> = None;
        for seq in 1..=n {
            let id = Uuid::now_v7();
            let payload = json!({"user_id": id, "b": 1, "a": [1, 2]});
            let row = CanonicalRow {
                id,
                tenant_id: None,
                seq,
                occurred_at: DateTime::from_timestamp(1_700_000_000 + seq, 0).unwrap(),
                name: "user.created",
                actor_type: "system",
                actor_id: None,
                subject_id: Some(id),
                impersonator_id: None,
                ip: None,
                user_agent: None,
                payload: &payload,
            };
            let h = hash(prev.as_deref(), &row);
            out.push((id, seq, payload.clone(), prev.clone(), h.clone()));
            prev = Some(h);
        }
        out
    }

    fn view(id: Uuid, seq: i64, payload: &Value) -> CanonicalRow<'_> {
        CanonicalRow {
            id,
            tenant_id: None,
            seq,
            occurred_at: DateTime::from_timestamp(1_700_000_000 + seq, 0).unwrap(),
            name: "user.created",
            actor_type: "system",
            actor_id: None,
            subject_id: Some(id),
            impersonator_id: None,
            ip: None,
            user_agent: None,
            payload,
        }
    }

    #[test]
    fn an_intact_chain_verifies_and_reports_its_head() {
        let rows = rows(5);
        let mut v = Verifier::new();
        for (id, seq, p, prev, h) in &rows {
            v.check(&view(*id, *seq, p), prev.as_deref(), h).unwrap();
        }
        assert_eq!((v.checked, v.first_seq, v.last_seq), (5, Some(1), Some(5)));
        assert_eq!(v.last_hash.as_ref(), Some(&rows[4].4));
    }

    #[test]
    fn a_changed_payload_a_gap_and_a_broken_link_are_each_caught() {
        let rows = rows(4);
        let mut v = Verifier::new();
        let (id, seq, _, prev, h) = &rows[0];
        let changed = json!({"user_id": id, "b": 2, "a": [1, 2]});
        let err = v
            .check(&view(*id, *seq, &changed), prev.as_deref(), h)
            .unwrap_err();
        assert_eq!(err.seq, 1);
        assert!(err.reason.contains("does not match"));

        let mut v = Verifier::new();
        let (id, seq, p, prev, h) = &rows[0];
        v.check(&view(*id, *seq, p), prev.as_deref(), h).unwrap();
        let (id, seq, p, prev, h) = &rows[2];
        let err = v
            .check(&view(*id, *seq, p), prev.as_deref(), h)
            .unwrap_err();
        assert!(err.reason.contains("gap"), "{err:?}");

        let mut v = Verifier::after(Uuid::nil(), 1, vec![0; 32]);
        let (id, seq, p, prev, h) = &rows[1];
        let err = v
            .check(&view(*id, *seq, p), prev.as_deref(), h)
            .unwrap_err();
        assert!(err.reason.contains("link"), "{err:?}");
    }

    #[test]
    fn the_impersonator_only_changes_the_hash_when_present() {
        let payload = json!({});
        let mut row = view(Uuid::nil(), 1, &payload);
        let before = canonical(&row);
        assert!(!String::from_utf8_lossy(&before).contains("impersonator"));
        row.impersonator_id = Some(Uuid::nil());
        assert!(canonical(&row).ends_with(format!("|impersonator:{}", Uuid::nil()).as_bytes()));
    }
}
