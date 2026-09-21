//! `ridm audit verify | export`.
//!
//! `verify --file` checks an export with nothing but the file and the chain's
//! rules ([`ridm_core::audit_chain`]): every row must hash to what it says
//! and follow the row before it, and with `--head` / `--after` the file must
//! end on, or continue from, a hash kept from an earlier check. It never
//! contacts the server, so a server that rewrote its log cannot vouch for
//! itself. Without `--file` the server walks its own copy.

use std::fmt;
use std::io::{BufReader, Read};

use ridm_core::audit_chain::{Break, ExportedRow, Verifier};
use serde::de::{DeserializeSeed, SeqAccess, Visitor};
use serde_json::json;

use crate::cli::{AuditCommand, AuditFormat};
use crate::context::Ctx;
use crate::error::{CliError, Result};
use crate::output;

pub async fn run(ctx: &mut Ctx, command: &AuditCommand) -> Result<()> {
    let json_out = ctx.output.is_json();
    match command {
        AuditCommand::Verify {
            file: Some(file),
            head,
            after,
            ..
        } => verify_file(json_out, file, head.as_deref(), after.as_deref()),
        AuditCommand::Verify {
            file: None,
            head,
            global,
            ..
        } => {
            let path = chain_path(ctx, *global, "verify");
            let api = ctx.api().await?;
            let report = api.get(&path, &[]).await?;
            let mut problem = (report["valid"] != true).then(|| {
                format!(
                    "the chain is broken at seq {}: {}",
                    output::field(&report, "broken_at_seq"),
                    output::field(&report, "reason")
                )
            });
            if problem.is_none()
                && let Some(expected) = head
                && !report["last_hash"]
                    .as_str()
                    .is_some_and(|h| h.eq_ignore_ascii_case(expected))
            {
                problem = Some(format!(
                    "the chain ends on {}, not on the expected {expected}",
                    output::field(&report, "last_hash")
                ));
            }
            if json_out {
                output::json(&report)?;
            } else if problem.is_none() {
                println!(
                    "Intact: {} rows (seq {}–{}), ending on {}.",
                    output::field(&report, "checked"),
                    output::field(&report, "first_seq"),
                    output::field(&report, "last_seq"),
                    output::field(&report, "last_hash")
                );
            }
            match problem {
                Some(p) => Err(CliError::failed(p)),
                None => Ok(()),
            }
        }
        AuditCommand::Export {
            out,
            format,
            global,
            from,
            to,
        } => {
            let path = chain_path(ctx, *global, "export");
            let mut query = vec![(
                "format",
                match format {
                    AuditFormat::Json => "json",
                    AuditFormat::Csv => "csv",
                }
                .to_string(),
            )];
            if let Some(f) = from {
                query.push(("from", f.clone()));
            }
            if let Some(t) = to {
                query.push(("to", t.clone()));
            }
            let api = ctx.api().await?;
            match out {
                Some(p) => {
                    let mut file = std::io::BufWriter::new(
                        std::fs::File::create(p)
                            .map_err(|e| CliError::failed(format!("{}: {e}", p.display())))?,
                    );
                    let n = api.download(&path, &query, &mut file).await?;
                    eprintln!("Wrote {} ({n} bytes).", p.display());
                }
                None => {
                    api.download(&path, &query, &mut std::io::stdout().lock())
                        .await?;
                }
            }
            Ok(())
        }
    }
}

fn chain_path(ctx: &Ctx, global: bool, what: &str) -> String {
    if global {
        format!("/admin/audit/{what}")
    } else {
        format!("/admin/tenants/{}/audit/{what}", ctx.tenant)
    }
}

/// What checking a file found.
#[derive(Debug)]
pub struct FileReport {
    pub verifier: Verifier,
    pub first_prev: Option<Option<Vec<u8>>>,
    pub broken: Option<Break>,
}

/// Walk a JSON export row by row without holding it in memory.
pub fn check_export(reader: impl Read) -> Result<FileReport> {
    let mut report = FileReport {
        verifier: Verifier::new(),
        first_prev: None,
        broken: None,
    };
    let mut de = serde_json::Deserializer::from_reader(BufReader::new(reader));
    Rows(&mut report)
        .deserialize(&mut de)
        .map_err(|e| CliError::failed(format!("not an audit export: {e}")))?;
    de.end()
        .map_err(|e| CliError::failed(format!("not an audit export: {e}")))?;
    Ok(report)
}

struct Rows<'a>(&'a mut FileReport);

impl<'de> DeserializeSeed<'de> for Rows<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for Rows<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON array of audit rows")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
        let report = self.0;
        while let Some(row) = seq.next_element::<ExportedRow>()? {
            if report.broken.is_some() {
                continue;
            }
            if report.first_prev.is_none() {
                report.first_prev = Some(row.prev_hash.clone());
            }
            if let Err(b) =
                report
                    .verifier
                    .check(&row.canonical(), row.prev_hash.as_deref(), &row.hash)
            {
                report.broken = Some(b);
            }
        }
        Ok(())
    }
}

fn verify_file(json_out: bool, file: &str, head: Option<&str>, after: Option<&str>) -> Result<()> {
    let report = if file == "-" {
        check_export(std::io::stdin().lock())?
    } else {
        check_export(
            std::fs::File::open(file).map_err(|e| CliError::failed(format!("{file}: {e}")))?,
        )?
    };
    let v = &report.verifier;
    let last_hash = v.last_hash.as_deref().map(hex_lower);
    let problem = if let Some(b) = &report.broken {
        let hint = if b.reason.starts_with("gap") {
            " (an export filtered by event name or user leaves gaps; export the whole chain)"
        } else {
            ""
        };
        Some(format!("broken at seq {}: {}{hint}", b.seq, b.reason))
    } else if v.checked == 0 {
        Some("the export holds no rows".into())
    } else if let Some(expected) = after
        && !report
            .first_prev
            .as_ref()
            .and_then(|p| p.as_ref())
            .is_some_and(|p| hex_lower(p).eq_ignore_ascii_case(expected))
    {
        Some(format!(
            "the first row (seq {}) does not follow {expected}",
            v.first_seq.unwrap_or_default()
        ))
    } else if let Some(expected) = head
        && !last_hash
            .as_deref()
            .is_some_and(|h| h.eq_ignore_ascii_case(expected))
    {
        Some(format!(
            "the export ends on {}, not on the expected {expected}",
            last_hash.as_deref().unwrap_or("-")
        ))
    } else {
        None
    };
    if json_out {
        output::json(&json!({
            "checked": v.checked,
            "valid": problem.is_none(),
            "first_seq": v.first_seq,
            "last_seq": v.last_seq,
            "last_hash": last_hash,
            "broken_at_seq": report.broken.as_ref().map(|b| b.seq),
            "reason": problem,
        }))?;
    } else if problem.is_none() {
        println!(
            "Intact: {} rows (seq {}–{}), ending on {}.",
            v.checked,
            v.first_seq.unwrap_or_default(),
            v.last_seq.unwrap_or_default(),
            last_hash.as_deref().unwrap_or("-")
        );
    }
    match problem {
        Some(p) => Err(CliError::failed(p)),
        None => Ok(()),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_array_is_not_an_export() {
        assert!(check_export(&b"{\"items\": []}"[..]).is_err());
        let empty = check_export(&b"[]"[..]).unwrap();
        assert_eq!(empty.verifier.checked, 0);
    }

    #[test]
    fn rows_that_do_not_hash_are_reported_with_their_seq() {
        let doc = json!([{
            "id": "0192f5d0-69f0-7a11-b3c4-2d5e6f708192",
            "tenant_id": null,
            "seq": 7,
            "occurred_at": "2026-09-21T10:00:00.123456Z",
            "recorded_at": "2026-09-21T10:00:00.2Z",
            "name": "user.created",
            "actor_type": "system",
            "actor_id": null,
            "subject_id": null,
            "ip": null,
            "user_agent": null,
            "payload": {"type": "user_created"},
            "prev_hash": null,
            "hash": "00"
        }]);
        let report = check_export(doc.to_string().as_bytes()).unwrap();
        assert_eq!(report.broken.map(|b| b.seq), Some(7));
    }
}
