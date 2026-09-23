//! `ridm key list | rotate` and `ridm master-key status | rotate | new-generation`.
//!
//! The two are different keys: a tenant's signing keys mint tokens and rotate
//! per tenant with an overlap, while the master key encrypts secrets at rest
//! for the whole deployment and rotates by re-encrypting every row.

use serde_json::Value;

use crate::cli::{KeyCommand, MasterKeyCommand};
use crate::context::Ctx;
use crate::error::{CliError, Result};
use crate::{input, output};

pub async fn run(ctx: &mut Ctx, command: &KeyCommand) -> Result<()> {
    let json_out = ctx.output.is_json();
    let tenant = ctx.tenant.clone();
    match command {
        KeyCommand::List { status } => {
            let query: Vec<(&str, String)> = status
                .clone()
                .map(|s| vec![("status", s)])
                .unwrap_or_default();
            let api = ctx.api().await?;
            let keys = api
                .get(&format!("/admin/tenants/{tenant}/keys"), &query)
                .await?;
            if json_out {
                return output::json(&keys);
            }
            let rows: Vec<Vec<String>> = output::items(&keys)
                .iter()
                .map(|k| {
                    vec![
                        output::field(k, "kid"),
                        output::field(k, "alg"),
                        output::field(k, "status"),
                        output::field(k, "not_before"),
                        output::field(k, "expires_at"),
                    ]
                })
                .collect();
            output::table(&["KID", "ALG", "STATUS", "NOT BEFORE", "EXPIRES"], &rows);
            Ok(())
        }
        KeyCommand::Rotate => {
            let api = ctx.api().await?;
            let key = api
                .post_empty(&format!("/admin/tenants/{tenant}/keys/rotate"))
                .await?;
            if json_out {
                return output::json(&key);
            }
            println!(
                "Tenant `{tenant}` now signs with {} ({}); the previous key is retiring.",
                output::field(&key, "kid"),
                output::field(&key, "alg")
            );
            Ok(())
        }
    }
}

pub async fn master(ctx: &mut Ctx, command: &MasterKeyCommand) -> Result<()> {
    let json_out = ctx.output.is_json();
    match command {
        MasterKeyCommand::Status => {
            let api = ctx.api().await?;
            let status = api.get("/admin/master-key", &[]).await?;
            if json_out {
                return output::json(&status);
            }
            render_status(&status);
            Ok(())
        }
        MasterKeyCommand::Rotate { yes } => {
            let yes = *yes;
            let api = ctx.api().await?;
            let status = api.get("/admin/master-key", &[]).await?;
            if !json_out {
                render_status(&status);
            }
            if pending(&status) == 0 {
                println!("Nothing to rotate.");
                return Ok(());
            }
            if !yes && !input::confirm("Re-encrypt every secret at rest?")? {
                println!("Nothing rotated.");
                return Ok(());
            }
            let report = api.post_empty("/admin/master-key/rotate").await?;
            if json_out {
                return output::json(&report);
            }
            output::json(&report)?;
            let failed: u64 = report
                .get("failed")
                .and_then(Value::as_object)
                .map(|m| m.values().filter_map(Value::as_u64).sum())
                .unwrap_or(0);
            if failed > 0 {
                return Err(CliError::failed(format!(
                    "{failed} row(s) could not be re-encrypted; check MASTER_KEY_PREVIOUS and \
                     KEY_WRAPPER_PREVIOUS"
                )));
            }
            println!("Master key rotation complete.");
            Ok(())
        }
        MasterKeyCommand::NewGeneration => {
            let api = ctx.api().await?;
            let created = api.post_empty("/admin/master-key/generations").await?;
            if json_out {
                return output::json(&created);
            }
            println!(
                "created master-key generation {}; run `ridm master-key rotate` to move \
                 existing secrets onto it",
                output::field(&created, "version")
            );
            Ok(())
        }
    }
}

/// Rows still on an older generation. The endpoint has already summed them
/// as `pending_rows`; `rows_by_version` (table → generation → rows) is the
/// fallback if that ever stops being sent.
fn pending(status: &Value) -> i64 {
    if let Some(n) = status.get("pending_rows").and_then(Value::as_i64) {
        return n;
    }
    let current = status
        .get("current_version")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    status
        .get("rows_by_version")
        .and_then(Value::as_object)
        .map(|tables| {
            tables
                .values()
                .filter_map(Value::as_object)
                .flat_map(|versions| versions.iter())
                .filter(|(version, _)| version.parse::<i64>().ok() != Some(current))
                .filter_map(|(_, rows)| rows.as_i64())
                .sum()
        })
        .unwrap_or(0)
}

fn render_status(status: &Value) {
    println!(
        "current generation {}",
        output::field(status, "current_version")
    );
    match status.get("key_wrapper").and_then(Value::as_str) {
        Some(backend) => println!("key custody: {backend}"),
        None => println!("key custody: environment (MASTER_KEY)"),
    }
    println!("{} row(s) still on an older generation", pending(status));
}
