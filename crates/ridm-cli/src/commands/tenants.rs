//! `ridm tenant list | show | create | export | import | diff`.
//!
//! Export and import are the admin API's configuration-as-code endpoints;
//! `diff` is an import with `?dry_run=true`, which returns the plan and
//! changes nothing. `import` runs that same plan first and shows it, so the
//! answer to "what is about to happen" never depends on a different request
//! than the one that happens.

use serde_json::{Value, json};

use crate::api::Api;
use crate::cli::TenantCommand;
use crate::context::Ctx;
use crate::error::{CliError, Result};
use crate::{input, output};

pub async fn run(ctx: &mut Ctx, command: &TenantCommand) -> Result<()> {
    let json_out = ctx.output.is_json();
    let default = ctx.tenant.clone();
    match command {
        TenantCommand::List { limit } => {
            let limit = *limit;
            let api = ctx.api().await?;
            list(json_out, &api, limit).await
        }
        TenantCommand::Show { slug: given } => {
            let slug = target(given, &default);
            let api = ctx.api().await?;
            let tenant = api.get(&format!("/admin/tenants/{slug}"), &[]).await?;
            output::json(&tenant)
        }
        TenantCommand::Create { slug, name } => {
            let (slug, name) = (slug.clone(), name.clone());
            let api = ctx.api().await?;
            create(json_out, &api, &slug, name.as_deref()).await
        }
        TenantCommand::Export { slug: given, out } => {
            let (slug, out) = (target(given, &default), out.clone());
            let api = ctx.api().await?;
            export(&api, &slug, out.as_deref()).await
        }
        TenantCommand::Import {
            slug: given,
            file,
            prune,
            yes,
        } => {
            let (slug, file, prune, yes) = (target(given, &default), file.clone(), *prune, *yes);
            let api = ctx.api().await?;
            import(json_out, &api, &slug, &file, prune, yes).await
        }
        TenantCommand::Diff {
            slug: given,
            file,
            prune,
            exit_code,
        } => {
            let (slug, file, prune, exit_code) =
                (target(given, &default), file.clone(), *prune, *exit_code);
            let api = ctx.api().await?;
            diff(json_out, &api, &slug, &file, prune, exit_code).await
        }
    }
}

/// The tenant a command acts on: the one named, else the profile's.
fn target(given: &Option<String>, default: &str) -> String {
    given.clone().unwrap_or_else(|| default.to_string())
}

async fn list(json_out: bool, api: &Api, limit: Option<u32>) -> Result<()> {
    let query: Vec<(&str, String)> = limit
        .map(|l| vec![("limit", l.to_string())])
        .unwrap_or_default();
    let page = api.get("/admin/tenants", &query).await?;
    if json_out {
        return output::json(&page);
    }
    let rows: Vec<Vec<String>> = output::items(&page)
        .iter()
        .map(|t| {
            vec![
                output::field(t, "slug"),
                output::field(t, "display_name"),
                output::field(t, "status"),
                output::field(t, "created_at"),
            ]
        })
        .collect();
    output::table(&["SLUG", "NAME", "STATUS", "CREATED"], &rows);
    Ok(())
}

async fn create(json_out: bool, api: &Api, slug: &str, name: Option<&str>) -> Result<()> {
    let body = json!({
        "slug": slug,
        "display_name": name.unwrap_or(slug),
    });
    let tenant = api.post("/admin/tenants", &[], &body).await?;
    if json_out {
        return output::json(&tenant);
    }
    println!(
        "Tenant `{}` created ({}).",
        output::field(&tenant, "slug"),
        output::field(&tenant, "id")
    );
    Ok(())
}

async fn export(api: &Api, slug: &str, out: Option<&std::path::Path>) -> Result<()> {
    let doc = api
        .get(&format!("/admin/tenants/{slug}/export"), &[])
        .await?;
    let body = serde_json::to_string_pretty(&doc)? + "\n";
    match out {
        Some(path) => {
            std::fs::write(path, body)
                .map_err(|e| CliError::failed(format!("{}: {e}", path.display())))?;
            eprintln!("Wrote {}.", path.display());
        }
        None => print!("{body}"),
    }
    Ok(())
}

async fn import(
    json_out: bool,
    api: &Api,
    slug: &str,
    file: &str,
    prune: bool,
    yes: bool,
) -> Result<()> {
    let doc = read_document(file)?;
    let path = format!("/admin/tenants/{slug}/import");
    let plan_query = query(prune, true);
    if !yes {
        let plan = api.post(&path, &plan_query, &doc).await?;
        render_plan(&plan);
        if empty(&plan) {
            println!("Nothing to apply.");
            return Ok(());
        }
        if !input::confirm(&format!("Apply to `{slug}`?"))? {
            println!("Nothing applied.");
            return Ok(());
        }
    }
    let report = api.post(&path, &query(prune, false), &doc).await?;
    if json_out {
        return output::json(&report);
    }
    render_plan(&report);
    println!("{} change(s) applied.", number(&report, "applied"));
    render_errors(&report)?;
    render_secrets(&report);
    Ok(())
}

async fn diff(
    json_out: bool,
    api: &Api,
    slug: &str,
    file: &str,
    prune: bool,
    exit_code: bool,
) -> Result<()> {
    let doc = read_document(file)?;
    let plan = api
        .post(
            &format!("/admin/tenants/{slug}/import"),
            &query(prune, true),
            &doc,
        )
        .await?;
    if json_out {
        output::json(&plan)?;
    } else {
        render_plan(&plan);
    }
    if exit_code && !empty(&plan) {
        return Err(CliError::Changes);
    }
    Ok(())
}

fn query(prune: bool, dry_run: bool) -> Vec<(&'static str, String)> {
    let mut q = vec![("dry_run", dry_run.to_string())];
    if prune {
        q.push(("prune", "true".to_string()));
    }
    q
}

fn read_document(file: &str) -> Result<Value> {
    let text = input::document(file)?;
    serde_json::from_str(&text)
        .map_err(|e| CliError::usage(format!("{file}: not a tenant configuration document: {e}")))
}

/// A plan with no creates, updates or deletes.
fn empty(plan: &Value) -> bool {
    plan.get("changes")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
}

fn number(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// `+ create`, `~ update`, `- delete`, with the changed fields under an update.
fn render_plan(plan: &Value) {
    let changes = plan
        .get("changes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for change in &changes {
        let mark = match change.get("op").and_then(Value::as_str) {
            Some("create") => '+',
            Some("delete") => '-',
            _ => '~',
        };
        println!(
            "  {mark} {:<18} {}",
            output::field(change, "resource"),
            output::field(change, "key")
        );
        let fields = change
            .get("fields")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for field in &fields {
            // A whole-value comparison (the server's fallback for a change
            // that is not between two objects) carries no field name.
            let name = field
                .get("field")
                .and_then(Value::as_str)
                .filter(|n| !n.is_empty())
                .map(|n| format!("{n}: "))
                .unwrap_or_default();
            println!(
                "      {name}{} → {}",
                short(field.get("from")),
                short(field.get("to"))
            );
        }
    }
    let summary = plan.get("summary").cloned().unwrap_or(Value::Null);
    println!(
        "{} to create, {} to update, {} to delete, {} unchanged.",
        number(&summary, "create"),
        number(&summary, "update"),
        number(&summary, "delete"),
        number(&summary, "unchanged")
    );
}

/// A value on one line, cut where it stops being useful.
fn short(value: Option<&Value>) -> String {
    let text = match value {
        None | Some(Value::Null) => "null".to_string(),
        Some(Value::String(s)) => format!("{s:?}"),
        Some(other) => other.to_string(),
    };
    if text.chars().count() <= 60 {
        return text;
    }
    let head: String = text.chars().take(57).collect();
    format!("{head}…")
}

/// Per-item failures; an import that reports any is a failed command.
fn render_errors(report: &Value) -> Result<()> {
    let errors = report
        .get("errors")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if errors.is_empty() {
        return Ok(());
    }
    for e in &errors {
        eprintln!(
            "  ! {} {}: {}",
            output::field(e, "resource"),
            output::field(e, "key"),
            output::field(e, "error")
        );
    }
    Err(CliError::failed(format!(
        "{} item(s) could not be applied",
        errors.len()
    )))
}

/// Secrets the server minted for what the import created, shown once.
fn render_secrets(report: &Value) {
    let Some(secrets) = report.get("secrets") else {
        return;
    };
    for (kind, label) in [("clients", "client"), ("webhooks", "webhook")] {
        let Some(map) = secrets.get(kind).and_then(Value::as_object) else {
            continue;
        };
        for (key, value) in map {
            output::secret(
                &format!("{label} {key} secret"),
                value.as_str().unwrap_or_default(),
            );
        }
    }
    if let Some(idps) = secrets.get("identity_providers").and_then(Value::as_array)
        && !idps.is_empty()
    {
        eprintln!(
            "Identity providers created without a client secret (set one): {}",
            idps.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_plan_with_no_changes_is_empty_however_it_is_shaped() {
        assert!(empty(&json!({"changes": [], "summary": {"unchanged": 8}})));
        assert!(empty(&json!({})));
        assert!(!empty(
            &json!({"changes": [{"resource": "client", "key": "app"}]})
        ));
    }

    #[test]
    fn a_long_value_is_cut_and_a_string_keeps_its_quotes() {
        assert_eq!(short(Some(&json!("acme"))), "\"acme\"");
        assert_eq!(short(Some(&Value::Null)), "null");
        assert_eq!(short(None), "null");
        let long = short(Some(&json!("x".repeat(200))));
        assert!(long.ends_with('…'), "{long}");
        assert_eq!(long.chars().count(), 58);
    }

    #[test]
    fn the_dry_run_flag_and_prune_travel_as_query_parameters() {
        assert_eq!(query(false, true), vec![("dry_run", "true".to_string())]);
        assert_eq!(
            query(true, false),
            vec![
                ("dry_run", "false".to_string()),
                ("prune", "true".to_string())
            ]
        );
    }

    #[test]
    fn the_tenant_falls_back_to_the_profiles_when_none_is_named() {
        assert_eq!(target(&Some("acme".into()), "master"), "acme");
        assert_eq!(target(&None, "master"), "master");
    }

    #[test]
    fn an_import_that_could_not_apply_everything_is_a_failed_command() {
        let report = json!({
            "applied": 1,
            "errors": [{"resource": "client", "key": "app", "error": "unknown scope"}]
        });
        assert!(render_errors(&report).is_err());
        assert!(render_errors(&json!({"applied": 2, "errors": []})).is_ok());
    }
}
