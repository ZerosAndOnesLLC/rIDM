//! `ridm profile list | use | show`: what the CLI remembers, and about which
//! server. Credentials are described, never printed.

use crate::cli::ProfileCommand;
use crate::context::Ctx;
use crate::error::{CliError, Result};
use crate::output;

pub fn run(ctx: &mut Ctx, command: &ProfileCommand) -> Result<()> {
    match command {
        ProfileCommand::List => list(ctx),
        ProfileCommand::Use { name } => select(ctx, name),
        ProfileCommand::Show { name } => show(ctx, name.as_deref()),
    }
}

fn list(ctx: &Ctx) -> Result<()> {
    let doc = ctx.store.document();
    let current = doc.current.clone().unwrap_or_default();
    let rows: Vec<Vec<String>> = doc
        .profiles
        .iter()
        .map(|(name, p)| {
            vec![
                if *name == current { "*" } else { " " }.to_string(),
                name.clone(),
                p.url.clone(),
                p.tenant.clone(),
                p.credential
                    .as_ref()
                    .map(crate::config::Credential::describe)
                    .unwrap_or_else(|| "(none)".to_string()),
            ]
        })
        .collect();
    if ctx.output.is_json() {
        return output::json(doc);
    }
    output::table(&["", "NAME", "URL", "TENANT", "CREDENTIAL"], &rows);
    println!("\n{}", ctx.store.path().display());
    Ok(())
}

fn select(ctx: &mut Ctx, name: &str) -> Result<()> {
    ctx.store.select(name)?;
    ctx.store.save()?;
    println!("Profile `{name}` selected.");
    Ok(())
}

fn show(ctx: &Ctx, name: Option<&str>) -> Result<()> {
    let name = name.unwrap_or(&ctx.name);
    let profile = ctx
        .store
        .get(name)
        .ok_or_else(|| CliError::usage(format!("no profile named `{name}`")))?;
    if ctx.output.is_json() {
        // The stored credential is a secret; describe it instead.
        return output::json(&serde_json::json!({
            "name": name,
            "url": profile.url,
            "tenant": profile.tenant,
            "credential": profile.credential.as_ref().map(crate::config::Credential::describe),
        }));
    }
    println!("name       {name}");
    println!("url        {}", profile.url);
    println!("tenant     {}", profile.tenant);
    println!(
        "credential {}",
        profile
            .credential
            .as_ref()
            .map(crate::config::Credential::describe)
            .unwrap_or_else(|| "(none)".to_string())
    );
    Ok(())
}
