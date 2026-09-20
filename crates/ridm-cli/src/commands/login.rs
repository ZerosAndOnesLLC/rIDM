//! `ridm login`, `ridm logout` and `ridm whoami`.

use serde_json::Value;

use crate::auth::{self, DEFAULT_SCOPE};
use crate::cli::{LoginArgs, LogoutArgs};
use crate::config::Credential;
use crate::context::Ctx;
use crate::error::{CliError, Result};
use crate::{input, output};

/// Obtain a credential, check it against `/admin/me`, and store it.
pub async fn login(ctx: &mut Ctx, args: &LoginArgs, token_flag: Option<&str>) -> Result<()> {
    if let Some(name) = &args.name {
        ctx.name = name.clone();
    }
    let url = ctx.url()?.to_string();
    // A login fixes the tenant the credential belongs to; later commands may
    // still act on another tenant with --tenant.
    ctx.profile.tenant = ctx.tenant.clone();

    let credential = match (&args.client_id, token_flag, args.token_stdin) {
        (Some(client_id), _, _) => oauth(ctx, args, client_id).await?,
        (None, Some(token), _) => Credential::Token {
            token: token.to_string(),
        },
        (None, None, true) => Credential::Token {
            token: input::line_from_stdin("a personal access token")?.to_string(),
        },
        (None, None, false) => {
            eprintln!(
                "Paste a personal access token for {url} (account console → Tokens),\n\
                 or run `ridm login --client-id …` to use an OAuth client."
            );
            Credential::Token {
                token: input::existing_secret("Token")?.to_string(),
            }
        }
    };

    ctx.profile.credential = Some(credential);
    let api = ctx.api().await?;
    let me = api.get("/admin/me", &[]).await.map_err(|e| match e {
        CliError::Api(a) if a.status == 401 || a.status == 403 => CliError::failed(format!(
            "the credential did not get through: {a}\n\
             an admin token must carry `{}` in aud and belong to a user with `ridm:*` permissions",
            auth::ADMIN_AUDIENCE
        )),
        other => other,
    })?;

    let credential = ctx
        .profile
        .credential
        .clone()
        .ok_or_else(|| CliError::failed("no credential to store"))?;
    ctx.remember(credential)?;

    if ctx.output.is_json() {
        return output::json(&me);
    }
    println!(
        "Logged in to {url} as {} ({}), profile `{}`.",
        output::field(&me, "username"),
        output::field(&me, "scope"),
        ctx.name
    );
    println!("Profile written to {}.", ctx.store.path().display());
    Ok(())
}

/// Run a grant against the tenant's token endpoint.
async fn oauth(ctx: &Ctx, args: &LoginArgs, client_id: &str) -> Result<Credential> {
    let url = ctx.url()?;
    let discovery = auth::discover(&ctx.http, url, &ctx.tenant).await?;
    let secret = if args.client_secret_stdin {
        Some(input::line_from_stdin("the client secret")?.to_string())
    } else if args.device {
        None
    } else {
        Some(input::existing_secret("Client secret")?.to_string())
    };
    let tokens = if args.device || secret.is_none() {
        auth::device_login(
            &ctx.http,
            &discovery,
            client_id,
            secret.as_deref(),
            scope_or_default(&args.scope),
        )
        .await?
    } else {
        auth::client_credentials(
            &ctx.http,
            &discovery.token_endpoint,
            client_id,
            secret.as_deref().unwrap_or_default(),
        )
        .await?
    };
    Ok(tokens.into_credential(discovery.token_endpoint, client_id.to_string(), secret))
}

fn scope_or_default(scope: &str) -> &str {
    if scope.trim().is_empty() {
        DEFAULT_SCOPE
    } else {
        scope
    }
}

/// Drop the credential, or the whole profile with `--all`.
pub fn logout(ctx: &mut Ctx, args: &LogoutArgs) -> Result<()> {
    let name = ctx.name.clone();
    if args.all {
        if !ctx.store.remove(&name) {
            return Err(CliError::usage(format!("no profile named `{name}`")));
        }
        ctx.store.save()?;
        println!("Profile `{name}` removed.");
        return Ok(());
    }
    let Some(profile) = ctx.store.get(&name).cloned() else {
        return Err(CliError::usage(format!("no profile named `{name}`")));
    };
    ctx.store.put(
        &name,
        crate::config::Profile {
            credential: None,
            ..profile
        },
    );
    ctx.store.save()?;
    println!("Credential for profile `{name}` forgotten.");
    Ok(())
}

/// `/admin/me`: who the token is, and what it may do.
pub async fn whoami(ctx: &mut Ctx) -> Result<()> {
    let api = ctx.api().await?;
    let me = api.get("/admin/me", &[]).await?;
    if ctx.output.is_json() {
        return output::json(&me);
    }
    println!(
        "user        {} ({})",
        output::field(&me, "username"),
        output::field(&me, "user_id")
    );
    println!("tenant      {}", output::field(&me, "tenant_slug"));
    println!("scope       {}", output::field(&me, "scope"));
    println!("roles       {}", join(&me, "roles"));
    println!("permissions {}", join(&me, "permissions"));
    // A token issued in a session that acts in an organization also carries
    // what is granted inside it (never a personal access token's).
    if let Some(org) = me.get("organization").filter(|v| !v.is_null()) {
        println!(
            "org         {} ({})",
            output::field(org, "display_name"),
            output::field(org, "slug")
        );
        println!("org perms   {}", join(&me, "organization_permissions"));
    }
    Ok(())
}

fn join(value: &Value, key: &str) -> String {
    let items: Vec<String> = value
        .get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|v| v.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default();
    if items.is_empty() {
        "-".to_string()
    } else {
        items.join(", ")
    }
}
