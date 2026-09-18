//! `ridm client create` and `ridm client iat create | list | revoke`.
//!
//! Only the fields an operator sets by hand are flags; everything else takes
//! the server's type-driven defaults (a `spa` is public and needs PKCE, a
//! `machine` client gets client credentials, and so on). The secret of a
//! confidential client is printed once and never again.

use serde_json::{Map, Value, json};

use crate::cli::{ClientCommand, ClientCreate, IatCommand};
use crate::context::Ctx;
use crate::error::Result;
use crate::output;

pub async fn run(ctx: &mut Ctx, command: &ClientCommand) -> Result<()> {
    let command = match command {
        ClientCommand::Create(create) => create,
        ClientCommand::Iat { command } => return iat(ctx, command).await,
    };
    let json_out = ctx.output.is_json();
    let tenant = ctx.tenant.clone();
    let body = create_body(command);
    let api = ctx.api().await?;
    let client = api
        .post(&format!("/admin/tenants/{tenant}/clients"), &[], &body)
        .await?;
    if json_out {
        return output::json(&client);
    }
    println!(
        "Client `{}` created ({}).",
        output::field(&client, "client_id"),
        output::field(&client, "name")
    );
    if let Some(secret) = client.get("client_secret").and_then(Value::as_str) {
        output::secret("client secret", secret);
    }
    Ok(())
}

/// Initial access tokens for dynamic client registration.
async fn iat(ctx: &mut Ctx, command: &IatCommand) -> Result<()> {
    let json_out = ctx.output.is_json();
    let tenant = ctx.tenant.clone();
    let path = format!("/admin/tenants/{tenant}/dcr/initial-access-tokens");
    let api = ctx.api().await?;
    match command {
        IatCommand::Create {
            description,
            expires_in,
            max_uses,
        } => {
            let body = iat_body(description.as_deref(), *expires_in, *max_uses);
            let created = api.post(&path, &[], &body).await?;
            if json_out {
                return output::json(&created);
            }
            println!(
                "Initial access token {} issued (expires: {}, uses: {}).",
                output::field(&created, "id"),
                output::field(&created, "expires_at"),
                output::field(&created, "max_uses"),
            );
            if let Some(token) = created.get("token").and_then(Value::as_str) {
                output::secret("initial access token", token);
            }
            Ok(())
        }
        IatCommand::List => {
            let tokens = api.get(&path, &[]).await?;
            if json_out {
                return output::json(&tokens);
            }
            let rows: Vec<Vec<String>> = output::items(&tokens)
                .iter()
                .map(|t| {
                    vec![
                        output::field(t, "id"),
                        output::field(t, "description"),
                        format!(
                            "{}/{}",
                            output::field(t, "uses"),
                            output::field(t, "max_uses")
                        ),
                        output::field(t, "expires_at"),
                        output::field(t, "revoked_at"),
                    ]
                })
                .collect();
            output::table(&["ID", "DESCRIPTION", "USES", "EXPIRES", "REVOKED"], &rows);
            Ok(())
        }
        IatCommand::Revoke { id } => {
            api.delete(&format!("{path}/{id}")).await?;
            if json_out {
                return output::json(&json!({"revoked": id}));
            }
            println!("Initial access token {id} revoked.");
            Ok(())
        }
    }
}

/// Only what was given: an absent expiry or budget means none.
fn iat_body(description: Option<&str>, expires_in: Option<u64>, max_uses: Option<u32>) -> Value {
    let mut body = Map::new();
    if let Some(d) = description {
        body.insert("description".into(), json!(d));
    }
    if let Some(s) = expires_in {
        body.insert("expires_in_secs".into(), json!(s));
    }
    if let Some(n) = max_uses {
        body.insert("max_uses".into(), json!(n));
    }
    Value::Object(body)
}

fn create_body(command: &ClientCreate) -> Value {
    let ClientCreate {
        name,
        client_id,
        client_type,
        redirect_uris,
        post_logout_redirect_uris,
        grants,
        scopes,
        audiences,
        cors_origins,
        auth_method,
        description,
        no_pkce,
        no_consent,
    } = command;
    let mut body = Map::new();
    body.insert("name".into(), json!(name));
    insert_some(&mut body, "client_id", client_id.clone());
    insert_some(&mut body, "client_type", client_type.clone());
    insert_some(&mut body, "token_endpoint_auth_method", auth_method.clone());
    insert_some(&mut body, "description", description.clone());
    body.insert("redirect_uris".into(), json!(redirect_uris));
    body.insert(
        "post_logout_redirect_uris".into(),
        json!(post_logout_redirect_uris),
    );
    body.insert("allowed_audiences".into(), json!(audiences));
    body.insert("cors_origins".into(), json!(cors_origins));
    // `allowed_grants` and `allowed_scopes` absent means "the defaults for
    // this client type"; an empty list would mean "none at all".
    if !grants.is_empty() {
        body.insert("allowed_grants".into(), json!(grants));
    }
    if !scopes.is_empty() {
        body.insert("allowed_scopes".into(), json!(scopes));
    }
    if *no_pkce {
        body.insert("require_pkce".into(), json!(false));
    }
    if *no_consent {
        body.insert("require_consent".into(), json!(false));
    }
    Value::Object(body)
}

fn insert_some(body: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        body.insert(key.to_string(), json!(v));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    use crate::cli::{Cli, Command};

    #[test]
    fn an_initial_access_token_body_carries_only_what_was_given() {
        assert_eq!(iat_body(None, None, None), json!({}));
        assert_eq!(
            iat_body(Some("ci"), Some(3600), Some(5)),
            json!({"description": "ci", "expires_in_secs": 3600, "max_uses": 5})
        );
    }

    #[test]
    fn iat_subcommands_parse() {
        let cli = Cli::try_parse_from([
            "ridm",
            "client",
            "iat",
            "create",
            "--max-uses",
            "2",
            "--expires-in",
            "600",
        ])
        .unwrap();
        let Command::Client {
            command:
                ClientCommand::Iat {
                    command:
                        IatCommand::Create {
                            max_uses,
                            expires_in,
                            description,
                        },
                },
        } = cli.command
        else {
            panic!("parsed as {:?}", cli.command);
        };
        assert_eq!(
            (max_uses, expires_in, description),
            (Some(2), Some(600), None)
        );
        let cli = Cli::try_parse_from(["ridm", "client", "iat", "revoke", "abc"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Client {
                command: ClientCommand::Iat {
                    command: IatCommand::Revoke { .. }
                }
            }
        ));
    }
}
