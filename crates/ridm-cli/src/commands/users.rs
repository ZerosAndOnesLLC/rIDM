//! `ridm user create | reset`.
//!
//! Both take a user by id, username or email address; a name that is not a
//! UUID is resolved through the admin user search and must match exactly one
//! account, so a typo never resets somebody else's password.

use serde_json::{Map, Value, json};

use crate::api::Api;
use crate::cli::UserCommand;
use crate::context::Ctx;
use crate::error::{CliError, Result};
use crate::{input, output};

pub async fn run(ctx: &mut Ctx, command: &UserCommand) -> Result<()> {
    let json_out = ctx.output.is_json();
    let tenant = ctx.tenant.clone();
    match command {
        UserCommand::Create { .. } => {
            let body = create_body(command)?;
            let api = ctx.api().await?;
            let user = api
                .post(&format!("/admin/tenants/{tenant}/users"), &[], &body)
                .await?;
            if json_out {
                return output::json(&user);
            }
            println!(
                "User `{}` created ({}).",
                output::field(&user, "username"),
                output::field(&user, "id")
            );
            if let Some(temp) = user.get("temporary_password").and_then(Value::as_str) {
                output::secret("temporary password", temp);
            }
            Ok(())
        }
        UserCommand::Reset {
            user,
            password_stdin,
            no_must_change,
            skip_policy,
            notify,
            revoke_sessions,
        } => {
            let password = if *password_stdin {
                Some(input::line_from_stdin("the new password")?.to_string())
            } else {
                None
            };
            let body = json!({
                "password": password,
                "must_change": !*no_must_change,
                "skip_policy": *skip_policy,
                "notify": *notify,
                "revoke_sessions": *revoke_sessions,
            });
            let user = user.clone();
            let api = ctx.api().await?;
            let id = resolve(&api, &tenant, &user).await?;
            let res = api
                .put(
                    &format!("/admin/tenants/{tenant}/users/{id}/password"),
                    &body,
                )
                .await?;
            if json_out {
                return output::json(&res);
            }
            match res.get("temporary_password").and_then(Value::as_str) {
                Some(temp) => {
                    println!("Password of `{user}` ({id}) reset.");
                    output::secret("temporary password", temp);
                }
                None => println!("Password of `{user}` ({id}) set."),
            }
            Ok(())
        }
    }
}

/// `NewUser` plus the password fields the create endpoint takes alongside it.
fn create_body(command: &UserCommand) -> Result<Value> {
    let UserCommand::Create {
        username,
        email,
        email_verified,
        phone,
        locale,
        status,
        external_id,
        attributes,
        password_stdin,
        temporary_password,
    } = command
    else {
        return Err(CliError::usage("not a create command"));
    };
    let mut body = Map::new();
    body.insert("username".into(), json!(username));
    insert_some(&mut body, "email", email.clone());
    if *email_verified {
        body.insert("email_verified".into(), json!(true));
    }
    insert_some(&mut body, "phone", phone.clone());
    insert_some(&mut body, "locale", locale.clone());
    insert_some(&mut body, "status", status.clone());
    insert_some(&mut body, "external_id", external_id.clone());
    if let Some(text) = attributes {
        let value: Value = serde_json::from_str(text)
            .map_err(|e| CliError::usage(format!("--attributes is not JSON: {e}")))?;
        if !value.is_object() {
            return Err(CliError::usage("--attributes must be a JSON object"));
        }
        body.insert("attributes".into(), value);
    }
    if *password_stdin {
        body.insert(
            "password".into(),
            json!(input::line_from_stdin("the password")?.to_string()),
        );
    } else if *temporary_password {
        body.insert("temporary_password".into(), json!(true));
    }
    Ok(Value::Object(body))
}

fn insert_some(body: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        body.insert(key.to_string(), json!(v));
    }
}

/// A user id, or the one account whose username or email is `needle`.
async fn resolve(api: &Api, tenant: &str, needle: &str) -> Result<String> {
    if uuid::Uuid::parse_str(needle).is_ok() {
        return Ok(needle.to_string());
    }
    let page = api
        .get(
            &format!("/admin/tenants/{tenant}/users"),
            &[("search", needle.to_string()), ("limit", "50".to_string())],
        )
        .await?;
    let lower = needle.to_lowercase();
    let matches: Vec<Value> = output::items(&page)
        .into_iter()
        .filter(|u| {
            [output::field(u, "username"), output::field(u, "email")]
                .iter()
                .any(|v| v.to_lowercase() == lower)
        })
        .collect();
    match matches.as_slice() {
        [one] => Ok(output::field(one, "id")),
        [] => Err(CliError::failed(format!(
            "no user in `{tenant}` with the username or email `{needle}`"
        ))),
        many => Err(CliError::failed(format!(
            "`{needle}` matches {} users in `{tenant}`; give the user id instead",
            many.len()
        ))),
    }
}
