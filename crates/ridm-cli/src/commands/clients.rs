//! `ridm client create`.
//!
//! Only the fields an operator sets by hand are flags; everything else takes
//! the server's type-driven defaults (a `spa` is public and needs PKCE, a
//! `machine` client gets client credentials, and so on). The secret of a
//! confidential client is printed once and never again.

use serde_json::{Map, Value, json};

use crate::cli::ClientCommand;
use crate::context::Ctx;
use crate::error::Result;
use crate::output;

pub async fn run(ctx: &mut Ctx, command: &ClientCommand) -> Result<()> {
    let ClientCommand::Create { .. } = command;
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

fn create_body(command: &ClientCommand) -> Value {
    let ClientCommand::Create {
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
