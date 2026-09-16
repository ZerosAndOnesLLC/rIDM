//! The built-in OIDC client the admin console signs in with.
//!
//! Every tenant carries a public, PKCE-only `ridm-admin-console` client whose
//! only audience is the admin resource server, so a browser session in any
//! tenant can obtain admin tokens for that tenant (or, from `master`, for all
//! of them). Its redirect URIs derive from `UI_URL`; the client is created at
//! startup and with every new tenant, and brought back in line when the UI
//! moves. It cannot be deleted and is left out of tenant exports.

use ridm_core::events::Actor;
use uuid::Uuid;

use crate::config::Config;
use crate::error::AppResult;
use crate::models::grants;
use crate::models::{Client, ClientType, NewClient, STANDARD_SCOPES, TokenEndpointAuthMethod};
use crate::repos;
use crate::services::admin_access::ADMIN_AUDIENCE;
use crate::services::clients;
use crate::state::AppState;

/// Public `client_id` of the console client in every tenant.
pub const CONSOLE_CLIENT_ID: &str = "ridm-admin-console";

/// Is this the built-in admin console client?
pub fn is_console_client(client_id: &str) -> bool {
    client_id == CONSOLE_CLIENT_ID
}

/// Is this one of the built-in console clients (admin or account)? Those
/// follow `UI_URL`, cannot be deleted and stay out of tenant exports.
pub fn is_builtin_client(client_id: &str) -> bool {
    is_console_client(client_id) || super::account_console::is_account_client(client_id)
}

/// UI page the authorization code is sent back to.
pub fn callback_uri(config: &Config) -> String {
    config.ui_page("console/callback", &[])
}

/// Where the browser lands after signing out of the console.
pub fn home_uri(config: &Config) -> String {
    config.ui_page("console", &[])
}

/// The client as it should look for the current configuration.
pub fn desired(config: &Config) -> NewClient {
    NewClient {
        client_id: Some(CONSOLE_CLIENT_ID.into()),
        name: "rIDM Admin Console".into(),
        client_type: Some(ClientType::Spa),
        description: Some("Built-in client of the bundled administration console.".into()),
        token_endpoint_auth_method: Some(TokenEndpointAuthMethod::None),
        redirect_uris: vec![callback_uri(config)],
        post_logout_redirect_uris: vec![home_uri(config)],
        allowed_grants: Some(vec![
            grants::AUTHORIZATION_CODE.into(),
            grants::REFRESH_TOKEN.into(),
        ]),
        allowed_scopes: Some(STANDARD_SCOPES.iter().map(|s| s.to_string()).collect()),
        allowed_audiences: vec![ADMIN_AUDIENCE.into()],
        require_pkce: Some(true),
        require_consent: Some(false),
        ..Default::default()
    }
}

/// Create the console client in `tenant_id`, or re-point its URIs at the
/// configured UI. Everything else an administrator may have tuned (token
/// lifetimes, status, CORS origins) is left alone.
pub async fn ensure(state: &AppState, tenant_id: Uuid) -> AppResult<Client> {
    ensure_builtin(state, tenant_id, CONSOLE_CLIENT_ID, desired(&state.config)).await
}

/// Create a built-in client, or bring its URIs, audiences and auth method
/// back in line with `want`; the rest is left as an administrator set it.
pub async fn ensure_builtin(
    state: &AppState,
    tenant_id: Uuid,
    client_id: &str,
    want: NewClient,
) -> AppResult<Client> {
    let existing = clients::find_by_client_id(state, tenant_id, client_id).await?;
    let Some(current) = existing else {
        let created = clients::create(state, tenant_id, Actor::System, want).await?;
        tracing::info!(%tenant_id, client_id, "built-in client created");
        return Ok(created.client);
    };
    let in_line = current.redirect_uris == want.redirect_uris
        && current.post_logout_redirect_uris == want.post_logout_redirect_uris
        && current.allowed_audiences == want.allowed_audiences
        && current.token_endpoint_auth_method == TokenEndpointAuthMethod::None
        && current.require_pkce
        && want
            .allowed_grants
            .as_ref()
            .is_some_and(|g| g.iter().all(|w| current.allowed_grants.contains(w)));
    if in_line {
        return Ok((*current).clone());
    }
    let input = NewClient {
        name: current.name.clone(),
        description: current.description.clone(),
        logo_uri: current.logo_uri.clone(),
        client_uri: current.client_uri.clone(),
        access_token_ttl_secs: current.access_token_ttl_secs,
        refresh_token_ttl_secs: current.refresh_token_ttl_secs,
        id_token_ttl_secs: current.id_token_ttl_secs,
        cors_origins: current.cors_origins.clone(),
        dpop_bound_access_tokens: Some(current.dpop_bound_access_tokens),
        ..want
    };
    let (client, _) =
        clients::update_metadata(state, tenant_id, Actor::System, current.id, input).await?;
    tracing::info!(%tenant_id, client_id, "built-in client updated for the configured UI_URL");
    Ok(client)
}

/// Bring every tenant's console client in line (startup).
pub async fn ensure_all(state: &AppState) -> AppResult<()> {
    for_every_tenant(state, |tid| ensure(state, tid)).await
}

/// Run `f` for every tenant, a page at a time.
pub async fn for_every_tenant<F, Fut>(state: &AppState, f: F) -> AppResult<()>
where
    F: Fn(Uuid) -> Fut,
    Fut: Future<Output = AppResult<Client>>,
{
    let mut after = None;
    loop {
        let rows = repos::tenants::list(&state.db, after.take(), 200).await?;
        let more = rows.len() > 200;
        for t in rows.iter().take(200) {
            f(t.id).await?;
        }
        if !more {
            return Ok(());
        }
        after = rows.get(199).map(|t| crate::util::cursor::Cursor {
            created_at: t.created_at,
            id: t.id,
        });
    }
}
