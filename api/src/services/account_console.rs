//! The built-in OIDC client the account console signs in with.
//!
//! Every tenant carries a public, PKCE-only `ridm-account-console` client
//! whose only audience is the built-in account resource server, so a user's
//! browser session obtains tokens that reach `/t/{slug}/account/...` and
//! nothing else. Like the admin console's client it follows `UI_URL`, cannot
//! be deleted and is left out of tenant exports. Unlike the admin console,
//! the account console is also served on a tenant's custom domain (by a node
//! serving the embedded UI), so the client accepts that host's pages too.

use crate::config::Config;
use crate::config::page_url;
use crate::error::AppResult;
use crate::models::grants;
use crate::models::{
    Client, ClientType, NewClient, STANDARD_SCOPES, Tenant, TokenEndpointAuthMethod,
};
use crate::services::admin_console;
use crate::state::AppState;

/// Audience of the self-service account API (a built-in resource server in
/// every tenant, seeded by migration).
pub const ACCOUNT_AUDIENCE: &str = "urn:ridm:account";
/// Public `client_id` of the account console client in every tenant.
pub const ACCOUNT_CLIENT_ID: &str = "ridm-account-console";

/// Is this the built-in account console client?
pub fn is_account_client(client_id: &str) -> bool {
    client_id == ACCOUNT_CLIENT_ID
}

/// UI page the authorization code is sent back to.
pub fn callback_uri(config: &Config) -> String {
    config.ui_page("account/callback", &[])
}

/// Where the browser lands after signing out of the account console.
pub fn home_uri(config: &Config) -> String {
    config.ui_page("account", &[])
}

/// The client as it should look for the current configuration and `tenant`:
/// the pages under `UI_URL`, plus those on the tenant's custom domain when
/// this node serves the embedded UI there.
pub fn desired(state: &AppState, tenant: &Tenant) -> NewClient {
    let config = &state.config;
    let mut redirect_uris = vec![callback_uri(config)];
    let mut post_logout_redirect_uris = vec![home_uri(config)];
    if let Some(base) = state.tenant_ui_base(tenant) {
        redirect_uris.push(page_url(&base, "account/callback", &[]));
        post_logout_redirect_uris.push(page_url(&base, "account", &[]));
    }
    NewClient {
        client_id: Some(ACCOUNT_CLIENT_ID.into()),
        name: "rIDM Account".into(),
        client_type: Some(ClientType::Spa),
        description: Some("Built-in client of the bundled account console.".into()),
        token_endpoint_auth_method: Some(TokenEndpointAuthMethod::None),
        redirect_uris,
        post_logout_redirect_uris,
        allowed_grants: Some(vec![
            grants::AUTHORIZATION_CODE.into(),
            grants::REFRESH_TOKEN.into(),
        ]),
        allowed_scopes: Some(STANDARD_SCOPES.iter().map(|s| s.to_string()).collect()),
        allowed_audiences: vec![ACCOUNT_AUDIENCE.into()],
        require_pkce: Some(true),
        require_consent: Some(false),
        ..Default::default()
    }
}

/// Create the account client in `tenant`, or re-point it at the configured
/// UI (and the tenant's custom domain). Called at startup, on tenant creation
/// and whenever a tenant's custom domain changes.
pub async fn ensure(state: &AppState, tenant: &Tenant) -> AppResult<Client> {
    admin_console::ensure_builtin(state, tenant.id, ACCOUNT_CLIENT_ID, desired(state, tenant)).await
}

/// Bring every tenant's account client in line (startup).
pub async fn ensure_all(state: &AppState) -> AppResult<()> {
    admin_console::for_every_tenant(state, |t| async move { ensure(state, &t).await }).await
}
