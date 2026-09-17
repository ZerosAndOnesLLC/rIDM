//! What a command needs before it can run: which server, which tenant, which
//! token — resolved once from the flags, the environment and the profile.

use crate::api::Api;
use crate::auth;
use crate::cli::Global;
use crate::config::{Credential, DEFAULT_PROFILE, DEFAULT_TENANT, Profile, Store, normalize_url};
use crate::error::{CliError, Result};
use crate::output::Format;

pub struct Ctx {
    pub http: reqwest::Client,
    pub store: Store,
    /// Profile the command reads and (for `login`/`logout`) writes.
    pub name: String,
    /// The profile as the flags leave it; not necessarily stored yet.
    pub profile: Profile,
    /// Tenant the command acts on.
    pub tenant: String,
    pub output: Format,
    /// A token from `--token`/`RIDM_TOKEN`, which is never written to disk.
    token_override: Option<String>,
}

impl Ctx {
    pub fn resolve(global: &Global) -> Result<Self> {
        let store = Store::load()?;
        let name = global
            .profile
            .clone()
            .unwrap_or_else(|| store.current_name());
        let stored = store.get(&name).cloned();
        let url = global
            .url
            .as_deref()
            .map(normalize_url)
            .or_else(|| stored.as_ref().map(|p| p.url.clone()));
        let tenant = global
            .tenant
            .clone()
            .or_else(|| stored.as_ref().map(|p| p.tenant.clone()))
            .unwrap_or_else(|| DEFAULT_TENANT.to_string());
        let profile = Profile {
            url: url.unwrap_or_default(),
            tenant: stored
                .as_ref()
                .map(|p| p.tenant.clone())
                .unwrap_or_else(|| tenant.clone()),
            credential: stored.and_then(|p| p.credential),
        };
        Ok(Self {
            http: http_client()?,
            store,
            name,
            profile,
            tenant,
            output: global.output,
            token_override: global.token.clone(),
        })
    }

    /// The server origin, or a pointed message about how to supply one.
    pub fn url(&self) -> Result<&str> {
        if self.profile.url.is_empty() {
            return Err(CliError::usage(format!(
                "no server URL: run `ridm login --url https://… --name {}`, \
                 or pass --url / set RIDM_URL",
                if self.name.is_empty() {
                    DEFAULT_PROFILE
                } else {
                    &self.name
                }
            )));
        }
        Ok(&self.profile.url)
    }

    /// An authenticated client for the admin API. A credential that had to be
    /// renewed is written back to the profile, so the next command reuses it.
    pub async fn api(&mut self) -> Result<Api> {
        let url = self.url()?.to_string();
        if let Some(token) = &self.token_override {
            return Ok(Api::new(self.http.clone(), url, token.clone()));
        }
        let (bearer, renewed) = auth::bearer(&self.http, &self.profile).await?;
        if let Some(credential) = renewed {
            self.remember(credential)?;
        }
        Ok(Api::new(self.http.clone(), url, bearer))
    }

    /// Store a credential in this profile and write the file.
    pub fn remember(&mut self, credential: Credential) -> Result<()> {
        self.profile.credential = Some(credential);
        let name = self.name.clone();
        let profile = self.profile.clone();
        self.store.put(&name, profile);
        self.store.save()
    }
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("ridm-cli/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| CliError::failed(format!("HTTP client: {e}")))
}
