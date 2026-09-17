//! Profiles: where the CLI remembers which server it talks to and what it
//! talks to it with.
//!
//! One JSON file holds every profile (`$RIDM_CONFIG`, else
//! `$XDG_CONFIG_HOME/ridm/config.json`, else `~/.config/ridm/config.json`),
//! written `0600` because a profile may hold a personal access token, a
//! refresh token or a client secret. Nothing is stored until `ridm login`
//! runs: `--url`/`--token` (or `RIDM_URL`/`RIDM_TOKEN`) alone are enough for
//! a one-off command or a CI job, and never touch the file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{CliError, Result};

/// Tenant a profile authenticates against when none is given: global
/// administrators live in `master`.
pub const DEFAULT_TENANT: &str = "master";
pub const DEFAULT_PROFILE: &str = "default";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Document {
    /// Profile used when `--profile`/`RIDM_PROFILE` is absent.
    pub current: Option<String>,
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Origin of the server, without a trailing slash (`https://idm.example.com`).
    pub url: String,
    /// Tenant the credential belongs to, and the default target of commands.
    #[serde(default = "default_tenant")]
    pub tenant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<Credential>,
}

fn default_tenant() -> String {
    DEFAULT_TENANT.to_string()
}

/// What the CLI presents as its bearer token, and what it needs to get a new
/// one when that expires.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Credential {
    /// A personal access token (`rpat_…`), or any bearer token pasted by the
    /// operator. Used as it stands; when it expires, `ridm login` again.
    Token { token: String },
    /// Tokens from an OAuth grant. Refreshed with the refresh token while one
    /// lasts, and for a confidential client re-fetched with its secret.
    Oauth {
        token_endpoint: String,
        client_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_secret: Option<String>,
        access_token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        refresh_token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<DateTime<Utc>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        /// Resource indicator the tokens were asked for (`urn:ridm:admin`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resource: Option<String>,
    },
}

impl Credential {
    /// How the profile is described in `ridm profile list`.
    pub fn describe(&self) -> String {
        match self {
            Self::Token { token } => format!("token {}", redact(token)),
            Self::Oauth {
                client_id,
                expires_at,
                ..
            } => match expires_at {
                Some(t) => format!("oauth {client_id} (expires {})", t.to_rfc3339()),
                None => format!("oauth {client_id}"),
            },
        }
    }
}

/// Enough of a secret to recognise it, never enough to use it.
pub fn redact(secret: &str) -> String {
    let head: String = secret.chars().take(8).collect();
    format!("{head}…")
}

/// Trim the trailing slash so `{url}{path}` is always well formed.
pub fn normalize_url(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

/// The profile file, and the edits made to it.
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    doc: Document,
}

impl Store {
    /// Read the file, or start an empty document when there is none.
    pub fn load() -> Result<Self> {
        let path = default_path()?;
        let doc = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
                CliError::failed(format!(
                    "{}: not a readable profile file: {e}",
                    path.display()
                ))
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Document::default(),
            Err(e) => return Err(CliError::failed(format!("{}: {e}", path.display()))),
        };
        Ok(Self { path, doc })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn document(&self) -> &Document {
        &self.doc
    }

    /// Name of the profile a command without `--profile` acts on.
    pub fn current_name(&self) -> String {
        self.doc
            .current
            .clone()
            .unwrap_or_else(|| DEFAULT_PROFILE.to_string())
    }

    pub fn get(&self, name: &str) -> Option<&Profile> {
        self.doc.profiles.get(name)
    }

    pub fn put(&mut self, name: &str, profile: Profile) {
        self.doc.profiles.insert(name.to_string(), profile);
        if self.doc.current.is_none() {
            self.doc.current = Some(name.to_string());
        }
    }

    pub fn remove(&mut self, name: &str) -> bool {
        let existed = self.doc.profiles.remove(name).is_some();
        if self.doc.current.as_deref() == Some(name) {
            self.doc.current = self.doc.profiles.keys().next().cloned();
        }
        existed
    }

    /// Make `name` the profile commands use by default.
    pub fn select(&mut self, name: &str) -> Result<()> {
        if !self.doc.profiles.contains_key(name) {
            return Err(CliError::usage(format!("no profile named `{name}`")));
        }
        self.doc.current = Some(name.to_string());
        Ok(())
    }

    /// Write the file, creating its directory, owner-readable only.
    pub fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| CliError::failed(format!("{}: {e}", dir.display())))?;
        }
        let body = serde_json::to_string_pretty(&self.doc)? + "\n";
        std::fs::write(&self.path, body)
            .map_err(|e| CliError::failed(format!("{}: {e}", self.path.display())))?;
        restrict(&self.path)?;
        Ok(())
    }
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| CliError::failed(format!("{}: {e}", path.display())))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<()> {
    Ok(())
}

fn default_path() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("RIDM_CONFIG")
        && !p.is_empty()
    {
        return Ok(PathBuf::from(p));
    }
    if let Ok(dir) = std::env::var("XDG_CONFIG_HOME")
        && !dir.is_empty()
    {
        return Ok(PathBuf::from(dir).join("ridm").join("config.json"));
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| {
            CliError::usage("no home directory: set RIDM_CONFIG to the profile file path")
        })?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("ridm")
        .join("config.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_url_never_keeps_its_trailing_slash() {
        assert_eq!(normalize_url("https://idm.example/"), "https://idm.example");
        assert_eq!(normalize_url("https://idm.example"), "https://idm.example");
    }

    #[test]
    fn a_described_credential_shows_no_usable_secret() {
        let token = "rpat_0123456789abcdefghijklmnop";
        let described = Credential::Token {
            token: token.into(),
        }
        .describe();
        assert!(described.starts_with("token rpat_012"), "{described}");
        assert!(!described.contains("9abcdef"), "{described}");
    }

    #[test]
    fn a_profile_without_a_tenant_belongs_to_master() {
        let profile: Profile =
            serde_json::from_str(r#"{"url":"https://idm.example"}"#).expect("profile");
        assert_eq!(profile.tenant, DEFAULT_TENANT);
        assert!(profile.credential.is_none());
    }

    #[test]
    fn a_stored_credential_round_trips_through_the_file_format() {
        let mut doc = Document::default();
        doc.profiles.insert(
            "prod".into(),
            Profile {
                url: "https://idm.example".into(),
                tenant: "master".into(),
                credential: Some(Credential::Oauth {
                    token_endpoint: "https://idm.example/t/master/token".into(),
                    client_id: "ops".into(),
                    client_secret: None,
                    access_token: "at".into(),
                    refresh_token: Some("rt".into()),
                    expires_at: None,
                    scope: Some("openid".into()),
                    resource: Some("urn:ridm:admin".into()),
                }),
            },
        );
        doc.current = Some("prod".into());
        let text = serde_json::to_string(&doc).expect("serialize");
        // Absent fields are left out rather than written as null.
        assert!(!text.contains("client_secret"), "{text}");
        let back: Document = serde_json::from_str(&text).expect("deserialize");
        assert_eq!(back.current.as_deref(), Some("prod"));
        let Some(Credential::Oauth { refresh_token, .. }) =
            back.profiles["prod"].credential.as_ref()
        else {
            panic!("credential kind lost in the round trip");
        };
        assert_eq!(refresh_token.as_deref(), Some("rt"));
    }

    fn store(profiles: &[&str]) -> Store {
        let mut doc = Document::default();
        for name in profiles {
            doc.profiles.insert(
                (*name).to_string(),
                Profile {
                    url: format!("https://{name}.example"),
                    tenant: DEFAULT_TENANT.into(),
                    credential: None,
                },
            );
        }
        doc.current = profiles.first().map(|n| (*n).to_string());
        Store {
            path: PathBuf::from("/nonexistent/config.json"),
            doc,
        }
    }

    #[test]
    fn the_first_profile_stored_becomes_the_selected_one() {
        let mut s = Store {
            path: PathBuf::from("/nonexistent/config.json"),
            doc: Document::default(),
        };
        assert_eq!(s.current_name(), DEFAULT_PROFILE);
        s.put(
            "prod",
            Profile {
                url: "https://idm.example".into(),
                tenant: DEFAULT_TENANT.into(),
                credential: None,
            },
        );
        assert_eq!(s.current_name(), "prod");
        // A second profile does not steal the selection.
        s.put(
            "staging",
            Profile {
                url: "https://staging.example".into(),
                tenant: DEFAULT_TENANT.into(),
                credential: None,
            },
        );
        assert_eq!(s.current_name(), "prod");
    }

    #[test]
    fn removing_the_selected_profile_selects_another_one() {
        let mut s = store(&["prod", "staging"]);
        assert!(s.remove("prod"));
        assert_eq!(s.current_name(), "staging");
        assert!(!s.remove("prod"));
    }

    #[test]
    fn a_profile_that_does_not_exist_cannot_be_selected() {
        let mut s = store(&["prod"]);
        assert!(s.select("nope").is_err());
        assert_eq!(s.current_name(), "prod");
    }
}
