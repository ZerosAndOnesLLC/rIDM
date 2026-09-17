//! Getting a bearer token for the admin API, and keeping it fresh.
//!
//! Three ways in, in the order an operator meets them:
//!
//! * a **personal access token** (`rpat_…`) minted in the account console —
//!   nothing to register, works against any server, the default of
//!   `ridm login`;
//! * **client credentials** of a machine client whose service-account user
//!   holds admin roles — for CI, where nobody can approve anything;
//! * the **device authorization grant** (RFC 8628) against a client that
//!   allows it — the operator approves in a browser and the CLI keeps a
//!   refresh token.
//!
//! Whatever the grant, the token must carry `urn:ridm:admin` in `aud`, so the
//! CLI always asks for that resource.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use crate::config::{Credential, Profile};
use crate::error::{CliError, OAuthError, Result};

/// Resource indicator every admin token must be issued for.
pub const ADMIN_AUDIENCE: &str = "urn:ridm:admin";
/// Scope the CLI asks for in a user-facing grant.
pub const DEFAULT_SCOPE: &str = "openid";
/// Refresh this long before the access token actually expires.
const REFRESH_MARGIN: chrono::TimeDelta = chrono::TimeDelta::seconds(60);
/// Give up polling a device code after this long, whatever the server said.
const DEVICE_CEILING: Duration = Duration::from_secs(15 * 60);

/// The parts of the discovery document the CLI uses.
#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    pub token_endpoint: String,
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
}

/// Read `{url}/t/{tenant}/.well-known/openid-configuration`.
pub async fn discover(http: &reqwest::Client, url: &str, tenant: &str) -> Result<Discovery> {
    let url = format!(
        "{}/t/{tenant}/.well-known/openid-configuration",
        crate::config::normalize_url(url)
    );
    let res = http.get(&url).send().await?;
    if !res.status().is_success() {
        return Err(CliError::failed(format!(
            "{url} → {}: is the server URL right, and does the tenant `{tenant}` exist?",
            res.status()
        )));
    }
    res.json::<Discovery>()
        .await
        .map_err(|e| CliError::failed(format!("{url}: unreadable discovery document: {e}")))
}

/// A token endpoint response.
#[derive(Debug, Clone, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub scope: Option<String>,
}

impl Tokens {
    fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_in
            .and_then(chrono::TimeDelta::try_seconds)
            .map(|d| Utc::now() + d)
    }

    /// Store what is needed to get the next token without asking again.
    pub fn into_credential(
        self,
        token_endpoint: String,
        client_id: String,
        client_secret: Option<String>,
    ) -> Credential {
        Credential::Oauth {
            token_endpoint,
            client_id,
            client_secret,
            expires_at: self.expires_at(),
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            scope: self.scope,
            resource: Some(ADMIN_AUDIENCE.to_string()),
        }
    }
}

/// POST a form to the token endpoint, mapping an OAuth error response to
/// [`OAuthError`] rather than to a bare status code.
async fn token_request(
    http: &reqwest::Client,
    endpoint: &str,
    form: &[(&str, &str)],
) -> Result<std::result::Result<Tokens, OAuthError>> {
    let res = http.post(endpoint).form(form).send().await?;
    let status = res.status();
    let text = res.text().await?;
    if status.is_success() {
        return Ok(Ok(serde_json::from_str(&text).map_err(|e| {
            CliError::failed(format!("{endpoint}: unreadable token response: {e}"))
        })?));
    }
    let doc: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let code = doc
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or_else(|| status.canonical_reason().unwrap_or("error"))
        .to_string();
    let description = doc
        .get("error_description")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(Err(OAuthError { code, description }))
}

/// `client_credentials` for a machine client: no browser, no refresh token.
pub async fn client_credentials(
    http: &reqwest::Client,
    endpoint: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<Tokens> {
    token_request(
        http,
        endpoint,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("resource", ADMIN_AUDIENCE),
        ],
    )
    .await?
    .map_err(|e| CliError::failed(format!("client credentials refused: {e}")))
}

/// RFC 8628: ask for a code, print it, poll until the operator approves.
pub async fn device_login(
    http: &reqwest::Client,
    discovery: &Discovery,
    client_id: &str,
    client_secret: Option<&str>,
    scope: &str,
) -> Result<Tokens> {
    let endpoint = discovery
        .device_authorization_endpoint
        .as_deref()
        .ok_or_else(|| {
            CliError::failed(
                "this tenant does not offer the device authorization grant; \
             use `--client-secret` or a personal access token instead",
            )
        })?;
    let mut form = vec![
        ("client_id", client_id),
        ("scope", scope),
        ("resource", ADMIN_AUDIENCE),
    ];
    if let Some(secret) = client_secret {
        form.push(("client_secret", secret));
    }
    let res = http.post(endpoint).form(&form).send().await?;
    let status = res.status();
    let text = res.text().await?;
    if !status.is_success() {
        let doc: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        return Err(CliError::failed(format!(
            "{endpoint} → {status}: {}",
            doc.get("error_description")
                .or_else(|| doc.get("error"))
                .and_then(Value::as_str)
                .unwrap_or(text.trim())
        )));
    }
    let auth: DeviceAuthorization = serde_json::from_str(&text)
        .map_err(|e| CliError::failed(format!("{endpoint}: unreadable response: {e}")))?;

    eprintln!("Open {} and enter the code", auth.verification_uri);
    eprintln!("\n    {}\n", auth.user_code);
    eprintln!("Or open {} directly.", auth.verification_uri_complete);
    eprintln!("Waiting for approval…");

    let mut interval = Duration::from_secs(auth.interval.clamp(1, 60));
    let deadline =
        std::time::Instant::now() + Duration::from_secs(auth.expires_in).min(DEVICE_CEILING);
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(CliError::failed(
                "the device code expired before it was approved",
            ));
        }
        tokio::time::sleep(interval).await;
        let mut form = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", auth.device_code.as_str()),
            ("client_id", client_id),
        ];
        if let Some(secret) = client_secret {
            form.push(("client_secret", secret));
        }
        match token_request(http, &discovery.token_endpoint, &form).await? {
            Ok(tokens) => return Ok(tokens),
            Err(e) if e.code == "authorization_pending" => {}
            // RFC 8628 §3.5: back off by five seconds and keep going.
            Err(e) if e.code == "slow_down" => interval += Duration::from_secs(5),
            Err(e) => {
                return Err(CliError::failed(format!(
                    "device authorization refused: {e}"
                )));
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct DeviceAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
}

/// The bearer token for this command, renewing it when it is about to expire.
///
/// Returns the credential to store when it changed, so the caller decides
/// whether the profile file is written (a `--token` override never is).
pub async fn bearer(
    http: &reqwest::Client,
    profile: &Profile,
) -> Result<(String, Option<Credential>)> {
    let credential = profile.credential.as_ref().ok_or_else(|| {
        CliError::usage(
            "this profile has no credential: run `ridm login`, or pass --token / set RIDM_TOKEN",
        )
    })?;
    match credential {
        Credential::Token { token } => Ok((token.clone(), None)),
        Credential::Oauth {
            token_endpoint,
            client_id,
            client_secret,
            access_token,
            refresh_token,
            expires_at,
            scope,
            resource,
        } => {
            let fresh = expires_at.is_none_or(|t| t > Utc::now() + REFRESH_MARGIN);
            if fresh {
                return Ok((access_token.clone(), None));
            }
            let renewed = renew(
                http,
                token_endpoint,
                client_id,
                client_secret.as_deref(),
                refresh_token.as_deref(),
                scope.as_deref(),
                resource.as_deref(),
            )
            .await?;
            let token = renewed.access_token.clone();
            // A refresh that returned no new refresh token keeps the old one.
            let carried = renewed
                .refresh_token
                .clone()
                .or_else(|| refresh_token.clone());
            let mut credential = renewed.into_credential(
                token_endpoint.clone(),
                client_id.clone(),
                client_secret.clone(),
            );
            if let Credential::Oauth { refresh_token, .. } = &mut credential {
                *refresh_token = carried;
            }
            Ok((token, Some(credential)))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn renew(
    http: &reqwest::Client,
    endpoint: &str,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: Option<&str>,
    scope: Option<&str>,
    resource: Option<&str>,
) -> Result<Tokens> {
    if let Some(refresh) = refresh_token {
        let mut form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", client_id),
        ];
        if let Some(secret) = client_secret {
            form.push(("client_secret", secret));
        }
        if let Some(s) = scope {
            form.push(("scope", s));
        }
        if let Some(r) = resource {
            form.push(("resource", r));
        }
        match token_request(http, endpoint, &form).await? {
            Ok(tokens) => return Ok(tokens),
            Err(e) if client_secret.is_none() => {
                return Err(CliError::failed(format!(
                    "the stored session could not be refreshed ({e}); run `ridm login` again"
                )));
            }
            // A confidential client can simply ask for a new token.
            Err(_) => {}
        }
    }
    let secret = client_secret.ok_or_else(|| {
        CliError::usage("the stored session expired and cannot be renewed; run `ridm login` again")
    })?;
    client_credentials(http, endpoint, client_id, secret).await
}
