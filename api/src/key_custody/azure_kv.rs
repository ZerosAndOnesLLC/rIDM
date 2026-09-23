//! Azure Key Vault / Managed HSM (`kms-azure`): `wrapkey` / `unwrapkey` over
//! REST. The key id Key Vault answers with (it names the key version) is what
//! is stored, with the algorithm, so rotating the key in Key Vault or
//! changing `AZURE_KEY_VAULT_ALGORITHM` leaves older generations readable.
//!
//! A token comes from, in order: workload identity (`AZURE_FEDERATED_TOKEN_FILE`,
//! as the AKS webhook sets it, or any cluster federated with Entra ID), a
//! client secret, the App Service / Container Apps identity endpoint, or the
//! instance metadata service (a VM's managed identity).

use async_trait::async_trait;
use ridm_core::providers::{KeyWrapper, ProviderError, WrappedKey};
use serde_json::json;
use url::Url;
use zeroize::Zeroizing;

use super::config::{AzureCredential, AzureKeyVaultConfig};
use super::http;

const API_VERSION: &str = "7.4";

pub struct AzureKeyVault {
    http: reqwest::Client,
    config: AzureKeyVaultConfig,
    /// `https://vault.azure.net` and the like: what the token is for.
    resource: String,
}

impl AzureKeyVault {
    pub fn new(config: &AzureKeyVaultConfig) -> Result<Self, ProviderError> {
        Ok(Self {
            http: http::client(None)?,
            resource: resource_for(&config.vault_url),
            config: config.clone(),
        })
    }

    async fn token(&self) -> Result<Zeroizing<String>, ProviderError> {
        let c: &AzureCredential = &self.config.credential;
        let scope = format!("{}/.default", self.resource);
        if let (Some(tenant), Some(client_id)) = (&c.tenant_id, &c.client_id)
            && (c.federated_token_file.is_some() || c.client_secret.is_some())
        {
            let url = format!(
                "{}/{tenant}/oauth2/v2.0/token",
                c.authority_host.as_str().trim_end_matches('/')
            );
            let mut form = vec![
                ("grant_type", "client_credentials".to_string()),
                ("client_id", client_id.clone()),
                ("scope", scope),
            ];
            // The federated token is re-read every time: the kubelet rotates it.
            let assertion;
            if let Some(file) = &c.federated_token_file {
                assertion = http::read_token_file(file, "AZURE_FEDERATED_TOKEN_FILE").await?;
                form.push((
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
                ));
                form.push(("client_assertion", assertion.to_string()));
            } else if let Some(secret) = &c.client_secret {
                form.push(("client_secret", secret.expose().to_string()));
            }
            let answer = http::json(self.http.post(url).form(&form), "azure token").await;
            for (_, v) in form.iter_mut() {
                zeroize::Zeroize::zeroize(v);
            }
            return Ok(Zeroizing::new(
                http::string(&answer?, "/access_token", "azure token")?.to_string(),
            ));
        }
        let mut query = vec![("resource", self.resource.clone())];
        let (request, what) = if let Some((endpoint, header)) = &c.identity_endpoint {
            query.push(("api-version", "2019-08-01".into()));
            if let Some(id) = &c.client_id {
                query.push(("client_id", id.clone()));
            }
            (
                self.http
                    .get(with_query(endpoint.clone(), &query))
                    .header("X-IDENTITY-HEADER", header.expose()),
                "azure managed identity (identity endpoint)",
            )
        } else {
            query.push(("api-version", "2018-02-01".into()));
            if let Some(id) = &c.client_id {
                query.push(("client_id", id.clone()));
            }
            (
                self.http
                    .get(with_query(c.imds_endpoint.clone(), &query))
                    .header("Metadata", "true"),
                "azure managed identity (IMDS)",
            )
        };
        let answer = http::json(request, what).await?;
        Ok(Zeroizing::new(
            http::string(&answer, "/access_token", what)?.to_string(),
        ))
    }

    /// A stored key id, only if it is a key of the configured vault: the
    /// token is never sent anywhere else.
    fn checked_kid(&self, kid: &str) -> Result<Url, ProviderError> {
        let url = Url::parse(kid)
            .map_err(|_| ProviderError::Rejected(format!("not a Key Vault key id: {kid}")))?;
        let vault = &self.config.vault_url;
        let same_origin = url.scheme() == vault.scheme()
            && url.host_str() == vault.host_str()
            && url.port_or_known_default() == vault.port_or_known_default();
        let segments: Vec<&str> = url.path_segments().map(|s| s.collect()).unwrap_or_default();
        let shaped = segments.len() == 3
            && segments[0] == "keys"
            && segments[1..]
                .iter()
                .all(|s| super::config::path_safe(s, false));
        if !same_origin || !shaped || url.query().is_some() {
            return Err(ProviderError::Rejected(format!(
                "key id {kid} is not a key version in {vault}"
            )));
        }
        Ok(url)
    }
}

fn with_query(mut url: Url, pairs: &[(&str, String)]) -> Url {
    url.query_pairs_mut()
        .extend_pairs(pairs.iter().map(|(k, v)| (k, v.as_str())));
    url
}

/// The token audience for a vault URL: the vault's host without its own
/// name (`https://x.vault.azure.net` → `https://vault.azure.net`, and the
/// same for Managed HSM and the sovereign clouds).
fn resource_for(vault: &Url) -> String {
    let host = vault.host_str().unwrap_or_default();
    match (vault.host(), host.split_once('.')) {
        (Some(url::Host::Domain(_)), Some((_, parent))) if parent.contains('.') => {
            format!("https://{parent}")
        }
        _ => format!("{}://{host}", vault.scheme()),
    }
}

#[async_trait]
impl KeyWrapper for AzureKeyVault {
    fn backend(&self) -> &'static str {
        "azure-key-vault"
    }

    async fn wrap(&self, key: &[u8], _context: &[u8]) -> Result<WrappedKey, ProviderError> {
        // Neither RSA-OAEP nor AES key wrap takes additional data; the
        // generation is bound by the stored key id.
        let token = self.token().await?;
        let mut url = format!(
            "{}/keys/{}",
            self.config.vault_url.as_str().trim_end_matches('/'),
            self.config.key
        );
        if let Some(version) = &self.config.key_version {
            url.push('/');
            url.push_str(version);
        }
        url.push_str("/wrapkey");
        let url = Url::parse(&url)
            .map_err(|e| ProviderError::Configuration(format!("AZURE_KEY_VAULT_URL: {e}")))?;
        let answer = http::json(
            self.http
                .post(with_query(url, &[("api-version", API_VERSION.into())]))
                .bearer_auth(token.as_str())
                .json(&json!({ "alg": self.config.algorithm, "value": http::b64url(key) })),
            "azure key vault wrapkey",
        )
        .await?;
        let kid = http::string(&answer, "/kid", "azure key vault wrapkey")?;
        self.checked_kid(kid)?;
        let wrapped = http::decode_b64(
            http::string(&answer, "/value", "azure key vault wrapkey")?,
            "azure key vault wrapkey",
        )?;
        Ok(WrappedKey {
            key_ref: format!("{kid}#{}", self.config.algorithm),
            wrapped: wrapped.to_vec(),
        })
    }

    async fn unwrap(
        &self,
        key_ref: &str,
        wrapped: &[u8],
        _context: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        let (kid, alg) = key_ref
            .rsplit_once('#')
            .filter(|(_, alg)| super::config::AZURE_ALGORITHMS.contains(alg))
            .ok_or_else(|| {
                ProviderError::Rejected(format!("not a Key Vault key reference: {key_ref}"))
            })?;
        let mut url = self.checked_kid(kid)?;
        url.path_segments_mut()
            .map_err(|_| ProviderError::Rejected("key id".into()))?
            .push("unwrapkey");
        let token = self.token().await?;
        let answer = http::json(
            self.http
                .post(with_query(url, &[("api-version", API_VERSION.into())]))
                .bearer_auth(token.as_str())
                .json(&json!({ "alg": alg, "value": http::b64url(wrapped) })),
            "azure key vault unwrapkey",
        )
        .await?;
        http::decode_b64(
            http::string(&answer, "/value", "azure key vault unwrapkey")?,
            "azure key vault unwrapkey",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_audience_follows_the_vault_host() {
        let r = |u: &str| resource_for(&Url::parse(u).unwrap());
        assert_eq!(r("https://ridm.vault.azure.net"), "https://vault.azure.net");
        assert_eq!(
            r("https://ridm.managedhsm.azure.net/"),
            "https://managedhsm.azure.net"
        );
        assert_eq!(r("https://ridm.vault.azure.cn"), "https://vault.azure.cn");
        assert_eq!(r("http://127.0.0.1:9999"), "http://127.0.0.1");
    }
}
