//! HashiCorp Vault / OpenBao Transit (`kms-vault`): the data key is sent to
//! `transit/encrypt/<key>` and back through `transit/decrypt/<key>`; the key
//! never leaves Vault. Authentication is a token, or the pod's Kubernetes
//! service-account token through Vault's Kubernetes auth method, so a pod on
//! Kubernetes or OpenShift holds no static credential.

use async_trait::async_trait;
use ridm_core::providers::{KeyWrapper, ProviderError, WrappedKey};
use serde_json::json;
use zeroize::Zeroizing;

use super::config::{VaultAuth, VaultConfig, path_safe};
use super::http;

pub struct VaultTransit {
    http: reqwest::Client,
    config: VaultConfig,
}

impl VaultTransit {
    pub fn new(config: &VaultConfig) -> Result<Self, ProviderError> {
        Ok(Self {
            http: http::client(config.ca_file.as_deref())?,
            config: config.clone(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/v1/{path}",
            self.config.addr.as_str().trim_end_matches('/')
        )
    }

    fn request(&self, path: &str, token: Option<&str>) -> reqwest::RequestBuilder {
        let mut req = self.http.post(self.url(path));
        if let Some(ns) = &self.config.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }
        if let Some(token) = token {
            req = req.header("X-Vault-Token", token);
        }
        req
    }

    /// A token for this call. A Kubernetes login is made each time: it only
    /// happens at start-up and when a generation is created.
    async fn token(&self) -> Result<Zeroizing<String>, ProviderError> {
        match &self.config.auth {
            VaultAuth::Token(t) => Ok(Zeroizing::new(t.expose().to_string())),
            VaultAuth::Kubernetes {
                role,
                mount,
                token_file,
            } => {
                let jwt = http::read_token_file(token_file, "service-account token").await?;
                let answer = http::json(
                    self.request(&format!("auth/{mount}/login"), None)
                        .json(&json!({ "role": role, "jwt": jwt.as_str() })),
                    "vault kubernetes login",
                )
                .await?;
                Ok(Zeroizing::new(
                    http::string(&answer, "/auth/client_token", "vault kubernetes login")?
                        .to_string(),
                ))
            }
        }
    }
}

/// `mount/key` as stored, split back; the mount may itself hold slashes.
fn split_ref(key_ref: &str) -> Result<(&str, &str), ProviderError> {
    key_ref
        .rsplit_once('/')
        .filter(|(mount, key)| path_safe(mount, true) && path_safe(key, false))
        .ok_or_else(|| ProviderError::Rejected(format!("not a Transit key reference: {key_ref}")))
}

#[async_trait]
impl KeyWrapper for VaultTransit {
    fn backend(&self) -> &'static str {
        "vault"
    }

    async fn wrap(&self, key: &[u8], _context: &[u8]) -> Result<WrappedKey, ProviderError> {
        // `context` is only accepted by derived Transit keys, which are not
        // required here; the generation is bound by the stored key reference.
        let token = self.token().await?;
        let (mount, name) = (&self.config.mount, &self.config.key);
        let answer = http::json(
            self.request(&format!("{mount}/encrypt/{name}"), Some(&token))
                .json(&json!({ "plaintext": http::b64(key) })),
            "vault transit encrypt",
        )
        .await?;
        let ciphertext = http::string(&answer, "/data/ciphertext", "vault transit encrypt")?;
        Ok(WrappedKey {
            key_ref: format!("{mount}/{name}"),
            wrapped: ciphertext.as_bytes().to_vec(),
        })
    }

    async fn unwrap(
        &self,
        key_ref: &str,
        wrapped: &[u8],
        _context: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        let (mount, name) = split_ref(key_ref)?;
        let ciphertext = std::str::from_utf8(wrapped)
            .ok()
            .filter(|c| c.starts_with("vault:"))
            .ok_or_else(|| ProviderError::Rejected("not a Transit ciphertext".into()))?;
        let token = self.token().await?;
        let answer = http::json(
            self.request(&format!("{mount}/decrypt/{name}"), Some(&token))
                .json(&json!({ "ciphertext": ciphertext })),
            "vault transit decrypt",
        )
        .await?;
        http::decode_b64(
            http::string(&answer, "/data/plaintext", "vault transit decrypt")?,
            "vault transit decrypt",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_references_split_on_the_last_slash() {
        assert_eq!(split_ref("transit/ridm").unwrap(), ("transit", "ridm"));
        assert_eq!(
            split_ref("team-a/transit/ridm").unwrap(),
            ("team-a/transit", "ridm")
        );
        assert!(split_ref("ridm").is_err());
        assert!(split_ref("../sys/ridm").is_err());
        assert!(split_ref("transit/").is_err());
    }
}
