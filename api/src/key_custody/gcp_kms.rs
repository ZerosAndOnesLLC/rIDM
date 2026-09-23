//! Google Cloud KMS (`kms-gcp`): `cryptoKeys.encrypt` / `decrypt` over REST,
//! the generation as additional authenticated data. Credentials, in the order
//! Google's client libraries use:
//!
//! - `GOOGLE_APPLICATION_CREDENTIALS` naming a service-account key (a signed
//!   JWT exchanged at its `token_uri`) or a workload identity federation file
//!   (`external_account`: a token file, such as a Kubernetes or OpenShift
//!   service-account token, exchanged at Google's STS, then optionally for a
//!   service account's token);
//! - otherwise the metadata server (Compute Engine, GKE Workload Identity,
//!   Cloud Run).

use std::path::PathBuf;

use async_trait::async_trait;
use ridm_core::providers::{KeyWrapper, ProviderError, WrappedKey};
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use super::config::GcpKmsConfig;
use super::http;

const SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

pub struct GcpKms {
    http: reqwest::Client,
    config: GcpKmsConfig,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum CredentialsFile {
    ServiceAccount {
        client_email: String,
        private_key: String,
        #[serde(default = "default_token_uri")]
        token_uri: String,
    },
    ExternalAccount {
        audience: String,
        subject_token_type: String,
        token_url: String,
        credential_source: CredentialSource,
        service_account_impersonation_url: Option<String>,
    },
}

#[derive(Deserialize)]
struct CredentialSource {
    file: Option<PathBuf>,
    format: Option<SourceFormat>,
}

#[derive(Deserialize)]
struct SourceFormat {
    #[serde(rename = "type")]
    kind: String,
    subject_token_field_name: Option<String>,
}

fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".into()
}

impl GcpKms {
    pub fn new(config: &GcpKmsConfig) -> Result<Self, ProviderError> {
        Ok(Self {
            http: http::client(None)?,
            config: config.clone(),
        })
    }

    async fn token(&self) -> Result<Zeroizing<String>, ProviderError> {
        let Some(path) = &self.config.credentials_file else {
            return self.metadata_token().await;
        };
        let raw = Zeroizing::new(tokio::fs::read(path).await.map_err(|e| {
            ProviderError::Configuration(format!(
                "GOOGLE_APPLICATION_CREDENTIALS {}: {e}",
                path.display()
            ))
        })?);
        let file: CredentialsFile = serde_json::from_slice(&raw).map_err(|e| {
            ProviderError::Configuration(format!(
                "GOOGLE_APPLICATION_CREDENTIALS: not a service_account or external_account file ({e})"
            ))
        })?;
        match file {
            CredentialsFile::ServiceAccount {
                client_email,
                private_key,
                token_uri,
            } => {
                self.service_account_token(&client_email, &private_key, &token_uri)
                    .await
            }
            CredentialsFile::ExternalAccount {
                audience,
                subject_token_type,
                token_url,
                credential_source,
                service_account_impersonation_url,
            } => {
                let subject = subject_token(&credential_source).await?;
                let answer = http::json(
                    self.http.post(&token_url).form(&[
                        (
                            "grant_type",
                            "urn:ietf:params:oauth:grant-type:token-exchange",
                        ),
                        ("audience", audience.as_str()),
                        ("scope", SCOPE),
                        (
                            "requested_token_type",
                            "urn:ietf:params:oauth:token-type:access_token",
                        ),
                        ("subject_token", subject.as_str()),
                        ("subject_token_type", subject_token_type.as_str()),
                    ]),
                    "gcp sts token exchange",
                )
                .await?;
                let federated = Zeroizing::new(
                    http::string(&answer, "/access_token", "gcp sts token exchange")?.to_string(),
                );
                let Some(url) = service_account_impersonation_url else {
                    return Ok(federated);
                };
                let answer = http::json(
                    self.http
                        .post(&url)
                        .bearer_auth(federated.as_str())
                        .json(&json!({ "scope": [SCOPE], "lifetime": "3600s" })),
                    "gcp service account impersonation",
                )
                .await?;
                Ok(Zeroizing::new(
                    http::string(&answer, "/accessToken", "gcp service account impersonation")?
                        .to_string(),
                ))
            }
        }
    }

    async fn service_account_token(
        &self,
        client_email: &str,
        private_key: &str,
        token_uri: &str,
    ) -> Result<Zeroizing<String>, ProviderError> {
        let now = chrono::Utc::now().timestamp();
        let claims = json!({
            "iss": client_email,
            "scope": SCOPE,
            "aud": token_uri,
            "iat": now,
            "exp": now + 3600,
        });
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key.as_bytes()).map_err(|e| {
            ProviderError::Configuration(format!("service account private_key: {e}"))
        })?;
        let assertion = Zeroizing::new(
            jsonwebtoken::encode(
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
                &claims,
                &key,
            )
            .map_err(|e| ProviderError::Configuration(format!("service account JWT: {e}")))?,
        );
        let answer = http::json(
            self.http.post(token_uri).form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ]),
            "gcp service account token",
        )
        .await?;
        Ok(Zeroizing::new(
            http::string(&answer, "/access_token", "gcp service account token")?.to_string(),
        ))
    }

    async fn metadata_token(&self) -> Result<Zeroizing<String>, ProviderError> {
        let url = format!(
            "http://{}/computeMetadata/v1/instance/service-accounts/default/token",
            self.config.metadata_host
        );
        let answer = http::json(
            self.http.get(url).header("Metadata-Flavor", "Google"),
            "gcp metadata server token",
        )
        .await?;
        Ok(Zeroizing::new(
            http::string(&answer, "/access_token", "gcp metadata server token")?.to_string(),
        ))
    }

    fn url(&self, key: &str, method: &str) -> String {
        format!(
            "{}/v1/{key}:{method}",
            self.config.endpoint.as_str().trim_end_matches('/')
        )
    }
}

/// The subject token of a workload identity federation file.
async fn subject_token(source: &CredentialSource) -> Result<Zeroizing<String>, ProviderError> {
    let path = source.file.as_ref().ok_or_else(|| {
        ProviderError::Configuration(
            "external_account credentials: only a `credential_source.file` is supported".into(),
        )
    })?;
    let raw = http::read_token_file(path, "credential_source.file").await?;
    match &source.format {
        Some(f) if f.kind == "json" => {
            let field = f
                .subject_token_field_name
                .as_deref()
                .unwrap_or("access_token");
            let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
                ProviderError::Configuration(format!("credential_source.file: {e}"))
            })?;
            Ok(Zeroizing::new(
                http::string(&v, &format!("/{field}"), "credential_source.file")?.to_string(),
            ))
        }
        _ => Ok(raw),
    }
}

/// A Cloud KMS key name as stored, re-checked before it goes into a URL.
fn checked_key(key_ref: &str) -> Result<&str, ProviderError> {
    let parts: Vec<&str> = key_ref.split('/').collect();
    let shaped = parts.len() == 8
        && parts[0] == "projects"
        && parts[2] == "locations"
        && parts[4] == "keyRings"
        && parts[6] == "cryptoKeys"
        && parts.iter().all(|p| super::config::path_safe(p, false));
    shaped
        .then_some(key_ref)
        .ok_or_else(|| ProviderError::Rejected(format!("not a Cloud KMS key name: {key_ref}")))
}

#[async_trait]
impl KeyWrapper for GcpKms {
    fn backend(&self) -> &'static str {
        "gcp-kms"
    }

    async fn wrap(&self, key: &[u8], context: &[u8]) -> Result<WrappedKey, ProviderError> {
        let token = self.token().await?;
        let answer = http::json(
            self.http
                .post(self.url(&self.config.key, "encrypt"))
                .bearer_auth(token.as_str())
                .json(&json!({
                    "plaintext": http::b64(key),
                    "additionalAuthenticatedData": http::b64(context),
                })),
            "gcp kms encrypt",
        )
        .await?;
        let ciphertext = http::decode_b64(
            http::string(&answer, "/ciphertext", "gcp kms encrypt")?,
            "gcp kms encrypt",
        )?;
        Ok(WrappedKey {
            // The key, not the version that encrypted: Cloud KMS finds the
            // version from the ciphertext, and rotating the key keeps
            // decrypting older versions.
            key_ref: self.config.key.clone(),
            wrapped: ciphertext.to_vec(),
        })
    }

    async fn unwrap(
        &self,
        key_ref: &str,
        wrapped: &[u8],
        context: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        let key = checked_key(key_ref)?;
        let token = self.token().await?;
        let answer = http::json(
            self.http
                .post(self.url(key, "decrypt"))
                .bearer_auth(token.as_str())
                .json(&json!({
                    "ciphertext": http::b64(wrapped),
                    "additionalAuthenticatedData": http::b64(context),
                })),
            "gcp kms decrypt",
        )
        .await?;
        http::decode_b64(
            http::string(&answer, "/plaintext", "gcp kms decrypt")?,
            "gcp kms decrypt",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_names_are_checked() {
        let good = "projects/p/locations/global/keyRings/r/cryptoKeys/k";
        assert_eq!(checked_key(good).unwrap(), good);
        assert!(
            checked_key("projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
                .is_err()
        );
        assert!(checked_key("projects/../locations/global/keyRings/r/cryptoKeys/k").is_err());
        assert!(checked_key("projects/p?x/locations/global/keyRings/r/cryptoKeys/k").is_err());
    }

    #[test]
    fn credential_files_parse() {
        let sa: CredentialsFile = serde_json::from_str(
            r#"{"type":"service_account","client_email":"a@b","private_key":"k"}"#,
        )
        .unwrap();
        assert!(
            matches!(sa, CredentialsFile::ServiceAccount { token_uri, .. } if token_uri == default_token_uri())
        );
        let ext: CredentialsFile = serde_json::from_str(
            r#"{"type":"external_account","audience":"//iam.googleapis.com/x","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","token_url":"https://sts.googleapis.com/v1/token","credential_source":{"file":"/var/run/token"}}"#,
        )
        .unwrap();
        assert!(matches!(ext, CredentialsFile::ExternalAccount { .. }));
        assert!(serde_json::from_str::<CredentialsFile>(r#"{"type":"authorized_user"}"#).is_err());
    }
}
