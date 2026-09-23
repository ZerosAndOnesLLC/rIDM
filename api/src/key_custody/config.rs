//! `KEY_WRAPPER` and each backend's settings. Parsed whatever the build's
//! features, so a configuration is validated the same way everywhere; a build
//! without the chosen backend refuses it when the wrappers are built.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use url::Url;

use crate::config::{ConfigError, optional, parse, parse_bool, required, secret};
use crate::util::secret::SecretString;

/// Where a master-key generation's data key is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Backend {
    Pkcs11,
    AwsKms,
    Vault,
    GcpKms,
    AzureKeyVault,
}

impl Backend {
    pub const ALL: [Backend; 5] = [
        Self::Pkcs11,
        Self::AwsKms,
        Self::Vault,
        Self::GcpKms,
        Self::AzureKeyVault,
    ];

    /// The name stored in `master_key_generations.backend` and accepted by
    /// `KEY_WRAPPER`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pkcs11 => "pkcs11",
            Self::AwsKms => "aws-kms",
            Self::Vault => "vault",
            Self::GcpKms => "gcp-kms",
            Self::AzureKeyVault => "azure-key-vault",
        }
    }

    /// The cargo feature that compiles it in.
    pub fn feature(self) -> &'static str {
        match self {
            Self::Pkcs11 => "hsm-pkcs11",
            Self::AwsKms => "kms-aws",
            Self::Vault => "kms-vault",
            Self::GcpKms => "kms-gcp",
            Self::AzureKeyVault => "kms-azure",
        }
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Backend {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|b| b.as_str() == s)
            .ok_or_else(|| {
                format!(
                    "unknown key wrapper `{s}` (expected one of {})",
                    Self::ALL.map(Backend::as_str).join(", ")
                )
            })
    }
}

/// Key custody settings. Empty (the default) keeps every generation in the
/// environment (`MASTER_KEY`), as before 13.6.
#[derive(Debug, Clone, Default)]
pub struct KeyCustodyConfig {
    /// `KEY_WRAPPER`: the backend new generations are wrapped by. Setting it
    /// makes `MASTER_KEY` optional.
    pub wrapper: Option<Backend>,
    /// `KEY_WRAPPER_PREVIOUS`: further backends still holding older
    /// generations, while a move from one to another is rotated through.
    pub previous: Vec<Backend>,
    pub pkcs11: Option<Pkcs11Config>,
    pub aws: Option<AwsKmsConfig>,
    pub vault: Option<VaultConfig>,
    pub gcp: Option<GcpKmsConfig>,
    pub azure: Option<AzureKeyVaultConfig>,
}

impl KeyCustodyConfig {
    /// Every backend named, current first.
    pub fn backends(&self) -> Vec<Backend> {
        let mut all: Vec<Backend> = self.wrapper.into_iter().collect();
        for b in &self.previous {
            if !all.contains(b) {
                all.push(*b);
            }
        }
        all
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        let wrapper = optional("KEY_WRAPPER")
            .map(|v| parse("KEY_WRAPPER", v, |v| v.parse::<Backend>()))
            .transpose()?;
        let previous = optional("KEY_WRAPPER_PREVIOUS")
            .map(|v| {
                parse("KEY_WRAPPER_PREVIOUS", v, |v| {
                    v.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::parse::<Backend>)
                        .collect::<Result<Vec<_>, _>>()
                })
            })
            .transpose()?
            .unwrap_or_default();
        let mut config = Self {
            wrapper,
            previous,
            ..Default::default()
        };
        for backend in config.backends() {
            match backend {
                Backend::Pkcs11 => config.pkcs11 = Some(Pkcs11Config::from_env()?),
                Backend::AwsKms => config.aws = Some(AwsKmsConfig::from_env()?),
                Backend::Vault => config.vault = Some(VaultConfig::from_env()?),
                Backend::GcpKms => config.gcp = Some(GcpKmsConfig::from_env()?),
                Backend::AzureKeyVault => config.azure = Some(AzureKeyVaultConfig::from_env()?),
            }
        }
        Ok(config)
    }
}

/// A PKCS#11 token: a network HSM, a USB one, a cloud HSM's client library,
/// or SoftHSM.
#[derive(Debug, Clone)]
pub struct Pkcs11Config {
    /// `PKCS11_MODULE`: the vendor's PKCS#11 library (`.so`).
    pub module: PathBuf,
    /// `PKCS11_TOKEN_LABEL`: the token to use; else `PKCS11_SLOT`; else the
    /// first slot with a token.
    pub token_label: Option<String>,
    pub slot: Option<u64>,
    /// `PKCS11_PIN` / `PKCS11_PIN_FILE`: the user PIN.
    pub pin: SecretString,
    /// `PKCS11_KEY_LABEL`: the AES-256 key (`CKA_LABEL`) that wraps data keys.
    pub key_label: String,
    /// `PKCS11_GENERATE_KEY`: create that key on the token, non-extractable,
    /// when it does not exist. Off by default: production keys are made by
    /// the HSM's administrators under their own ceremony.
    pub generate_key: bool,
}

impl Pkcs11Config {
    fn from_env() -> Result<Self, ConfigError> {
        let slot = optional("PKCS11_SLOT")
            .map(|v| parse("PKCS11_SLOT", v, |v| v.trim().parse::<u64>()))
            .transpose()?;
        Ok(Self {
            module: PathBuf::from(required("PKCS11_MODULE")?),
            token_label: optional("PKCS11_TOKEN_LABEL"),
            slot,
            pin: secret("PKCS11_PIN", "PKCS11_PIN_FILE")?
                .map(SecretString::new)
                .ok_or(ConfigError::Missing("PKCS11_PIN or PKCS11_PIN_FILE"))?,
            key_label: optional("PKCS11_KEY_LABEL").unwrap_or_else(|| "ridm-master-key".into()),
            generate_key: parse_bool("PKCS11_GENERATE_KEY", false)?,
        })
    }
}

/// AWS KMS. Region and credentials come from the SDK's standard chain
/// (`AWS_REGION`, IRSA / EKS Pod Identity, the ECS task role, the instance
/// profile, SSO, `AWS_PROFILE`...).
#[derive(Debug, Clone)]
pub struct AwsKmsConfig {
    /// `AWS_KMS_KEY_ID`: key id, ARN or `alias/...` of a symmetric key.
    pub key_id: String,
    /// `AWS_KMS_ENDPOINT`: another endpoint (a VPC endpoint's DNS name, a
    /// local KMS for development). The SDK's own `AWS_ENDPOINT_URL_KMS` works
    /// as well.
    pub endpoint: Option<Url>,
}

impl AwsKmsConfig {
    fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            key_id: required("AWS_KMS_KEY_ID")?,
            endpoint: optional("AWS_KMS_ENDPOINT")
                .map(|v| parse("AWS_KMS_ENDPOINT", v, |v| http_url(&v)))
                .transpose()?,
        })
    }
}

/// HashiCorp Vault or OpenBao, Transit secrets engine.
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// `VAULT_ADDR`.
    pub addr: Url,
    /// `VAULT_TRANSIT_MOUNT` (default `transit`).
    pub mount: String,
    /// `VAULT_TRANSIT_KEY`: the Transit key's name.
    pub key: String,
    /// `VAULT_NAMESPACE` (Vault Enterprise / HCP).
    pub namespace: Option<String>,
    /// `VAULT_CACERT`: PEM roots to trust instead of the system's.
    pub ca_file: Option<PathBuf>,
    pub auth: VaultAuth,
}

#[derive(Debug, Clone)]
pub enum VaultAuth {
    /// `VAULT_TOKEN` / `VAULT_TOKEN_FILE`.
    Token(SecretString),
    /// `VAULT_KUBERNETES_ROLE`: the pod's service-account token logs in
    /// through the Kubernetes auth method (also OpenShift's).
    Kubernetes {
        role: String,
        /// `VAULT_KUBERNETES_MOUNT` (default `kubernetes`).
        mount: String,
        /// `VAULT_KUBERNETES_TOKEN_FILE` (default the projected token).
        token_file: PathBuf,
    },
}

/// Where Kubernetes projects a pod's service-account token.
pub const SERVICE_ACCOUNT_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

impl VaultConfig {
    fn from_env() -> Result<Self, ConfigError> {
        let auth = match optional("VAULT_KUBERNETES_ROLE") {
            Some(role) => VaultAuth::Kubernetes {
                role,
                mount: optional("VAULT_KUBERNETES_MOUNT").unwrap_or_else(|| "kubernetes".into()),
                token_file: optional("VAULT_KUBERNETES_TOKEN_FILE")
                    .unwrap_or_else(|| SERVICE_ACCOUNT_TOKEN.into())
                    .into(),
            },
            None => VaultAuth::Token(
                secret("VAULT_TOKEN", "VAULT_TOKEN_FILE")?
                    .map(SecretString::new)
                    .ok_or(ConfigError::Missing(
                        "VAULT_TOKEN, VAULT_TOKEN_FILE or VAULT_KUBERNETES_ROLE",
                    ))?,
            ),
        };
        let mount = optional("VAULT_TRANSIT_MOUNT").unwrap_or_else(|| "transit".into());
        let key = required("VAULT_TRANSIT_KEY")?;
        for (name, v, slashes) in [
            ("VAULT_TRANSIT_MOUNT", &mount, true),
            ("VAULT_TRANSIT_KEY", &key, false),
        ] {
            if !path_safe(v, slashes) {
                return Err(ConfigError::Invalid {
                    name,
                    reason: "letters, digits, `-`, `_` and `.` (and `/` in a mount path) only"
                        .into(),
                });
            }
        }
        Ok(Self {
            addr: parse("VAULT_ADDR", required("VAULT_ADDR")?, |v| http_url(&v))?,
            mount,
            key,
            namespace: optional("VAULT_NAMESPACE"),
            ca_file: optional("VAULT_CACERT").map(PathBuf::from),
            auth,
        })
    }
}

/// Google Cloud KMS.
#[derive(Debug, Clone)]
pub struct GcpKmsConfig {
    /// `GCP_KMS_KEY`: `projects/…/locations/…/keyRings/…/cryptoKeys/…`.
    pub key: String,
    /// `GCP_KMS_ENDPOINT` (default `https://cloudkms.googleapis.com`).
    pub endpoint: Url,
    /// `GOOGLE_APPLICATION_CREDENTIALS`: a service-account key or a workload
    /// identity federation (`external_account`) file. Unset: the metadata
    /// server (GCE, GKE Workload Identity, Cloud Run).
    pub credentials_file: Option<PathBuf>,
    /// `GCE_METADATA_HOST` (default `metadata.google.internal`).
    pub metadata_host: String,
}

impl GcpKmsConfig {
    fn from_env() -> Result<Self, ConfigError> {
        let key = required("GCP_KMS_KEY")?;
        let parts: Vec<&str> = key.split('/').collect();
        let shaped = parts.len() == 8
            && parts[0] == "projects"
            && parts[2] == "locations"
            && parts[4] == "keyRings"
            && parts[6] == "cryptoKeys"
            && parts.iter().all(|p| path_safe(p, false));
        if !shaped {
            return Err(ConfigError::Invalid {
                name: "GCP_KMS_KEY",
                reason: "expected projects/P/locations/L/keyRings/R/cryptoKeys/K".into(),
            });
        }
        Ok(Self {
            key,
            endpoint: parse(
                "GCP_KMS_ENDPOINT",
                optional("GCP_KMS_ENDPOINT")
                    .unwrap_or_else(|| "https://cloudkms.googleapis.com".into()),
                |v| http_url(&v),
            )?,
            credentials_file: optional("GOOGLE_APPLICATION_CREDENTIALS").map(PathBuf::from),
            metadata_host: optional("GCE_METADATA_HOST")
                .unwrap_or_else(|| "metadata.google.internal".into()),
        })
    }
}

/// Azure Key Vault or Managed HSM.
#[derive(Debug, Clone)]
pub struct AzureKeyVaultConfig {
    /// `AZURE_KEY_VAULT_URL`: `https://<name>.vault.azure.net` or
    /// `https://<name>.managedhsm.azure.net`.
    pub vault_url: Url,
    /// `AZURE_KEY_VAULT_KEY`: the key's name.
    pub key: String,
    /// `AZURE_KEY_VAULT_KEY_VERSION`: pin a version (default the current one;
    /// the version used is recorded either way).
    pub key_version: Option<String>,
    /// `AZURE_KEY_VAULT_ALGORITHM` (default `RSA-OAEP-256`; `A256KW` for an
    /// AES key in a Managed HSM).
    pub algorithm: String,
    pub credential: AzureCredential,
}

/// Key wrap algorithms Key Vault and Managed HSM offer.
pub const AZURE_ALGORITHMS: [&str; 5] = ["RSA-OAEP-256", "RSA-OAEP", "A256KW", "A192KW", "A128KW"];

/// How rIDM gets a token for Key Vault. The variables are the ones the Azure
/// SDKs and the workload identity webhook use.
#[derive(Debug, Clone)]
pub struct AzureCredential {
    /// `AZURE_TENANT_ID`.
    pub tenant_id: Option<String>,
    /// `AZURE_CLIENT_ID`: the application, or a user-assigned managed identity.
    pub client_id: Option<String>,
    /// `AZURE_CLIENT_SECRET` / `AZURE_CLIENT_SECRET_FILE`.
    pub client_secret: Option<SecretString>,
    /// `AZURE_FEDERATED_TOKEN_FILE`: workload identity (AKS, or any
    /// Kubernetes/OpenShift cluster federated with Entra ID).
    pub federated_token_file: Option<PathBuf>,
    /// `AZURE_AUTHORITY_HOST` (default `https://login.microsoftonline.com`).
    pub authority_host: Url,
    /// `IDENTITY_ENDPOINT` + `IDENTITY_HEADER`: App Service / Container Apps
    /// managed identity.
    pub identity_endpoint: Option<(Url, SecretString)>,
    /// The instance metadata service (VMs, VM scale sets): the last resort.
    pub imds_endpoint: Url,
}

impl AzureKeyVaultConfig {
    fn from_env() -> Result<Self, ConfigError> {
        let key = required("AZURE_KEY_VAULT_KEY")?;
        let key_version = optional("AZURE_KEY_VAULT_KEY_VERSION");
        for (name, v) in [
            ("AZURE_KEY_VAULT_KEY", Some(&key)),
            ("AZURE_KEY_VAULT_KEY_VERSION", key_version.as_ref()),
        ] {
            if v.is_some_and(|v| !path_safe(v, false)) {
                return Err(ConfigError::Invalid {
                    name,
                    reason: "letters, digits and `-` only".into(),
                });
            }
        }
        let algorithm =
            optional("AZURE_KEY_VAULT_ALGORITHM").unwrap_or_else(|| "RSA-OAEP-256".into());
        if !AZURE_ALGORITHMS.contains(&algorithm.as_str()) {
            return Err(ConfigError::Invalid {
                name: "AZURE_KEY_VAULT_ALGORITHM",
                reason: format!("expected one of {}", AZURE_ALGORITHMS.join(", ")),
            });
        }
        let identity_endpoint = match (optional("IDENTITY_ENDPOINT"), optional("IDENTITY_HEADER")) {
            (Some(url), Some(header)) => Some((
                parse("IDENTITY_ENDPOINT", url, |v| http_url(&v))?,
                SecretString::new(header),
            )),
            _ => None,
        };
        Ok(Self {
            vault_url: parse(
                "AZURE_KEY_VAULT_URL",
                required("AZURE_KEY_VAULT_URL")?,
                |v| http_url(&v),
            )?,
            key,
            key_version,
            algorithm,
            credential: AzureCredential {
                tenant_id: optional("AZURE_TENANT_ID"),
                client_id: optional("AZURE_CLIENT_ID"),
                client_secret: secret("AZURE_CLIENT_SECRET", "AZURE_CLIENT_SECRET_FILE")?
                    .map(SecretString::new),
                federated_token_file: optional("AZURE_FEDERATED_TOKEN_FILE").map(PathBuf::from),
                authority_host: parse(
                    "AZURE_AUTHORITY_HOST",
                    optional("AZURE_AUTHORITY_HOST")
                        .unwrap_or_else(|| "https://login.microsoftonline.com".into()),
                    |v| http_url(&v),
                )?,
                identity_endpoint,
                imds_endpoint: Url::parse("http://169.254.169.254/metadata/identity/oauth2/token")
                    .expect("constant URL"),
            },
        })
    }
}

fn http_url(v: &str) -> Result<Url, String> {
    let url = Url::parse(v.trim()).map_err(|e| e.to_string())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("expected an http(s) URL".into());
    }
    Ok(url)
}

/// A value that goes into a URL path unescaped.
pub(super) fn path_safe(v: &str, slashes: bool) -> bool {
    !v.is_empty()
        && v.len() <= 256
        && !v.split('/').any(|s| s.is_empty() || s == "." || s == "..")
        && v.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') || (slashes && c == '/')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_names_round_trip() {
        for b in Backend::ALL {
            assert_eq!(b.as_str().parse::<Backend>().unwrap(), b);
        }
        assert_eq!(" AWS-KMS ".parse::<Backend>().unwrap(), Backend::AwsKms);
        assert!("kms".parse::<Backend>().is_err());
    }

    #[test]
    fn path_segments_are_checked() {
        assert!(path_safe("transit", true));
        assert!(path_safe("team-a/transit", true));
        assert!(!path_safe("team-a/transit", false));
        assert!(!path_safe("../sys", true));
        assert!(!path_safe("a//b", true));
        assert!(!path_safe("a?b", true));
        assert!(!path_safe("", true));
    }

    #[test]
    fn backends_lists_current_first_without_repeats() {
        let c = KeyCustodyConfig {
            wrapper: Some(Backend::Vault),
            previous: vec![Backend::AwsKms, Backend::Vault],
            ..Default::default()
        };
        assert_eq!(c.backends(), vec![Backend::Vault, Backend::AwsKms]);
    }
}
