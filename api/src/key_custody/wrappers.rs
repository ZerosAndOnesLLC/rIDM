//! Build the configured [`KeyWrapper`]s. A backend this build was compiled
//! without is refused here, naming the cargo feature, rather than silently
//! ignored: the deployment would otherwise start on the wrong key.

use std::sync::Arc;

use ridm_core::providers::KeyWrapper;

use super::config::{Backend, KeyCustodyConfig};
use super::envelope::CustodyError;

/// One wrapper per backend in `KEY_WRAPPER` and `KEY_WRAPPER_PREVIOUS`.
pub async fn build(config: &KeyCustodyConfig) -> Result<Vec<Arc<dyn KeyWrapper>>, CustodyError> {
    let mut out = Vec::new();
    for backend in config.backends() {
        out.push(
            one(config, backend)
                .await
                .map_err(|e| CustodyError(format!("key wrapper `{backend}`: {e}")))?,
        );
    }
    Ok(out)
}

#[cfg(not(all(
    feature = "hsm-pkcs11",
    feature = "kms-aws",
    feature = "kms-vault",
    feature = "kms-gcp",
    feature = "kms-azure"
)))]
fn missing(backend: Backend) -> CustodyError {
    CustodyError(format!(
        "this build of rIDM does not include the `{}` cargo feature (the released image does)",
        backend.feature()
    ))
}

async fn one(
    config: &KeyCustodyConfig,
    backend: Backend,
) -> Result<Arc<dyn KeyWrapper>, CustodyError> {
    let unset = || CustodyError(format!("{backend} is not configured"));
    match backend {
        Backend::Pkcs11 => {
            #[cfg(feature = "hsm-pkcs11")]
            {
                let c = config.pkcs11.as_ref().ok_or_else(unset)?;
                Ok(Arc::new(super::pkcs11::Pkcs11Wrapper::new(c).await?))
            }
            #[cfg(not(feature = "hsm-pkcs11"))]
            {
                let _ = (config.pkcs11.as_ref(), unset);
                Err(missing(backend))
            }
        }
        Backend::AwsKms => {
            #[cfg(feature = "kms-aws")]
            {
                let c = config.aws.as_ref().ok_or_else(unset)?;
                Ok(Arc::new(super::aws_kms::AwsKms::new(c).await))
            }
            #[cfg(not(feature = "kms-aws"))]
            {
                let _ = (config.aws.as_ref(), unset);
                Err(missing(backend))
            }
        }
        Backend::Vault => {
            #[cfg(feature = "kms-vault")]
            {
                let c = config.vault.as_ref().ok_or_else(unset)?;
                Ok(Arc::new(super::vault::VaultTransit::new(c)?))
            }
            #[cfg(not(feature = "kms-vault"))]
            {
                let _ = (config.vault.as_ref(), unset);
                Err(missing(backend))
            }
        }
        Backend::GcpKms => {
            #[cfg(feature = "kms-gcp")]
            {
                let c = config.gcp.as_ref().ok_or_else(unset)?;
                Ok(Arc::new(super::gcp_kms::GcpKms::new(c)?))
            }
            #[cfg(not(feature = "kms-gcp"))]
            {
                let _ = (config.gcp.as_ref(), unset);
                Err(missing(backend))
            }
        }
        Backend::AzureKeyVault => {
            #[cfg(feature = "kms-azure")]
            {
                let c = config.azure.as_ref().ok_or_else(unset)?;
                Ok(Arc::new(super::azure_kv::AzureKeyVault::new(c)?))
            }
            #[cfg(not(feature = "kms-azure"))]
            {
                let _ = (config.azure.as_ref(), unset);
                Err(missing(backend))
            }
        }
    }
}
