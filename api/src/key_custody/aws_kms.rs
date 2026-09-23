//! AWS KMS (`kms-aws`): `Encrypt` / `Decrypt` under a symmetric key, with the
//! generation as encryption context (so CloudTrail shows which generation a
//! node unwrapped, and a key policy can require it). Credentials and region
//! come from the SDK's standard chain: IRSA or EKS Pod Identity, the ECS task
//! role, an instance profile, SSO, environment keys.

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_kms::Client;
use aws_sdk_kms::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_kms::primitives::Blob;
use ridm_core::providers::{KeyWrapper, ProviderError, WrappedKey};
use zeroize::Zeroizing;

use super::config::AwsKmsConfig;

/// The encryption-context entry carrying the generation.
const CONTEXT_KEY: &str = "ridm:master-key";

pub struct AwsKms {
    client: Client,
    key_id: String,
}

impl AwsKms {
    pub async fn new(config: &AwsKmsConfig) -> Self {
        let mut loader = aws_config::defaults(BehaviorVersion::latest());
        if let Some(endpoint) = &config.endpoint {
            loader = loader.endpoint_url(endpoint.as_str().trim_end_matches('/'));
        }
        let sdk = loader.load().await;
        Self::with_client(Client::new(&sdk), &config.key_id)
    }

    /// Around a client built elsewhere (tests pass explicit credentials).
    pub fn with_client(client: Client, key_id: &str) -> Self {
        Self {
            client,
            key_id: key_id.to_string(),
        }
    }
}

fn context_value(context: &[u8]) -> String {
    String::from_utf8_lossy(context).into_owned()
}

fn sdk_error<E, R>(what: &str, err: SdkError<E, R>) -> ProviderError
where
    E: ProvideErrorMetadata + std::error::Error + 'static,
    R: std::fmt::Debug,
{
    let msg = format!("aws kms {what}: {}", DisplayErrorContext(&err));
    match &err {
        SdkError::ServiceError(service) => match service.err().code() {
            Some(
                "KMSInternalException"
                | "DependencyTimeoutException"
                | "ThrottlingException"
                | "LimitExceededException"
                | "KeyUnavailableException",
            ) => ProviderError::Unavailable(msg),
            Some(
                "AccessDeniedException"
                | "NotFoundException"
                | "DisabledException"
                | "KMSInvalidStateException"
                | "UnrecognizedClientException",
            ) => ProviderError::Configuration(msg),
            _ => ProviderError::Rejected(msg),
        },
        SdkError::ConstructionFailure(_) => ProviderError::Configuration(msg),
        _ => ProviderError::Unavailable(msg),
    }
}

#[async_trait]
impl KeyWrapper for AwsKms {
    fn backend(&self) -> &'static str {
        "aws-kms"
    }

    async fn wrap(&self, key: &[u8], context: &[u8]) -> Result<WrappedKey, ProviderError> {
        let out = self
            .client
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(Blob::new(key))
            .encryption_context(CONTEXT_KEY, context_value(context))
            .send()
            .await
            .map_err(|e| sdk_error("encrypt", e))?;
        let wrapped = out
            .ciphertext_blob()
            .ok_or_else(|| ProviderError::Rejected("aws kms encrypt: no ciphertext".into()))?
            .as_ref()
            .to_vec();
        // The key's ARN, whatever alias the configuration named it by, so a
        // re-pointed alias leaves this generation on its own key.
        let key_ref = out.key_id().unwrap_or(&self.key_id).to_string();
        Ok(WrappedKey { key_ref, wrapped })
    }

    async fn unwrap(
        &self,
        key_ref: &str,
        wrapped: &[u8],
        context: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        let out = self
            .client
            .decrypt()
            .key_id(key_ref)
            .ciphertext_blob(Blob::new(wrapped))
            .encryption_context(CONTEXT_KEY, context_value(context))
            .send()
            .await
            .map_err(|e| sdk_error("decrypt", e))?;
        let plaintext = out
            .plaintext()
            .ok_or_else(|| ProviderError::Rejected("aws kms decrypt: no plaintext".into()))?;
        Ok(Zeroizing::new(plaintext.as_ref().to_vec()))
    }
}
