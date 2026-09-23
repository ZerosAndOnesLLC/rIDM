//! The AWS KMS key wrapper (`kms-aws`) against local-kms, a KMS-compatible
//! server (`nsmithuk/local-kms`), through the real AWS SDK.
#![cfg(feature = "kms-aws")]

use std::time::Duration;

use aws_sdk_kms::Client;
use aws_sdk_kms::config::{BehaviorVersion, Credentials, Region};
use ridm_api::key_custody::aws_kms::AwsKms;
use ridm_core::providers::{KeyWrapper, ProviderError};
use testcontainers::core::{ContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

fn client(endpoint: &str) -> Client {
    let conf = aws_sdk_kms::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .credentials_provider(Credentials::new("test", "test", None, None, "ridm-test"))
        .endpoint_url(endpoint)
        .build();
    Client::from_conf(conf)
}

#[tokio::test]
async fn aws_kms_wraps_under_the_generation_context() {
    let container = GenericImage::new("nsmithuk/local-kms", "3.11.7")
        .with_exposed_port(ContainerPort::Tcp(8080))
        .with_wait_for(WaitFor::seconds(1))
        .with_label("dev.ridm.test", "true")
        .start()
        .await
        .expect("start local-kms");
    let port = container.get_host_port_ipv4(8080).await.unwrap();
    let kms = client(&format!("http://127.0.0.1:{port}"));
    let mut key = None;
    for _ in 0..60 {
        if let Ok(out) = kms.create_key().send().await {
            key = out
                .key_metadata()
                .map(|m| m.arn().unwrap_or(m.key_id()).to_string());
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let arn = key.expect("local-kms never answered");
    kms.create_alias()
        .alias_name("alias/ridm-test")
        .target_key_id(&arn)
        .send()
        .await
        .unwrap();

    // Configured by alias; the generation records the key itself.
    let wrapper = AwsKms::with_client(kms.clone(), "alias/ridm-test");
    let data_key = [0x5au8; 32];
    let wrapped = wrapper
        .wrap(&data_key, b"ridm:master-key:v3")
        .await
        .unwrap();
    assert_eq!(wrapped.key_ref, arn);
    assert_ne!(&wrapped.wrapped[..], &data_key[..]);
    let back = wrapper
        .unwrap(&wrapped.key_ref, &wrapped.wrapped, b"ridm:master-key:v3")
        .await
        .unwrap();
    assert_eq!(&*back, &data_key);

    // The encryption context is bound: another generation's context fails.
    let err = wrapper
        .unwrap(&wrapped.key_ref, &wrapped.wrapped, b"ridm:master-key:v4")
        .await
        .unwrap_err();
    assert!(!err.is_retryable(), "{err}");
    // So does a key that did not encrypt it.
    let other = kms.create_key().send().await.unwrap();
    let other_arn = other.key_metadata().unwrap().arn().unwrap().to_string();
    let err = wrapper
        .unwrap(&other_arn, &wrapped.wrapped, b"ridm:master-key:v3")
        .await
        .unwrap_err();
    assert!(!err.is_retryable(), "{err}");
    // A disabled key is the deployment's configuration.
    kms.disable_key().key_id(&arn).send().await.unwrap();
    let err = wrapper
        .unwrap(&wrapped.key_ref, &wrapped.wrapped, b"ridm:master-key:v3")
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::Configuration(_)), "{err}");

    // An unreachable endpoint is retryable.
    drop(container);
    let err = AwsKms::with_client(client("http://127.0.0.1:9"), &arn)
        .wrap(&data_key, b"")
        .await
        .unwrap_err();
    assert!(err.is_retryable(), "{err}");
}
