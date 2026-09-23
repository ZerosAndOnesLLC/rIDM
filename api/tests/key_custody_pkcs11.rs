//! The PKCS#11 key wrapper (`hsm-pkcs11`) against SoftHSM: finding the token
//! by label, the key by label (and creating it only when told to), AES-GCM
//! wrapping bound to the generation, a second context in the same process,
//! and a wrong PIN.
//!
//! Needs SoftHSM 2: `RIDM_TEST_PKCS11_MODULE` (default
//! `/usr/lib/softhsm/libsofthsm2.so`), `softhsm2-util` on `PATH` (or
//! `RIDM_TEST_SOFTHSM_UTIL`), and a writable token directory through
//! `SOFTHSM2_CONF`. It skips without them unless `RIDM_REQUIRE_SOFTHSM=1`
//! (CI sets it).
#![cfg(feature = "hsm-pkcs11")]

use std::path::PathBuf;
use std::process::Command;

use ridm_api::key_custody::config::Pkcs11Config;
use ridm_api::key_custody::pkcs11::Pkcs11Wrapper;
use ridm_api::util::secret::SecretString;
use ridm_core::providers::{KeyWrapper, ProviderError};

const PIN: &str = "4711-ridm";

fn softhsm() -> Option<(PathBuf, String)> {
    let module = std::env::var_os("RIDM_TEST_PKCS11_MODULE")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/usr/lib/softhsm/libsofthsm2.so".into());
    let util = std::env::var("RIDM_TEST_SOFTHSM_UTIL").unwrap_or_else(|_| "softhsm2-util".into());
    let required = std::env::var("RIDM_REQUIRE_SOFTHSM").as_deref() == Ok("1");
    let usable = module.exists()
        && Command::new(&util)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
    if !usable {
        assert!(
            !required,
            "RIDM_REQUIRE_SOFTHSM=1 but SoftHSM is missing ({} / {util})",
            module.display()
        );
        eprintln!("skipping: SoftHSM is not installed");
        return None;
    }
    Some((module, util))
}

/// A fresh token of its own, so runs never see each other's keys.
fn init_token(module: &std::path::Path, util: &str) -> String {
    let label = format!("ridm-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let out = Command::new(util)
        .arg("--module")
        .arg(module)
        .args(["--init-token", "--free", "--label", &label])
        .args(["--pin", PIN, "--so-pin", "so-4711-ridm"])
        .output()
        .expect("run softhsm2-util");
    assert!(
        out.status.success(),
        "softhsm2-util --init-token: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    label
}

fn config(module: &std::path::Path, token: &str, pin: &str, generate: bool) -> Pkcs11Config {
    Pkcs11Config {
        module: module.to_path_buf(),
        token_label: Some(token.into()),
        slot: None,
        pin: SecretString::new(pin.into()),
        key_label: "ridm-master-key".into(),
        generate_key: generate,
    }
}

/// One test: every PKCS#11 context in the process shares the library's
/// global state, and dropping one finalizes it for all.
#[tokio::test]
async fn an_hsm_key_wraps_data_keys_it_never_releases() {
    let Some((module, util)) = softhsm() else {
        return;
    };
    let token = init_token(&module, &util);

    // Without the key, and without leave to create it, start-up refuses.
    let err = Pkcs11Wrapper::new(&config(&module, &token, PIN, false))
        .await
        .err()
        .expect("no key on a fresh token");
    assert!(err.to_string().contains("PKCS11_GENERATE_KEY"), "{err}");

    let hsm = Pkcs11Wrapper::new(&config(&module, &token, PIN, true))
        .await
        .unwrap();
    let data_key = [0x77u8; 32];
    let wrapped = hsm.wrap(&data_key, b"ridm:master-key:v2").await.unwrap();
    assert_eq!(wrapped.key_ref, "ridm-master-key");
    assert_eq!(wrapped.wrapped.len(), 12 + 32 + 16, "IV, ciphertext, tag");
    let back = hsm
        .unwrap(&wrapped.key_ref, &wrapped.wrapped, b"ridm:master-key:v2")
        .await
        .unwrap();
    assert_eq!(&*back, &data_key);
    // Two wraps of the same key differ (fresh IV).
    let again = hsm.wrap(&data_key, b"ridm:master-key:v2").await.unwrap();
    assert_ne!(again.wrapped, wrapped.wrapped);

    // The generation is authenticated, and so is every byte.
    assert!(
        hsm.unwrap(&wrapped.key_ref, &wrapped.wrapped, b"ridm:master-key:v3")
            .await
            .is_err()
    );
    let mut tampered = wrapped.wrapped.clone();
    tampered[20] ^= 1;
    assert!(
        hsm.unwrap(&wrapped.key_ref, &tampered, b"ridm:master-key:v2")
            .await
            .is_err()
    );
    let err = hsm
        .unwrap("no-such-key", &wrapped.wrapped, b"ridm:master-key:v2")
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::Rejected(_)), "{err}");

    // A second context (a restarted node) finds the key by its label now,
    // without creating another.
    let restarted = Pkcs11Wrapper::new(&config(&module, &token, PIN, false))
        .await
        .unwrap();
    assert_eq!(
        &*restarted
            .unwrap(&wrapped.key_ref, &wrapped.wrapped, b"ridm:master-key:v2")
            .await
            .unwrap(),
        &data_key
    );

    // A wrong PIN and an unknown token are configuration errors.
    let err = Pkcs11Wrapper::new(&config(&module, &init_token(&module, &util), "0000", true))
        .await
        .err()
        .expect("wrong PIN");
    assert!(matches!(err, ProviderError::Configuration(_)), "{err}");
    let err = Pkcs11Wrapper::new(&config(&module, "no-such-token", PIN, true))
        .await
        .err()
        .expect("unknown token");
    assert!(err.to_string().contains("no-such-token"), "{err}");
    drop(restarted);
    drop(hsm);
}
