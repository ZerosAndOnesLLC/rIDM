//! The Vault / OpenBao Transit key wrapper (`kms-vault`) against the real
//! servers in dev mode, its Kubernetes login against a fake Vault (a real
//! one would need a Kubernetes API to review the service-account token), and
//! the `ridm-api` binary configured through `KEY_WRAPPER=vault`.
#![cfg(feature = "kms-vault")]

mod common;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use base64::Engine as _;
use common::throwaway::ThrowawayDb;
use ridm_api::key_custody::config::{VaultAuth, VaultConfig};
use ridm_api::key_custody::vault::VaultTransit;
use ridm_api::util::secret::SecretString;
use ridm_core::providers::{KeyWrapper, ProviderError};
use serde_json::{Value, json};
use testcontainers::core::{ContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

const ROOT_TOKEN: &str = "ridm-root-token";

/// A dev-mode server of `image`, its Transit engine on and one key made.
async fn dev_server(
    image: &str,
    tag: &str,
    env_prefix: &str,
) -> (testcontainers::ContainerAsync<GenericImage>, String) {
    // Under a loaded Docker a dev server now and then exits as it starts;
    // try again rather than fail the suite on it.
    let mut attempt = 0;
    let (container, port) = loop {
        attempt += 1;
        let started = GenericImage::new(image, tag)
            .with_exposed_port(ContainerPort::Tcp(8200))
            .with_wait_for(WaitFor::message_on_stdout("server started!"))
            .with_env_var(format!("{env_prefix}_DEV_ROOT_TOKEN_ID"), ROOT_TOKEN)
            .with_env_var(format!("{env_prefix}_DEV_LISTEN_ADDRESS"), "0.0.0.0:8200")
            .with_env_var("SKIP_SETCAP", "1")
            .with_label("dev.ridm.test", "true")
            .with_startup_timeout(Duration::from_secs(60))
            .start()
            .await;
        let failure = match started {
            Ok(c) => match c.get_host_port_ipv4(8200).await {
                Ok(port) => break (c, port),
                Err(e) => format!("{e}"),
            },
            Err(e) => format!("{e}"),
        };
        assert!(attempt < 3, "{image} did not start three times: {failure}");
        eprintln!("{image} did not start ({failure}); trying again");
    };
    let addr = format!("http://127.0.0.1:{port}");
    let http = reqwest::Client::new();
    let mut up = false;
    for _ in 0..120 {
        if http
            .get(format!("{addr}/v1/sys/health"))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(up, "{image} never became healthy");
    for (path, body) in [
        ("sys/mounts/transit", json!({ "type": "transit" })),
        ("transit/keys/ridm", json!({})),
    ] {
        let r = http
            .post(format!("{addr}/v1/{path}"))
            .header("X-Vault-Token", ROOT_TOKEN)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success(), "{path}: {}", r.status());
    }
    (container, addr)
}

fn config(addr: &str, key: &str, auth: VaultAuth) -> VaultConfig {
    VaultConfig {
        addr: addr.parse().unwrap(),
        mount: "transit".into(),
        key: key.into(),
        namespace: None,
        ca_file: None,
        auth,
    }
}

fn token(t: &str) -> VaultAuth {
    VaultAuth::Token(SecretString::new(t.to_string()))
}

async fn exercise(image: &str, tag: &str, env_prefix: &str) {
    let (_server, addr) = dev_server(image, tag, env_prefix).await;
    let transit = VaultTransit::new(&config(&addr, "ridm", token(ROOT_TOKEN))).unwrap();
    let data_key = [0x42u8; 32];
    let wrapped = transit
        .wrap(&data_key, b"ridm:master-key:v2")
        .await
        .unwrap();
    assert_eq!(wrapped.key_ref, "transit/ridm");
    assert!(wrapped.wrapped.starts_with(b"vault:v1:"), "{image}");
    let back = transit
        .unwrap(&wrapped.key_ref, &wrapped.wrapped, b"ridm:master-key:v2")
        .await
        .unwrap();
    assert_eq!(&*back, &data_key);

    // Rotating the Transit key keeps older ciphertexts decrypting.
    let http = reqwest::Client::new();
    let r = http
        .post(format!("{addr}/v1/transit/keys/ridm/rotate"))
        .header("X-Vault-Token", ROOT_TOKEN)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let newer = transit.wrap(&data_key, b"").await.unwrap();
    assert!(newer.wrapped.starts_with(b"vault:v2:"));
    assert_eq!(
        &*transit
            .unwrap(&wrapped.key_ref, &wrapped.wrapped, b"")
            .await
            .unwrap(),
        &data_key
    );

    // A bad token is the deployment's configuration, not an outage.
    let denied = VaultTransit::new(&config(&addr, "ridm", token("wrong")))
        .unwrap()
        .unwrap(&wrapped.key_ref, &wrapped.wrapped, b"")
        .await
        .unwrap_err();
    assert!(
        matches!(denied, ProviderError::Configuration(_)),
        "{denied}"
    );
    // A key reference naming another key does not decrypt.
    let other = transit
        .unwrap("transit/other", &wrapped.wrapped, b"")
        .await
        .unwrap_err();
    assert!(!other.is_retryable(), "{other}");
    // Nothing but a Transit ciphertext is sent.
    assert!(
        transit
            .unwrap("transit/ridm", b"garbage", b"")
            .await
            .is_err()
    );
    // An unreachable server is retryable.
    let down = VaultTransit::new(&config("http://127.0.0.1:9", "ridm", token(ROOT_TOKEN)))
        .unwrap()
        .wrap(&data_key, b"")
        .await
        .unwrap_err();
    assert!(down.is_retryable(), "{down}");
}

#[tokio::test]
async fn hashicorp_vault_transit_wraps_and_unwraps() {
    exercise("hashicorp/vault", "2.1.1", "VAULT").await;
}

#[tokio::test]
async fn openbao_transit_wraps_and_unwraps() {
    exercise("openbao/openbao", "2.6.2", "BAO").await;
}

/// What the fake Vault saw.
#[derive(Default)]
struct Seen {
    logins: Vec<Value>,
    namespaces: Vec<String>,
}

type Fake = Arc<Mutex<Seen>>;

async fn fake_login(
    State(seen): State<Fake>,
    Path(mount): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    seen.lock().unwrap().logins.push(body.clone());
    if mount != "k8s" || body["jwt"] != "sa-token-from-kubelet" || body["role"] != "ridm" {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "errors": ["permission denied"] })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "auth": { "client_token": "vault-session-token" } })),
    )
}

async fn fake_transit(
    State(seen): State<Fake>,
    Path((op, key)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Some(ns) = headers.get("X-Vault-Namespace") {
        seen.lock()
            .unwrap()
            .namespaces
            .push(ns.to_str().unwrap().into());
    }
    if headers.get("X-Vault-Token").and_then(|v| v.to_str().ok()) != Some("vault-session-token")
        || key != "ridm"
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "errors": ["permission denied"] })),
        );
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    match op.as_str() {
        "encrypt" => {
            let pt = body["plaintext"].as_str().unwrap();
            (
                StatusCode::OK,
                Json(json!({ "data": { "ciphertext": format!("vault:v1:{pt}") } })),
            )
        }
        _ => {
            let ct = body["ciphertext"].as_str().unwrap();
            let pt = ct.strip_prefix("vault:v1:").unwrap();
            assert!(b64.decode(pt).is_ok());
            (StatusCode::OK, Json(json!({ "data": { "plaintext": pt } })))
        }
    }
}

#[tokio::test]
async fn kubernetes_auth_logs_in_with_the_service_account_token() {
    let seen: Fake = Arc::default();
    let app = axum::Router::new()
        .route("/v1/auth/{mount}/login", post(fake_login))
        .route("/v1/transit/{op}/{key}", post(fake_transit))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let token_file: PathBuf =
        std::env::temp_dir().join(format!("ridm-sa-token-{}", uuid::Uuid::new_v4()));
    std::fs::write(&token_file, "sa-token-from-kubelet\n").unwrap();
    let mut c = config(
        &addr,
        "ridm",
        VaultAuth::Kubernetes {
            role: "ridm".into(),
            mount: "k8s".into(),
            token_file: token_file.clone(),
        },
    );
    c.namespace = Some("team-a".into());
    let transit = VaultTransit::new(&c).unwrap();
    let wrapped = transit.wrap(&[7u8; 32], b"ctx").await.unwrap();
    let back = transit
        .unwrap(&wrapped.key_ref, &wrapped.wrapped, b"ctx")
        .await
        .unwrap();
    assert_eq!(&*back, &[7u8; 32]);
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.logins.len(), 2, "one login per call");
        assert!(seen.namespaces.iter().all(|n| n == "team-a"));
        assert_eq!(seen.namespaces.len(), 2);
    }

    // A token the auth method refuses stops there.
    std::fs::write(&token_file, "someone-else").unwrap();
    let err = transit.wrap(&[7u8; 32], b"").await.unwrap_err();
    assert!(matches!(err, ProviderError::Configuration(_)), "{err}");
    std::fs::remove_file(&token_file).unwrap();
    let err = transit.wrap(&[7u8; 32], b"").await.unwrap_err();
    assert!(err.to_string().contains("service-account token"), "{err}");
}

/// The pretty-printed status report in the command's output, which also
/// carries its JSON log lines.
fn report(out: &str) -> Value {
    let start = out
        .find("\n{\n")
        .map(|i| i + 1)
        .or_else(|| out.starts_with("{\n").then_some(0))
        .unwrap_or_else(|| panic!("no report in {out}"));
    let mut stream = serde_json::Deserializer::from_str(&out[start..]).into_iter::<Value>();
    stream.next().unwrap().expect("report JSON")
}

/// `ridm-api <args>` with the variables an operator sets, in a directory
/// without the repository's `.env`.
async fn ridm_api(
    database_url: &str,
    vars: &[(&str, String)],
    args: &[&str],
) -> (i32, String, String) {
    let infra = common::infra().await;
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_ridm-api"));
    cmd.current_dir(std::env::temp_dir())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("DATABASE_URL", database_url)
        .env("REDIS_URL", &infra.redis_url)
        .env("PUBLIC_URL", "http://127.0.0.1:1")
        .env("LOG_FORMAT", "json")
        .env("MIGRATE_ON_START", "true")
        .env("BOOTSTRAP_ADMIN_EMAIL", "root@example.test")
        .env("BOOTSTRAP_ADMIN_PASSWORD", "Kc-Test-Passw0rd!2026")
        .env("BOOTSTRAP_ADMIN_USERNAME", "root")
        .args(args);
    for (k, v) in vars {
        cmd.env(k, v);
    }
    let out = cmd.output().await.expect("run ridm-api");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A signing key for the master tenant, written by an in-process node
/// configured like the binary (`KEY_WRAPPER=vault` unless `env_key`), so
/// the runs below have a secret to move.
async fn seed_secret(database_url: &str, addr: &str, env_key: Option<u8>) {
    use ridm_api::key_custody::{Backend, KeyCustodyConfig};
    let infra = common::infra().await;
    let mut config = common::test_config(database_url, &infra.redis_url, "http://127.0.0.1:1");
    config.master_key = env_key.map(|k| ridm_api::util::secret::SecretBytes::new(vec![k; 32]));
    if env_key.is_none() {
        config.key_custody = KeyCustodyConfig {
            wrapper: Some(Backend::Vault),
            vault: Some(root_config(addr)),
            ..Default::default()
        };
    }
    let db = ridm_api::db::connect(&config).await.unwrap();
    let redis = ridm_api::cache::connect(&config).unwrap();
    let state = ridm_api::state::AppState::new(config, db, redis);
    ridm_api::key_custody::attach(&state).await.unwrap();
    ridm_api::services::keys::create(
        &state,
        ridm_api::models::MASTER_TENANT_ID,
        ridm_core::events::Actor::System,
        ridm_api::models::SigningAlg::EdDSA,
        ridm_api::models::RsaBits::B2048,
        ridm_api::models::KeyStatus::Active,
        None,
    )
    .await
    .unwrap();
    state.db.close().await;
}

fn root_config(addr: &str) -> VaultConfig {
    config(addr, "ridm", token(ROOT_TOKEN))
}

/// Every encrypted row of the report is under `version`.
fn all_under(status: &Value, version: u64) {
    let mut rows = 0;
    for (table, versions) in status["rows_by_version"].as_object().unwrap() {
        for (v, n) in versions.as_object().unwrap() {
            assert_eq!(v, &version.to_string(), "{table}: {status:#}");
            rows += n.as_u64().unwrap();
        }
    }
    assert!(rows > 0, "{status:#}");
}

#[tokio::test]
async fn the_binary_runs_on_vault_from_day_one_and_after_a_move() {
    let (_server, addr) = dev_server("hashicorp/vault", "2.1.1", "VAULT").await;
    let vault = |extra: &[(&'static str, &str)]| -> Vec<(&'static str, String)> {
        [
            ("VAULT_ADDR", addr.as_str()),
            ("VAULT_TOKEN", ROOT_TOKEN),
            ("VAULT_TRANSIT_KEY", "ridm"),
        ]
        .iter()
        .chain(extra)
        .map(|(k, v)| (*k, v.to_string()))
        .collect()
    };
    let env_key = "07".repeat(32);

    // A new deployment with no MASTER_KEY at all: bootstrap makes the first
    // generation in Vault and encrypts the master tenant's keys under it.
    let guard1 = ThrowawayDb::new(false).await;
    let db1 = guard1.url.as_str();
    let kms_only = vault(&[("KEY_WRAPPER", "vault")]);
    let (code, out, err) = ridm_api(db1, &kms_only, &["bootstrap"]).await;
    assert_eq!(code, 0, "{out}\n{err}");
    seed_secret(db1, &addr, None).await;
    let (code, out, err) = ridm_api(db1, &kms_only, &["rotate-master-key", "--status"]).await;
    assert_eq!(code, 0, "{out}\n{err}");
    let status = report(&out);
    assert_eq!(status["key_wrapper"], "vault");
    assert_eq!(status["current_version"], 1);
    assert_eq!(status["generations"][0]["backend"], "vault");
    assert_eq!(status["generations"][0]["key_ref"], "transit/ridm");
    all_under(&status, 1);
    let pool = sqlx::PgPool::connect(db1).await.unwrap();
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT wrapped_key FROM master_key_generations WHERE version = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        stored.starts_with(b"vault:v1:"),
        "only Vault's ciphertext is stored"
    );
    pool.close().await;

    // `--new-generation` wraps another and moves every row onto it.
    let (code, out, err) =
        ridm_api(db1, &kms_only, &["rotate-master-key", "--new-generation"]).await;
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(out.contains("created master-key generation 2"), "{out}");
    let (_, out, _) = ridm_api(db1, &kms_only, &["rotate-master-key", "--status"]).await;
    all_under(&report(&out), 2);

    // A bad Vault token refuses to start rather than run on the wrong key.
    let bad = vec![
        ("KEY_WRAPPER", "vault".to_string()),
        ("VAULT_ADDR", addr.clone()),
        ("VAULT_TOKEN", "wrong".into()),
        ("VAULT_TRANSIT_KEY", "ridm".into()),
    ];
    let (code, _, err) = ridm_api(db1, &bad, &["rotate-master-key", "--status"]).await;
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("key custody"), "{err}");
    drop(guard1);

    // An existing deployment on MASTER_KEY moves to Vault online, then back.
    let guard2 = ThrowawayDb::new(false).await;
    let db2 = guard2.url.as_str();
    let env_only = vec![
        ("MASTER_KEY", env_key.clone()),
        ("MASTER_KEY_VERSION", "1".to_string()),
    ];
    let (code, out, err) = ridm_api(db2, &env_only, &["bootstrap"]).await;
    assert_eq!(code, 0, "{out}\n{err}");
    seed_secret(db2, &addr, Some(0x07)).await;
    let moving = vault(&[
        ("KEY_WRAPPER", "vault"),
        ("MASTER_KEY", &env_key),
        ("MASTER_KEY_VERSION", "1"),
    ]);
    let (code, out, err) = ridm_api(db2, &moving, &["rotate-master-key"]).await;
    assert_eq!(code, 0, "{out}\n{err}");
    // MASTER_KEY can go once nothing is left under it.
    let (code, out, err) = ridm_api(db2, &kms_only, &["rotate-master-key", "--status"]).await;
    assert_eq!(code, 0, "{out}\n{err}");
    let status = report(&out);
    assert_eq!(
        status["current_version"], 2,
        "above the environment's generation"
    );
    all_under(&status, 2);
    // And back, reading Vault's generation through KEY_WRAPPER_PREVIOUS.
    let back = vault(&[
        ("KEY_WRAPPER_PREVIOUS", "vault"),
        ("MASTER_KEY", &env_key),
        ("MASTER_KEY_VERSION", "1"),
    ]);
    let (code, out, err) = ridm_api(db2, &back, &["rotate-master-key"]).await;
    assert_eq!(code, 0, "{out}\n{err}");
    let (_, out, _) = ridm_api(db2, &env_only, &["rotate-master-key", "--status"]).await;
    all_under(&report(&out), 1);
}
