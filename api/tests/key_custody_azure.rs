//! The Azure Key Vault key wrapper (`kms-azure`) against a fake Entra ID
//! token endpoint, managed-identity endpoint and Key Vault: client secret,
//! workload identity and managed identity tokens, the recorded key version
//! and algorithm, and a stored key id that points elsewhere never getting
//! the token. Azure has no local Key Vault emulator.
#![cfg(feature = "kms-azure")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use ridm_api::key_custody::azure_kv::AzureKeyVault;
use ridm_api::key_custody::config::{AzureCredential, AzureKeyVaultConfig};
use ridm_api::util::secret::SecretString;
use ridm_core::providers::{KeyWrapper, ProviderError};
use serde_json::{Value, json};

const TENANT: &str = "00000000-0000-0000-0000-00000000000a";
const CLIENT: &str = "00000000-0000-0000-0000-00000000000b";

#[derive(Default)]
struct Fake {
    base: String,
    wrapped: HashMap<String, (Vec<u8>, String)>,
    /// Bearer tokens Key Vault saw.
    tokens: Vec<String>,
}

type Shared = Arc<Mutex<Fake>>;

fn b64url() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

async fn entra_token(
    State(fake): State<Shared>,
    Path(tenant): Path<String>,
    Form(form): Form<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let base = fake.lock().unwrap().base.clone();
    assert_eq!(tenant, TENANT);
    assert_eq!(form["grant_type"], "client_credentials");
    assert_eq!(form["client_id"], CLIENT);
    // The audience is the vault's host (here an address, so all of it).
    assert_eq!(
        form["scope"],
        format!("{}/.default", base.rsplit_once(':').unwrap().0)
    );
    let token = match (form.get("client_secret"), form.get("client_assertion")) {
        (Some(s), None) if s == "app-secret" => "secret-token",
        (None, Some(a)) if a == "federated-jwt" => {
            assert_eq!(
                form["client_assertion_type"],
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            );
            "federated-token"
        }
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid_client" })),
            );
        }
    };
    (
        StatusCode::OK,
        Json(json!({ "access_token": token, "expires_in": 3599 })),
    )
}

async fn identity(
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    if headers
        .get("X-IDENTITY-HEADER")
        .and_then(|v| v.to_str().ok())
        != Some("identity-header")
    {
        return (StatusCode::FORBIDDEN, Json(json!({})));
    }
    assert_eq!(q["api-version"], "2019-08-01");
    assert!(q["resource"].starts_with("http://127.0.0.1"));
    (StatusCode::OK, Json(json!({ "access_token": "msi-token" })))
}

fn bearer(fake: &Shared, headers: &HeaderMap) -> bool {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_string();
    let ok = ["secret-token", "federated-token", "msi-token"].contains(&token.as_str());
    fake.lock().unwrap().tokens.push(token);
    ok
}

async fn wrap(
    State(fake): State<Shared>,
    Path(path): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    assert_eq!(q["api-version"], "7.4");
    if !bearer(&fake, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
    let mut fake = fake.lock().unwrap();
    let parts: Vec<&str> = path.split('/').collect();
    let (name, version, op) = match parts.as_slice() {
        [name, op] => (*name, "v-current", *op),
        [name, version, op] => (*name, *version, *op),
        _ => return (StatusCode::NOT_FOUND, Json(json!({}))),
    };
    assert_eq!(name, "ridm");
    let alg = body["alg"].as_str().unwrap().to_string();
    let value = b64url().decode(body["value"].as_str().unwrap()).unwrap();
    match op {
        "wrapkey" => {
            let id = uuid::Uuid::new_v4().to_string();
            fake.wrapped.insert(id.clone(), (value, alg));
            (
                StatusCode::OK,
                Json(json!({
                    "kid": format!("{}/keys/{name}/{version}", fake.base),
                    "value": b64url().encode(id.as_bytes()),
                })),
            )
        }
        "unwrapkey" => {
            let id = String::from_utf8(value).unwrap();
            match fake.wrapped.get(&id) {
                Some((pt, a)) if *a == alg => (
                    StatusCode::OK,
                    Json(
                        json!({ "kid": format!("{}/keys/{name}/{version}", fake.base), "value": b64url().encode(pt) }),
                    ),
                ),
                _ => (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": { "code": "BadParameter" } })),
                ),
            }
        }
        _ => (StatusCode::NOT_FOUND, Json(json!({}))),
    }
}

async fn server() -> (String, Shared) {
    let fake: Shared = Arc::default();
    let app = Router::new()
        .route("/{tenant}/oauth2/v2.0/token", post(entra_token))
        .route("/msi/token", get(identity))
        .route("/keys/{*path}", post(wrap))
        .with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    fake.lock().unwrap().base = base.clone();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, fake)
}

fn credential(base: &str) -> AzureCredential {
    AzureCredential {
        tenant_id: Some(TENANT.into()),
        client_id: Some(CLIENT.into()),
        client_secret: None,
        federated_token_file: None,
        authority_host: base.parse().unwrap(),
        identity_endpoint: None,
        imds_endpoint: "http://127.0.0.1:9/metadata/identity/oauth2/token"
            .parse()
            .unwrap(),
    }
}

fn config(base: &str, credential: AzureCredential) -> AzureKeyVaultConfig {
    AzureKeyVaultConfig {
        vault_url: base.parse().unwrap(),
        key: "ridm".into(),
        key_version: None,
        algorithm: "RSA-OAEP-256".into(),
        credential,
    }
}

async fn round_trip(vault: &AzureKeyVault, base: &str, version: &str) {
    let data_key = [0x33u8; 32];
    let wrapped = vault.wrap(&data_key, b"ridm:master-key:v7").await.unwrap();
    assert_eq!(
        wrapped.key_ref,
        format!("{base}/keys/ridm/{version}#RSA-OAEP-256"),
        "the key version and the algorithm are recorded"
    );
    let back = vault
        .unwrap(&wrapped.key_ref, &wrapped.wrapped, b"ridm:master-key:v7")
        .await
        .unwrap();
    assert_eq!(&*back, &data_key);
}

#[tokio::test]
async fn a_client_secret_gets_the_token() {
    let (base, fake) = server().await;
    let mut c = credential(&base);
    c.client_secret = Some(SecretString::new("app-secret".into()));
    round_trip(
        &AzureKeyVault::new(&config(&base, c)).unwrap(),
        &base,
        "v-current",
    )
    .await;
    assert!(
        fake.lock()
            .unwrap()
            .tokens
            .iter()
            .all(|t| t == "secret-token")
    );
}

#[tokio::test]
async fn workload_identity_reads_the_federated_token_file() {
    let (base, fake) = server().await;
    let file: PathBuf = std::env::temp_dir().join(format!("ridm-azure-{}", uuid::Uuid::new_v4()));
    std::fs::write(&file, "federated-jwt\n").unwrap();
    let mut c = credential(&base);
    c.federated_token_file = Some(file.clone());
    let mut cfg = config(&base, c);
    cfg.key_version = Some("v42".into());
    round_trip(&AzureKeyVault::new(&cfg).unwrap(), &base, "v42").await;
    assert!(
        fake.lock()
            .unwrap()
            .tokens
            .iter()
            .all(|t| t == "federated-token")
    );
    // The kubelet rotated the token to one Entra ID does not accept.
    std::fs::write(&file, "stale").unwrap();
    let err = AzureKeyVault::new(&cfg)
        .unwrap()
        .wrap(&[0u8; 32], b"")
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::Configuration(_)), "{err}");
    std::fs::remove_file(file).unwrap();
}

#[tokio::test]
async fn a_managed_identity_endpoint_gets_the_token() {
    let (base, fake) = server().await;
    let mut c = credential(&base);
    c.tenant_id = None;
    c.identity_endpoint = Some((
        format!("{base}/msi/token").parse().unwrap(),
        SecretString::new("identity-header".into()),
    ));
    round_trip(
        &AzureKeyVault::new(&config(&base, c)).unwrap(),
        &base,
        "v-current",
    )
    .await;
    assert!(fake.lock().unwrap().tokens.iter().all(|t| t == "msi-token"));
}

#[tokio::test]
async fn a_stored_key_id_elsewhere_never_gets_the_token() {
    let (base, fake) = server().await;
    let mut c = credential(&base);
    c.client_secret = Some(SecretString::new("app-secret".into()));
    let vault = AzureKeyVault::new(&config(&base, c)).unwrap();
    let wrapped = vault.wrap(&[1u8; 32], b"").await.unwrap();
    let seen = fake.lock().unwrap().tokens.len();
    for key_ref in [
        "https://attacker.example/keys/ridm/v1#RSA-OAEP-256".to_string(),
        format!("{base}/secrets/ridm/v1#RSA-OAEP-256"),
        format!("{base}/keys/ridm/v1?x=1#RSA-OAEP-256"),
        format!("{base}/keys/ridm/v-current#RSA1_5"),
        format!("{base}/keys/ridm/v-current"),
    ] {
        let err = vault
            .unwrap(&key_ref, &wrapped.wrapped, b"")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ProviderError::Rejected(_)),
            "{key_ref}: {err}"
        );
    }
    assert_eq!(
        fake.lock().unwrap().tokens.len(),
        seen,
        "no request was made"
    );
    // The same key id with another algorithm is refused by the vault.
    let (kid, _) = wrapped.key_ref.rsplit_once('#').unwrap();
    let err = vault
        .unwrap(&format!("{kid}#RSA-OAEP"), &wrapped.wrapped, b"")
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::Rejected(_)), "{err}");
}
