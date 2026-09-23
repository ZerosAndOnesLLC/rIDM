//! The Google Cloud KMS key wrapper (`kms-gcp`) against a fake Cloud KMS, STS,
//! OAuth token endpoint and metadata server that check what Google's would:
//! the service-account JWT's signature and audience, the federation exchange,
//! the impersonation call, bearer tokens and the additional authenticated
//! data. Google has no local KMS emulator.
#![cfg(feature = "kms-gcp")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use ridm_api::key_custody::config::GcpKmsConfig;
use ridm_api::key_custody::gcp_kms::GcpKms;
use ridm_core::providers::{KeyWrapper, ProviderError};
use serde_json::{Value, json};

const KEY: &str = "projects/p1/locations/global/keyRings/ring/cryptoKeys/ridm";

#[derive(Default)]
struct Fake {
    /// PEM of the service account's public key.
    sa_public_pem: String,
    base: String,
    ciphertexts: HashMap<String, (Vec<u8>, Vec<u8>)>,
    tokens_used: Vec<String>,
}

type Shared = Arc<Mutex<Fake>>;

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

async fn token(
    State(fake): State<Shared>,
    Form(form): Form<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let fake = fake.lock().unwrap();
    assert_eq!(
        form["grant_type"],
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    );
    let key = jsonwebtoken::DecodingKey::from_rsa_pem(fake.sa_public_pem.as_bytes()).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[format!("{}/token", fake.base)]);
    validation.set_issuer(&["ridm@p1.iam.gserviceaccount.com"]);
    match jsonwebtoken::decode::<Value>(&form["assertion"], &key, &validation) {
        Ok(data) => {
            assert_eq!(
                data.claims["scope"],
                "https://www.googleapis.com/auth/cloud-platform"
            );
            (
                StatusCode::OK,
                Json(json!({ "access_token": "sa-token", "expires_in": 3600 })),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

async fn metadata(headers: HeaderMap) -> (StatusCode, Json<Value>) {
    if headers.get("Metadata-Flavor").and_then(|v| v.to_str().ok()) != Some("Google") {
        return (StatusCode::FORBIDDEN, Json(json!({})));
    }
    (
        StatusCode::OK,
        Json(json!({ "access_token": "metadata-token" })),
    )
}

async fn sts(Form(form): Form<HashMap<String, String>>) -> (StatusCode, Json<Value>) {
    assert_eq!(
        form["grant_type"],
        "urn:ietf:params:oauth:grant-type:token-exchange"
    );
    assert_eq!(
        form["audience"],
        "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/k8s/providers/cluster"
    );
    assert_eq!(
        form["subject_token_type"],
        "urn:ietf:params:oauth:token-type:jwt"
    );
    if form["subject_token"] != "projected-sa-token" {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_grant" })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "access_token": "federated-token" })),
    )
}

async fn impersonate(headers: HeaderMap, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    assert_eq!(
        body["scope"][0],
        "https://www.googleapis.com/auth/cloud-platform"
    );
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some("Bearer federated-token")
    {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
    (
        StatusCode::OK,
        Json(json!({ "accessToken": "impersonated-token" })),
    )
}

async fn kms(
    State(fake): State<Shared>,
    Path(rest): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let mut fake = fake.lock().unwrap();
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_string();
    if !["sa-token", "metadata-token", "impersonated-token"].contains(&bearer.as_str()) {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
    fake.tokens_used.push(bearer);
    let aad = b64()
        .decode(
            body["additionalAuthenticatedData"]
                .as_str()
                .unwrap_or_default(),
        )
        .unwrap();
    if let Some(name) = rest.strip_suffix(":encrypt") {
        assert_eq!(name, KEY);
        let pt = b64().decode(body["plaintext"].as_str().unwrap()).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        fake.ciphertexts.insert(id.clone(), (pt, aad));
        return (
            StatusCode::OK,
            Json(json!({
                "name": format!("{KEY}/cryptoKeyVersions/1"),
                "ciphertext": b64().encode(id.as_bytes()),
            })),
        );
    }
    let name = rest.strip_suffix(":decrypt").unwrap();
    assert_eq!(name, KEY);
    let id =
        String::from_utf8(b64().decode(body["ciphertext"].as_str().unwrap()).unwrap()).unwrap();
    match fake.ciphertexts.get(&id) {
        Some((pt, want)) if *want == aad => (
            StatusCode::OK,
            Json(json!({ "plaintext": b64().encode(pt) })),
        ),
        _ => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "message": "Decryption failed" } })),
        ),
    }
}

struct Server {
    base: String,
    fake: Shared,
    /// A service-account key file for this server's token endpoint.
    sa_file: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.sa_file);
    }
}

async fn server() -> Server {
    use rsa::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _, LineEnding};
    let private = rsa::RsaPrivateKey::new(&mut rand_core_06::OsRng, 2048).unwrap();
    let public_pem = private
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let fake: Shared = Arc::new(Mutex::new(Fake {
        sa_public_pem: public_pem,
        ..Default::default()
    }));
    let app = Router::new()
        .route("/token", post(token))
        .route("/sts", post(sts))
        .route("/impersonate", post(impersonate))
        .route(
            "/computeMetadata/v1/instance/service-accounts/default/token",
            get(metadata),
        )
        .route("/v1/{*rest}", post(kms))
        .with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    fake.lock().unwrap().base = base.clone();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    // The key file the service-account test writes.
    let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
    let sa_file = temp_file(
        "sa.json",
        &json!({
            "type": "service_account",
            "client_email": "ridm@p1.iam.gserviceaccount.com",
            "private_key": pem.as_str(),
            "token_uri": format!("{base}/token"),
        })
        .to_string(),
    );
    Server {
        base,
        fake,
        sa_file,
    }
}

fn temp_file(name: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("ridm-gcp-{}-{name}", uuid::Uuid::new_v4()));
    std::fs::write(&path, contents).unwrap();
    path
}

fn config(server: &Server, credentials: Option<PathBuf>) -> GcpKmsConfig {
    GcpKmsConfig {
        key: KEY.into(),
        endpoint: server.base.parse().unwrap(),
        credentials_file: credentials,
        metadata_host: server.base.trim_start_matches("http://").into(),
    }
}

async fn round_trip(wrapper: &GcpKms) {
    let data_key = [0x11u8; 32];
    let wrapped = wrapper
        .wrap(&data_key, b"ridm:master-key:v5")
        .await
        .unwrap();
    assert_eq!(wrapped.key_ref, KEY, "the key, not its version");
    let back = wrapper
        .unwrap(&wrapped.key_ref, &wrapped.wrapped, b"ridm:master-key:v5")
        .await
        .unwrap();
    assert_eq!(&*back, &data_key);
    let err = wrapper
        .unwrap(&wrapped.key_ref, &wrapped.wrapped, b"ridm:master-key:v6")
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::Rejected(_)), "{err}");
    let err = wrapper
        .unwrap(
            "projects/p1/locations/global/keyRings/ring/cryptoKeys/../x",
            &wrapped.wrapped,
            b"ridm:master-key:v5",
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("not a Cloud KMS key name"),
        "{err}"
    );
}

#[tokio::test]
async fn a_service_account_key_signs_its_own_token_request() {
    let server = server().await;
    round_trip(&GcpKms::new(&config(&server, Some(server.sa_file.clone()))).unwrap()).await;
    assert!(
        server
            .fake
            .lock()
            .unwrap()
            .tokens_used
            .iter()
            .all(|t| t == "sa-token")
    );
}

#[tokio::test]
async fn the_metadata_server_supplies_the_token_without_a_file() {
    let server = server().await;
    round_trip(&GcpKms::new(&config(&server, None)).unwrap()).await;
    assert!(
        server
            .fake
            .lock()
            .unwrap()
            .tokens_used
            .iter()
            .all(|t| t == "metadata-token")
    );
}

#[tokio::test]
async fn workload_identity_federation_exchanges_a_projected_token() {
    let server = server().await;
    let subject = temp_file("token", "projected-sa-token\n");
    let file = temp_file(
        "external.json",
        &json!({
            "type": "external_account",
            "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/k8s/providers/cluster",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": format!("{}/sts", server.base),
            "service_account_impersonation_url": format!("{}/impersonate", server.base),
            "credential_source": { "file": subject },
        })
        .to_string(),
    );
    round_trip(&GcpKms::new(&config(&server, Some(file.clone()))).unwrap()).await;
    assert!(
        server
            .fake
            .lock()
            .unwrap()
            .tokens_used
            .iter()
            .all(|t| t == "impersonated-token")
    );
    // A subject token the pool does not trust stops at the exchange.
    std::fs::write(&subject, "someone-else").unwrap();
    let err = GcpKms::new(&config(&server, Some(file.clone())))
        .unwrap()
        .wrap(&[0u8; 32], b"")
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::Configuration(_)), "{err}");
    std::fs::remove_file(subject).unwrap();
    std::fs::remove_file(file).unwrap();
}
