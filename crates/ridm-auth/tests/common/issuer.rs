//! The stand-in tenant itself (see `mod.rs`).

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};

/// Three P-256 keys. `k1` and `k2` are published (the second only after a
/// rotation); `rogue` never is, and stands for a forger's key.
pub const K1_PEM: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEUqEcN58QqiXv3iF\n\
+CGrop6xKhzyu9kh2B6ZoeDWh8KhRANCAATi6aTbvx2timWvJeHjaiPuYD0hakwv\n\
SY1A7yUsShEIljGZrGG5GISYEHHk1sZaNutuTAcGDs/f6iNGGS2gATnK\n\
-----END PRIVATE KEY-----";
const K1_X: &str = "4umk278drYplryXh42oj7mA9IWpML0mNQO8lLEoRCJY";
const K1_Y: &str = "MZmsYbkYhJgQceTWxlo2625MBwYOz9_qI0YZLaABOco";

pub const K2_PEM: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfaZ80mze1YgnjwZ/\n\
RaI2XZHsp6IY8ZuVADWMvYAEn/yhRANCAAT600DZAwpNa2OoyItXbjAzuxQ4OVXf\n\
0oKUli53OnPYDMaDx37NaOoBgiFiJkOx+dfcRgE9/EaK+FUapO9ZMa19\n\
-----END PRIVATE KEY-----";
const K2_X: &str = "-tNA2QMKTWtjqMiLV24wM7sUODlV39KClJYudzpz2Aw";
const K2_Y: &str = "xoPHfs1o6gGCIWImQ7H519xGAT38Ror4VRqk71kxrX0";

pub const ROGUE_PEM: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgG5cUCfSSKSE7J90R\n\
VgMYg444jddToFVmBmYuziWxHIWhRANCAAQy6vB4qia3O9Rj3APB43qLz1MlCyXU\n\
CAPhJwxcqHtvyQb3EpZ8cDC6RQ7h3OuWS+Qv08vNMsYaRkzRdEtU9nLr\n\
-----END PRIVATE KEY-----";

/// The published JWK for `k1`.
pub fn k1_jwk() -> Value {
    jwk("k1", K1_X, K1_Y)
}

/// The published JWK for `k2`.
pub fn k2_jwk() -> Value {
    jwk("k2", K2_X, K2_Y)
}

fn jwk(kid: &str, x: &str, y: &str) -> Value {
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "alg": "ES256",
        "use": "sig",
        "kid": kid,
    })
}

#[derive(Debug)]
struct Inner {
    keys: Mutex<Vec<Value>>,
    /// What the discovery document claims as its issuer.
    issuer: Mutex<String>,
    jwks_requests: AtomicUsize,
    jwks_down: AtomicBool,
}

/// A running issuer. Dropping it leaves the server task to be reaped with the
/// test's runtime.
#[derive(Clone, Debug)]
pub struct Issuer {
    pub base: String,
    inner: Arc<Inner>,
}

impl Issuer {
    /// Start an issuer publishing `k1` only.
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let inner = Arc::new(Inner {
            keys: Mutex::new(vec![k1_jwk()]),
            issuer: Mutex::new(base.clone()),
            jwks_requests: AtomicUsize::new(0),
            jwks_down: AtomicBool::new(false),
        });
        let issuer = Self {
            base: base.clone(),
            inner: inner.clone(),
        };
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/.well-known/jwks.json", get(jwks))
            .with_state(issuer.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        issuer
    }

    pub fn jwks_uri(&self) -> String {
        format!("{}/.well-known/jwks.json", self.base)
    }

    /// Replace the published key set.
    pub fn publish(&self, keys: Vec<Value>) {
        *self.inner.keys.lock().expect("keys") = keys;
    }

    /// Make the key set answer 503, as an issuer having a bad day would.
    pub fn take_jwks_down(&self, down: bool) {
        self.inner.jwks_down.store(down, Ordering::SeqCst);
    }

    /// Make the discovery document name a different issuer.
    pub fn claim_issuer(&self, issuer: &str) {
        *self.inner.issuer.lock().expect("issuer") = issuer.to_string();
    }

    /// How often the key set has been fetched.
    pub fn jwks_requests(&self) -> usize {
        self.inner.jwks_requests.load(Ordering::SeqCst)
    }

    /// A validator for this issuer, asking for `urn:orders`.
    pub fn validator(&self) -> ridm_auth::ValidatorBuilder {
        ridm_auth::Validator::builder(&self.base)
            .audience("urn:orders")
            .allow_http(true)
    }

    /// The claims of an ordinary, valid access token for `urn:orders`.
    pub fn claims(&self) -> Value {
        json!({
            "iss": self.base,
            "sub": "5d3a1f12-4b0e-4a5f-9b6f-1c2d3e4f5a6b",
            "aud": "urn:orders",
            "exp": unix_now() + 300,
            "iat": unix_now(),
            "nbf": unix_now(),
            "jti": "01J0000000000000000000000",
            "tid": "9f1d6b6e-7c2a-4f3d-8e5b-0a1b2c3d4e5f",
            "client_id": "orders-web",
            "azp": "orders-web",
            "scope": "openid orders:read",
            "roles": ["staff"],
            "groups": ["warehouse"],
            "permissions": ["orders:read"],
        })
    }
}

async fn discovery(State(issuer): State<Issuer>) -> Response {
    let document = json!({
        "issuer": *issuer.inner.issuer.lock().expect("issuer"),
        "jwks_uri": issuer.jwks_uri(),
        "authorization_endpoint": format!("{}/authorize", issuer.base),
        "token_endpoint": format!("{}/token", issuer.base),
    });
    axum::Json(document).into_response()
}

async fn jwks(State(issuer): State<Issuer>) -> Response {
    issuer.inner.jwks_requests.fetch_add(1, Ordering::SeqCst);
    if issuer.inner.jwks_down.load(Ordering::SeqCst) {
        return (StatusCode::SERVICE_UNAVAILABLE, "down").into_response();
    }
    let keys = issuer.inner.keys.lock().expect("keys").clone();
    axum::Json(json!({ "keys": keys })).into_response()
}

/// Sign `claims` with `pem`, naming `kid` and `typ` in the header.
pub fn sign(pem: &str, kid: &str, typ: &str, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.to_string());
    header.typ = Some(typ.to_string());
    let key = EncodingKey::from_ec_pem(pem.as_bytes()).expect("private key");
    jsonwebtoken::encode(&header, claims, &key).expect("sign")
}

/// An `at+jwt` access token signed by `k1`.
pub fn access_token(claims: &Value) -> String {
    sign(K1_PEM, "k1", "at+jwt", claims)
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}
