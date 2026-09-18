//! An orders API that accepts rIDM access tokens.
//!
//! The whole of the authentication is [`ridm_auth`]: one [`Validator`] built at
//! startup, a [`Guard`] per route subtree naming the permission that subtree
//! needs, and [`RidmClaims`] where a handler wants to know who is calling.
//! There is no session, no cookie and no user table here — a resource server
//! holds none of that.
//!
//! ```text
//! RIDM_ISSUER=http://localhost:8090/t/demo \
//! RIDM_AUDIENCE=https://orders.example \
//! RIDM_ALLOW_HTTP=true \
//! cargo run -p ridm-example-axum-api
//! ```

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::from_fn_with_state;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use ridm_auth::Validator;
use ridm_auth::axum::{Guard, RidmClaims};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
struct Order {
    id: Uuid,
    item: String,
    quantity: u32,
    /// The `sub` of the token that placed it.
    placed_by: String,
    placed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
struct NewOrder {
    item: String,
    #[serde(default = "one")]
    quantity: u32,
}

fn one() -> u32 {
    1
}

/// Everything the router needs: the validator (which the extractors read
/// through `FromRef`) and the orders themselves.
#[derive(Clone)]
struct AppState {
    validator: Arc<Validator>,
    orders: Arc<Mutex<Vec<Order>>>,
}

impl axum::extract::FromRef<AppState> for Arc<Validator> {
    fn from_ref(state: &AppState) -> Self {
        state.validator.clone()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,ridm_auth=debug".into()),
        )
        .init();

    let issuer = env("RIDM_ISSUER")?;
    let audience = env("RIDM_AUDIENCE")?;
    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".into());
    // A tenant on `http://localhost` is a development tenant; in production the
    // issuer is https and this stays false.
    let allow_http = std::env::var("RIDM_ALLOW_HTTP").is_ok_and(|v| v == "true");

    // One validator for the process. It holds the key-set cache, so building
    // one per request would fetch the key set on every request.
    let validator = Validator::builder(&issuer)
        .audience(&audience)
        .allow_http(allow_http)
        .discover()
        .await?
        .shared();
    // Not required — the first request would fetch the keys anyway — but it
    // turns a misconfigured issuer into a startup failure instead of a 503 on
    // someone's first call.
    validator.warm().await?;
    tracing::info!(%issuer, %audience, jwks = %validator.jwks_uri(), "trusting");

    let state = AppState {
        validator: validator.clone(),
        orders: Arc::new(Mutex::new(Vec::new())),
    };

    // Each subtree carries the permission it needs. The guard validates once
    // and leaves the claims in the request extensions, so `RidmClaims` in a
    // handler below costs nothing more.
    let read = Router::new()
        .route("/orders", get(list_orders))
        .route_layer(from_fn_with_state(
            Guard::new(validator.clone())
                .permission("orders:read")
                .realm("orders"),
            ridm_auth::axum::guard,
        ));
    let write = Router::new()
        .route("/orders", post(place_order))
        .route_layer(from_fn_with_state(
            Guard::new(validator)
                .permission("orders:write")
                .realm("orders"),
            ridm_auth::axum::guard,
        ));

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        // No guard: the extractor alone asks for a valid token and nothing
        // more, which is what an endpoint that only reports on the caller
        // wants. A client reads it to know which buttons to show.
        .route("/whoami", get(whoami))
        .merge(read)
        .merge(write)
        .layer(cors())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("listening on http://{bind}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// The SPA example runs on another origin, so the browser preflights every
/// request that carries an `Authorization` header.
fn cors() -> CorsLayer {
    let origins = std::env::var("CORS_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:3100,http://localhost:3200".into());
    let origins: Vec<HeaderValue> = origins
        .split(',')
        .filter_map(|o| o.trim().parse().ok())
        .collect();
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
}

/// Who the token says is calling, and what it lets them do.
async fn whoami(RidmClaims(claims): RidmClaims) -> impl IntoResponse {
    Json(serde_json::json!({
        "subject": claims.sub,
        "tenant": claims.tid,
        "client": claims.client_id,
        "scopes": claims.scopes().collect::<Vec<_>>(),
        "roles": claims.roles,
        "permissions": claims.permissions,
        // True only when nobody is behind the token — a machine client with
        // no service account.
        "client_only": claims.is_client_only(),
    }))
}

/// Everyone who may read orders sees every order. A real API would scope the
/// query — `claims.sub` is the customer, and an operator's role or permission
/// is what widens it.
async fn list_orders(State(state): State<AppState>) -> impl IntoResponse {
    let orders = state.orders.lock().expect("orders").clone();
    Json(orders)
}

async fn place_order(
    State(state): State<AppState>,
    RidmClaims(claims): RidmClaims,
    Json(new): Json<NewOrder>,
) -> impl IntoResponse {
    if new.item.trim().is_empty() || new.quantity == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "an order needs an item and a quantity" })),
        )
            .into_response();
    }
    let order = Order {
        id: Uuid::now_v7(),
        item: new.item,
        quantity: new.quantity,
        placed_by: claims.sub,
        placed_at: chrono::Utc::now(),
    };
    state.orders.lock().expect("orders").push(order.clone());
    (StatusCode::CREATED, Json(order)).into_response()
}

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is required (see the README)"))
}
