//! A server-side web app that signs users in with rIDM.
//!
//! The browser never sees a token: the authorization code comes back to this
//! app, this app spends it with its client secret, and what the browser gets is
//! a session cookie. That is the whole reason to be a confidential client.
//!
//! What the example covers, in the order it happens:
//!
//! 1. discovery, so the endpoints are read rather than assembled;
//! 2. `/login` — authorization code with PKCE, `state`, `nonce`, and RFC 8707
//!    `resource` so the access token is minted for the orders API;
//! 3. `/callback` — spend the code, verify the ID token with [`ridm_auth`],
//!    check the nonce, open a session;
//! 4. calling the API, refreshing the access token when it has run out;
//! 5. `/logout` — revoke the refresh token, then RP-initiated logout;
//! 6. `/backchannel-logout` — a logout token from rIDM ends the session here
//!    even though the browser never came back.
//!
//! ```text
//! RIDM_ISSUER=http://localhost:8090/t/demo \
//! RIDM_CLIENT_ID=orders-web RIDM_CLIENT_SECRET=… RIDM_ALLOW_HTTP=true \
//! cargo run -p ridm-example-confidential-client
//! ```

mod config;
mod oidc;
mod pages;
mod session;

use std::sync::Arc;

use axum::Form;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use chrono::Utc;
use ridm_auth::Validator;
use serde::Deserialize;

use config::Config;
use session::{Pending, Session, Store, random_token};

const COOKIE: &str = "ridm_example_session";

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    http: reqwest::Client,
    store: Store,
    /// Verifies ID tokens: `typ` is `JWT` and the audience is this client.
    id_tokens: Arc<Validator>,
    /// Verifies back-channel logout tokens, which are a different `typ`.
    logout_tokens: Arc<Validator>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,ridm_auth=debug".into()),
        )
        .init();

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let config = Arc::new(Config::load(&http).await?);

    // An ID token is not an access token: it is addressed to this client, and
    // its `typ` is `JWT`. Saying both is what stops one being taken for the
    // other.
    let id_tokens = Validator::builder(&config.issuer)
        .audience(&config.client_id)
        .token_type(Some("JWT"))
        .allow_http(config.allow_http)
        .discover()
        .await?
        .shared();
    // The same keys, a different `typ` (OIDC Back-Channel Logout §2.4).
    let logout_tokens = Validator::builder(&config.issuer)
        .audience(&config.client_id)
        .token_type(Some("logout+jwt"))
        .allow_http(config.allow_http)
        .discover()
        .await?
        .shared();

    let bind = config.bind.clone();
    let state = AppState {
        config,
        http,
        store: Store::default(),
        id_tokens,
        logout_tokens,
    };

    let app = Router::new()
        .route("/", get(home))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/orders", post(place_order))
        .route("/logout", get(logout))
        .route("/backchannel-logout", post(backchannel_logout))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(
        "listening on http://{bind} — register {} as a redirect URI",
        state.config.redirect_uri()
    );
    axum::serve(listener, app).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// pages
// ---------------------------------------------------------------------------

async fn home(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some((id, mut current)) = current_session(&state, &headers) else {
        return Html(pages::signed_out(&state.config.issuer)).into_response();
    };
    let orders = match fetch_orders(&state, &id, &mut current).await {
        Ok(orders) => pages::orders_table(&orders),
        Err(e) => format!("<p class=\"notice error\">{e}</p>"),
    };
    Html(pages::signed_in(&current, &orders, None)).into_response()
}

/// Start a sign-in: remember the `state`, `nonce` and PKCE verifier, and send
/// the browser to rIDM.
async fn login(State(state): State<AppState>) -> Response {
    let csrf = random_token();
    let nonce = random_token();
    let verifier = oidc::code_verifier();
    state.store.start(
        csrf.clone(),
        Pending {
            nonce: nonce.clone(),
            code_verifier: verifier.clone(),
            started_at: Utc::now(),
            next: "/".into(),
        },
    );
    Redirect::to(&oidc::authorization_url(
        &state.config,
        &csrf,
        &nonce,
        &verifier,
    ))
    .into_response()
}

#[derive(Debug, Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// The user is back. Everything here is a refusal until proven otherwise.
async fn callback(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<Callback>,
) -> Response {
    if let Some(error) = params.error {
        let detail = params.error_description.unwrap_or_default();
        return fail(format!("rIDM refused the sign-in: {error} {detail}"));
    }
    let (Some(code), Some(returned_state)) = (params.code, params.state) else {
        return fail("the callback carried no code".into());
    };
    // `state` is what ties this callback to a sign-in this app started; without
    // the match, anyone could feed us a code of their own choosing.
    let Some(pending) = state.store.take(&returned_state) else {
        return fail("this sign-in is unknown or has expired — start again".into());
    };

    let tokens = match oidc::exchange_code(
        &state.http,
        &state.config,
        &code,
        &pending.code_verifier,
    )
    .await
    {
        Ok(tokens) => tokens,
        Err(e) => return fail(e),
    };
    let Some(id_token) = tokens.id_token.clone() else {
        return fail("the token response carried no ID token".into());
    };

    let claims = match state.id_tokens.validate(&id_token).await {
        Ok(claims) => claims,
        Err(e) => return fail(format!("the ID token is not acceptable: {e}")),
    };
    // The nonce ties the ID token to the request this app made (OIDC Core
    // §3.1.3.7). A token without it, or with someone else's, is not ours.
    if claims.claim("nonce").and_then(|n| n.as_str()) != Some(pending.nonce.as_str()) {
        return fail("the ID token does not answer this sign-in".into());
    }

    let expires_at = tokens.expires_at();
    let mut current = Session {
        subject: claims.sub.clone(),
        name: claim_str(&claims, "name"),
        email: claim_str(&claims, "email"),
        sid: claims.sid.clone(),
        id_token,
        access_token: tokens.access_token,
        access_token_expires_at: expires_at,
        refresh_token: tokens.refresh_token,
        permissions: Vec::new(),
    };
    // The API is the authority on what this user may do; the client asks it so
    // the page can hide a button it would only be refused for.
    current.permissions = whoami_permissions(&state, &current).await;

    let id = state.store.create(current);
    (
        [(header::SET_COOKIE, set_cookie(&state, &id))],
        Redirect::to(&pending.next),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct NewOrder {
    item: String,
    quantity: Option<u32>,
}

async fn place_order(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(new): Form<NewOrder>,
) -> Response {
    let Some((id, mut current)) = current_session(&state, &headers) else {
        return Redirect::to("/").into_response();
    };
    if let Err(e) = ensure_access_token(&state, &id, &mut current).await {
        return fail(e);
    }
    let sent = state
        .http
        .post(format!("{}/orders", state.config.api_url))
        .bearer_auth(&current.access_token)
        .json(&serde_json::json!({
            "item": new.item,
            "quantity": new.quantity.unwrap_or(1),
        }))
        .send()
        .await;

    let notice = match sent {
        Ok(response) if response.status().is_success() => "Order placed.".to_string(),
        // The API answers 403 `insufficient_scope` when the token does not
        // carry `orders:write`, which is the interesting case to show.
        Ok(response) => format!(
            "The orders API refused: {} {}",
            response.status(),
            response.text().await.unwrap_or_default()
        ),
        Err(e) => format!("The orders API could not be reached: {e}"),
    };
    let orders = match fetch_orders(&state, &id, &mut current).await {
        Ok(orders) => pages::orders_table(&orders),
        Err(e) => format!("<p class=\"notice error\">{e}</p>"),
    };
    Html(pages::signed_in(&current, &orders, Some(&notice))).into_response()
}

/// Sign out here, give the refresh token back, then ask rIDM to end the SSO
/// session too — otherwise the next `/login` signs the user straight back in.
async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(id) = cookie(&headers) else {
        return Redirect::to("/").into_response();
    };
    let Some(current) = state.store.remove(&id) else {
        return Redirect::to("/").into_response();
    };
    if let Some(refresh_token) = &current.refresh_token {
        oidc::revoke(&state.http, &state.config, refresh_token).await;
    }
    (
        [(header::SET_COOKIE, clear_cookie(&state))],
        Redirect::to(&oidc::end_session_url(&state.config, &current.id_token)),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct LogoutToken {
    logout_token: String,
}

/// rIDM calls this when the session ends somewhere else — another app's sign-
/// out, an administrator revoking the session, a password reset. There is no
/// browser involved, so the answer is a status code and nothing else.
async fn backchannel_logout(
    State(state): State<AppState>,
    Form(form): Form<LogoutToken>,
) -> Response {
    let claims = match state.logout_tokens.validate(&form.logout_token).await {
        Ok(claims) => claims,
        Err(e) => {
            tracing::warn!(error = %e, "refused a logout token");
            return (StatusCode::BAD_REQUEST, no_store(), "invalid_request").into_response();
        }
    };
    // A logout token must carry the logout event and must not carry a nonce —
    // that is what separates it from an ID token (Back-Channel Logout §2.4).
    let is_logout = claims
        .claim("events")
        .and_then(|e| e.as_object())
        .is_some_and(|e| e.contains_key("http://schemas.openid.net/event/backchannel-logout"));
    if !is_logout || claims.claim("nonce").is_some() {
        tracing::warn!("refused a token that is not a logout token");
        return (StatusCode::BAD_REQUEST, no_store(), "invalid_request").into_response();
    }

    let ended = match claims.sid.as_deref() {
        Some(sid) => state.store.remove_by_sid(sid),
        None => state.store.remove_by_subject(&claims.sub),
    };
    tracing::info!(ended, sid = ?claims.sid, "back-channel logout");
    (StatusCode::OK, no_store()).into_response()
}

// ---------------------------------------------------------------------------
// the session cookie, and keeping the access token alive
// ---------------------------------------------------------------------------

fn current_session(state: &AppState, headers: &HeaderMap) -> Option<(String, Session)> {
    let id = cookie(headers)?;
    let session = state.store.get(&id)?;
    Some((id, session))
}

/// Refresh the access token if it has run out, and keep what came back.
async fn ensure_access_token(
    state: &AppState,
    id: &str,
    current: &mut Session,
) -> Result<(), String> {
    if current.access_token_is_usable() {
        return Ok(());
    }
    let Some(refresh_token) = current.refresh_token.clone() else {
        return Err("this session has expired — sign in again".into());
    };
    let tokens = oidc::refresh(&state.http, &state.config, &refresh_token).await?;
    current.access_token_expires_at = tokens.expires_at();
    current.access_token = tokens.access_token;
    // rIDM rotates refresh tokens: the new one replaces the old, and offering
    // the old one again would end the family.
    if let Some(rotated) = tokens.refresh_token {
        current.refresh_token = Some(rotated);
    }
    state.store.put(id, current.clone());
    Ok(())
}

async fn fetch_orders(
    state: &AppState,
    id: &str,
    current: &mut Session,
) -> Result<Vec<serde_json::Value>, String> {
    ensure_access_token(state, id, current).await?;
    let response = state
        .http
        .get(format!("{}/orders", state.config.api_url))
        .bearer_auth(&current.access_token)
        .send()
        .await
        .map_err(|e| format!("the orders API could not be reached: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "the orders API answered {}: {}",
            response.status(),
            response.text().await.unwrap_or_default()
        ));
    }
    response
        .json()
        .await
        .map_err(|e| format!("the orders API answered something unexpected: {e}"))
}

/// Ask the API what this token may do. A refusal is an answer too — it means
/// the user may not read orders, which the page then says.
async fn whoami_permissions(state: &AppState, current: &Session) -> Vec<String> {
    let response = state
        .http
        .get(format!("{}/whoami", state.config.api_url))
        .bearer_auth(&current.access_token)
        .send()
        .await;
    let Ok(response) = response else {
        return Vec::new();
    };
    if !response.status().is_success() {
        return Vec::new();
    }
    response
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|body| {
            Some(
                body.get("permissions")?
                    .as_array()?
                    .iter()
                    .filter_map(|p| p.as_str().map(str::to_string))
                    .collect(),
            )
        })
        .unwrap_or_default()
}

fn cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE)
        .map(|(_, value)| value.to_string())
}

/// `HttpOnly` so no script can read it, `SameSite=Lax` so it still rides the
/// redirect back from rIDM, and `Secure` as soon as this app is on https.
fn set_cookie(state: &AppState, id: &str) -> String {
    let secure = if state.config.base_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    format!("{COOKIE}={id}; Path=/; HttpOnly; SameSite=Lax{secure}")
}

fn clear_cookie(state: &AppState) -> String {
    format!("{}; Max-Age=0", set_cookie(state, ""))
}

fn no_store() -> [(header::HeaderName, &'static str); 1] {
    [(header::CACHE_CONTROL, "no-store")]
}

fn claim_str(claims: &ridm_auth::Claims, name: &str) -> Option<String> {
    claims.claim(name)?.as_str().map(str::to_string)
}

fn fail(message: String) -> Response {
    tracing::warn!(%message, "sign-in failed");
    (StatusCode::BAD_REQUEST, Html(pages::error(&message))).into_response()
}
