//! Signing in through an upstream provider ("brokering").
//!
//! `start` sends the browser to the provider's authorization endpoint with a
//! fresh `state` (whose record in Redis remembers the login flow, or the
//! signed-in user an identity is being linked to), a `nonce` and a PKCE
//! verifier. `callback` redeems the code at the token endpoint, proves the
//! identity (the ID token's signature against the provider's JWK set, its
//! issuer, audience, expiry and nonce; or the userinfo document for plain
//! OAuth 2.0), maps the claims and resolves the local user by the
//! provider's link policy. A first sign-in creates the account or links an
//! existing one; the login flow then continues like any other first factor
//! (second step, profile completion, terms, consent).

use axum::http::HeaderMap;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use redis::AsyncCommands as _;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::middleware::TenantCtx;
use crate::models::{
    IdentityProvider, IdpAuthMethod, IdpKind, LinkPolicy, LinkedIdentity, NewUser, User,
    UserStatus, UserUpdate,
};
use crate::repos;
use crate::services::flows::{self, AuthStep, RequestContext};
use crate::services::login_flows::{self, FlowStage, LoginFlow};
use crate::services::{identity_providers, users};
use crate::state::AppState;

/// How long the browser has to come back from the provider.
const STATE_TTL_SECS: u64 = 10 * 60;
/// How long a link ticket handed to the account console stays valid.
const LINK_TICKET_TTL_SECS: u64 = 5 * 60;
/// The `amr` value a brokered sign-in records.
pub const AMR_FEDERATED: &str = "fed";

fn hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::fill(&mut buf[..]);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Why a sign-in through a provider stopped; the login page shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerError {
    /// The user cancelled at the provider or it refused.
    Denied,
    /// The provider answered with an error or something unverifiable.
    Upstream,
    /// The `state` is unknown, used or expired.
    InvalidState,
    /// A local account holds the email; sign in there and link.
    EmailInUse,
    /// The identity is linked to another account (link mode).
    AlreadyLinked,
    /// The local account is disabled or locked.
    AccountDisabled,
}

impl BrokerError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Upstream => "upstream",
            Self::InvalidState => "invalid_state",
            Self::EmailInUse => "email_in_use",
            Self::AlreadyLinked => "already_linked",
            Self::AccountDisabled => "account_disabled",
        }
    }
}

/// What the callback continues.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Mode {
    /// A login flow at its first step.
    Flow { flow_id: Uuid },
    /// Linking to the signed-in user of the account console.
    Link {
        user_id: Uuid,
        return_to: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct StateRecord {
    idp_id: Uuid,
    mode: Mode,
    nonce: String,
    verifier: Option<String>,
    /// The hash of the browser's binding cookie (see [`binding_cookie`]).
    browser: String,
}

// ---------------------------------------------------------------------------
// Browser binding
// ---------------------------------------------------------------------------

/// How long a binding cookie lives: the provider's round trip, and the
/// SAML parking step after it.
pub const BINDING_TTL_SECS: i64 = 15 * 60;

fn binding_cookie_name(state: &AppState, slug: &str) -> String {
    crate::services::sessions::tenant_cookie_name(state.config.cookie_secure, "ridm_broker", slug)
}

/// The cookie that binds a brokered sign-in to the browser that started it.
/// The step that signs the browser in (the callback, or SAML's same-site
/// continue) must present it, so a callback URL or continue link someone
/// else obtained signs nobody in (login CSRF). `SameSite=Lax`: a
/// provider's cross-site POST does not carry it, so a posted answer is
/// parked and continued by a same-site GET that does.
pub fn binding_cookie(
    state: &AppState,
    tenant: &crate::models::Tenant,
    value: &str,
    max_age: i64,
) -> String {
    crate::services::sessions::cookie_header(
        state.config.cookie_secure,
        &binding_cookie_name(state, &tenant.slug),
        value,
        max_age,
    )
}

/// The binding cookie a request carries.
pub fn browser_binding(
    state: &AppState,
    tenant: &crate::models::Tenant,
    headers: &HeaderMap,
) -> Option<String> {
    let name = binding_cookie_name(state, &tenant.slug);
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|line| line.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim().to_string())
        .filter(|v| !v.is_empty() && v.len() <= 128)
}

/// Whether `presented` (the request's binding cookie) is the one `hashed`
/// was made from.
pub fn binding_matches(presented: Option<&str>, hashed: &str) -> bool {
    presented.is_some_and(|p| hash(p) == hashed)
}

/// A fresh binding value and its hash, to store with the sign-in.
pub fn new_binding() -> (String, String) {
    let v = random_token(32);
    let h = hash(&v);
    (v, h)
}

/// The callback URL the provider must know: `{issuer}/broker/{alias}/callback`.
pub fn callback_url(state: &AppState, tenant: &TenantCtx, alias: &str) -> String {
    format!("{}/broker/{alias}/callback", tenant.issuer(state))
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

/// Build the authorization request and remember the state. Returns the URL
/// to send the browser to and the value of the binding cookie to set.
pub async fn start(
    state: &AppState,
    tenant: &TenantCtx,
    idp: &IdentityProvider,
    mode: Mode,
) -> AppResult<(String, String)> {
    if !idp.enabled {
        return Err(AppError::NotFound("identity provider"));
    }
    let Some(authorization_endpoint) = &idp.authorization_endpoint else {
        return Err(AppError::BadRequest(
            "the provider has no authorization endpoint".into(),
        ));
    };
    if let Mode::Flow { flow_id } = &mode {
        let flow = flows::load(state, tenant.id(), *flow_id).await?;
        if !matches!(flow.stage, FlowStage::Authenticate | FlowStage::Register) {
            return Err(AppError::BadRequest(
                "flow does not accept a sign-in at this step".into(),
            ));
        }
    }
    let token = random_token(32);
    let nonce = random_token(32);
    let verifier = idp.pkce.then(|| random_token(48));
    let (browser, browser_hash) = new_binding();
    let rec = StateRecord {
        idp_id: idp.id,
        mode,
        nonce: nonce.clone(),
        verifier: verifier.clone(),
        browser: browser_hash,
    };
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(
            keys::broker_state(tenant.id(), &hash(&token)),
            serde_json::to_string(&rec)?,
            STATE_TTL_SECS,
        )
        .await?;
    let mut url = url::Url::parse(authorization_endpoint)
        .map_err(|_| AppError::Internal("invalid authorization endpoint".into()))?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", &idp.client_id)
            .append_pair("redirect_uri", &callback_url(state, tenant, &idp.alias))
            .append_pair("scope", &idp.scopes.join(" "))
            .append_pair("state", &token);
        if idp.kind == IdpKind::Oidc {
            q.append_pair("nonce", &nonce);
        }
        if let Some(v) = &verifier {
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()));
            q.append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256");
        }
        if idp.preset.as_deref() == Some("apple") {
            // Apple posts the response when it carries the name or email.
            q.append_pair("response_mode", "form_post");
        }
    }
    Ok((url.to_string(), browser))
}

// ---------------------------------------------------------------------------
// Link tickets (account console)
// ---------------------------------------------------------------------------

/// A one-time ticket the signed-in user's browser presents to
/// `/broker/{alias}/start?ticket=`, so linking never depends on the SSO
/// cookie or its age: the account API checked the recent sign-in already.
pub async fn create_link_ticket(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    idp_id: Uuid,
    return_to: Option<String>,
) -> AppResult<String> {
    let ticket = random_token(32);
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(
            keys::broker_link_ticket(tenant_id, &hash(&ticket)),
            serde_json::to_string(&(user_id, idp_id, return_to))?,
            LINK_TICKET_TTL_SECS,
        )
        .await?;
    Ok(ticket)
}

/// Redeem a link ticket for the provider it was issued for.
pub async fn redeem_link_ticket(
    state: &AppState,
    tenant_id: Uuid,
    idp_id: Uuid,
    ticket: &str,
) -> AppResult<Mode> {
    if ticket.is_empty() || ticket.len() > 128 {
        return Err(AppError::NotFound("link ticket"));
    }
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = redis::cmd("GETDEL")
        .arg(keys::broker_link_ticket(tenant_id, &hash(ticket)))
        .query_async(&mut conn)
        .await?;
    let (user_id, for_idp, return_to): (Uuid, Uuid, Option<String>) = raw
        .and_then(|r| serde_json::from_str(&r).ok())
        .ok_or(AppError::NotFound("link ticket"))?;
    if for_idp != idp_id {
        return Err(AppError::NotFound("link ticket"));
    }
    Ok(Mode::Link { user_id, return_to })
}

// ---------------------------------------------------------------------------
// Callback
// ---------------------------------------------------------------------------

/// The parameters a provider sends back (query for `GET`, form for `POST`).
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    /// Apple sends the name once, as JSON, next to the code.
    pub user: Option<String>,
}

/// What upstream said about the person.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub username: Option<String>,
    /// Every claim seen (ID token and userinfo), for the mappers.
    pub claims: Map<String, Value>,
}

/// Where the browser goes next.
pub enum Outcome {
    /// Signed in: set the session cookie and send the browser to the page
    /// for the flow's stage.
    Authenticated {
        session: Box<crate::services::sessions::SsoSession>,
        flow: Box<LoginFlow>,
    },
    /// Linked from the account console: back to it.
    Linked { return_to: Option<String> },
    /// The risk policy refused the sign-in: straight back to the client
    /// with `access_denied`; there is no flow left to tell.
    Blocked { redirect_to: String },
    /// Stopped: the page to tell it on (`Some(flow)` for the login page,
    /// `None` when linking) and why.
    Failed {
        flow_id: Option<Uuid>,
        return_to: Option<String>,
        error: BrokerError,
    },
}

fn parked_key(tenant_id: Uuid, id: Uuid) -> String {
    format!("{}:t:{tenant_id}:broker:posted:{id}", keys::PREFIX)
}

/// Keep a provider's posted answer (`response_mode=form_post`) for the
/// same-site GET that continues it, which carries the binding and session
/// cookies the cross-site POST did not. Returns its one-time id.
pub async fn park_callback(
    state: &AppState,
    tenant_id: Uuid,
    params: &CallbackParams,
) -> AppResult<Uuid> {
    let id = Uuid::new_v4();
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(
            parked_key(tenant_id, id),
            serde_json::to_string(params)?,
            STATE_TTL_SECS,
        )
        .await?;
    Ok(id)
}

/// Take a parked answer (once).
pub async fn unpark_callback(
    state: &AppState,
    tenant_id: Uuid,
    id: Uuid,
) -> AppResult<Option<CallbackParams>> {
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = redis::cmd("GETDEL")
        .arg(parked_key(tenant_id, id))
        .query_async(&mut conn)
        .await?;
    Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
}

/// Take the state record for `state` (once).
async fn take_state(
    state: &AppState,
    tenant_id: Uuid,
    token: &str,
) -> AppResult<Option<StateRecord>> {
    if token.is_empty() || token.len() > 128 {
        return Ok(None);
    }
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = redis::cmd("GETDEL")
        .arg(keys::broker_state(tenant_id, &hash(token)))
        .query_async(&mut conn)
        .await?;
    Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
}

pub async fn callback(
    state: &AppState,
    tenant: &TenantCtx,
    idp: &IdentityProvider,
    params: CallbackParams,
    browser: Option<&str>,
    ctx: RequestContext,
) -> AppResult<Outcome> {
    let Some(rec) = take_state(
        state,
        tenant.id(),
        params.state.as_deref().unwrap_or_default(),
    )
    .await?
    else {
        // Nothing to go back to: the request is answered as an error.
        return Ok(Outcome::Failed {
            flow_id: None,
            return_to: None,
            error: BrokerError::InvalidState,
        });
    };
    let (flow_id, return_to) = match &rec.mode {
        Mode::Flow { flow_id } => (Some(*flow_id), None),
        Mode::Link { return_to, .. } => (None, return_to.clone()),
    };
    let failed = |error: BrokerError| Outcome::Failed {
        flow_id,
        return_to: return_to.clone(),
        error,
    };
    if rec.idp_id != idp.id || !idp.enabled {
        return Ok(failed(BrokerError::InvalidState));
    }
    if !binding_matches(browser, &rec.browser) {
        tracing::warn!(provider = %idp.alias, "a brokered sign-in was completed by another browser than the one that started it");
        return Ok(failed(BrokerError::InvalidState));
    }
    if let Some(err) = &params.error {
        tracing::info!(provider = %idp.alias, error = %err, description = params.error_description.as_deref().unwrap_or(""), "upstream sign-in refused");
        return Ok(failed(if err == "access_denied" {
            BrokerError::Denied
        } else {
            BrokerError::Upstream
        }));
    }
    let Some(code) = params.code.as_deref().filter(|c| !c.is_empty()) else {
        return Ok(failed(BrokerError::Upstream));
    };
    let identity = match prove(state, tenant, idp, code, &rec, params.user.as_deref()).await {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(provider = %idp.alias, error = %e, "upstream identity could not be established");
            return Ok(failed(BrokerError::Upstream));
        }
    };
    conclude(state, tenant, idp, rec.mode, identity, ctx).await
}

/// Finish what `mode` started with a proven upstream identity: sign in to
/// the login flow (resolving or creating the local user by the provider's
/// link policy) or link it to the account-console user. Shared by every
/// provider kind; SAML reaches it from its assertion consumer service.
pub async fn conclude(
    state: &AppState,
    tenant: &TenantCtx,
    idp: &IdentityProvider,
    mode: Mode,
    identity: Identity,
    ctx: RequestContext,
) -> AppResult<Outcome> {
    let (flow_id, return_to) = match &mode {
        Mode::Flow { flow_id } => (Some(*flow_id), None),
        Mode::Link { return_to, .. } => (None, return_to.clone()),
    };
    let failed = |error: BrokerError| Outcome::Failed {
        flow_id,
        return_to: return_to.clone(),
        error,
    };
    match mode {
        Mode::Flow { flow_id } => {
            let flow = flows::load(state, tenant.id(), flow_id).await?;
            if !matches!(flow.stage, FlowStage::Authenticate | FlowStage::Register) {
                return Ok(failed(BrokerError::InvalidState));
            }
            let user = match resolve_user(state, &tenant.tenant, idp, &identity).await? {
                Ok(u) => u,
                Err(e) => return Ok(failed(e)),
            };
            apply_mappers(state, tenant.id(), idp, &user, &identity).await?;
            let step = flows::complete_authentication(
                state,
                tenant,
                flow,
                &user,
                vec![AMR_FEDERATED.into()],
                ctx,
                false,
            )
            .await?;
            state.events.publish(Event::new(
                Some(tenant.id()),
                Actor::User { id: user.id },
                EventKind::BrokeredLogin {
                    user_id: user.id,
                    idp_id: idp.id,
                    provider: idp.alias.clone(),
                },
            ));
            match step {
                AuthStep::Authenticated { session, flow } => {
                    Ok(Outcome::Authenticated { session, flow })
                }
                AuthStep::Blocked { redirect_to } => Ok(Outcome::Blocked { redirect_to }),
                AuthStep::Rejected { .. } => Ok(failed(BrokerError::AccountDisabled)),
            }
        }
        Mode::Link { user_id, return_to } => {
            let user = users::get(state, tenant.id(), user_id).await?;
            match link(state, &tenant.tenant, idp, &user, &identity).await? {
                Ok(()) => Ok(Outcome::Linked { return_to }),
                Err(e) => Ok(Outcome::Failed {
                    flow_id: None,
                    return_to,
                    error: e,
                }),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Proving the identity
// ---------------------------------------------------------------------------

/// Exchange the code and establish who signed in.
async fn prove(
    state: &AppState,
    tenant: &TenantCtx,
    idp: &IdentityProvider,
    code: &str,
    rec: &StateRecord,
    apple_user: Option<&str>,
) -> AppResult<Identity> {
    let Some(token_endpoint) = &idp.token_endpoint else {
        return Err(AppError::BadRequest(
            "the provider has no token endpoint".into(),
        ));
    };
    let redirect_uri = callback_url(state, tenant, &idp.alias);
    let secret = identity_providers::client_secret(state, idp).await?;
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &redirect_uri),
        ("client_id", &idp.client_id),
    ];
    if let Some(v) = &rec.verifier {
        form.push(("code_verifier", v));
    }
    let mut basic = None;
    match (
        idp.token_endpoint_auth_method,
        secret.as_ref().map(|s| s.as_str()),
    ) {
        (IdpAuthMethod::ClientSecretBasic, Some(s)) => basic = Some((idp.client_id.as_str(), s)),
        (IdpAuthMethod::ClientSecretPost, Some(s)) => form.push(("client_secret", s)),
        _ => {}
    }
    let tokens =
        identity_providers::post_form("token endpoint", token_endpoint, &form, basic).await?;
    let access_token = tokens["access_token"].as_str().map(str::to_string);
    let mut claims = Map::new();
    if let Some(u) = apple_user
        && let Ok(Value::Object(m)) = serde_json::from_str::<Value>(u)
    {
        claims.insert("user".into(), Value::Object(m));
    }
    let mut verified_subject: Option<String> = None;
    if idp.kind == IdpKind::Oidc {
        let Some(id_token) = tokens["id_token"].as_str() else {
            return Err(AppError::Unavailable(
                "the token endpoint returned no id_token".into(),
            ));
        };
        let id_claims = verify_id_token(state, idp, id_token, &rec.nonce).await?;
        verified_subject = id_claims
            .get("sub")
            .and_then(Value::as_str)
            .map(str::to_string);
        for (k, v) in id_claims {
            claims.insert(k, v);
        }
    }
    // Userinfo fills in what the ID token left out; the ID token's `sub` wins.
    if let (Some(endpoint), Some(at)) = (&idp.userinfo_endpoint, &access_token) {
        let need_userinfo = idp.kind == IdpKind::Oauth2
            || claim(&claims, idp.mappers.0.email.as_deref().unwrap_or("email")).is_none();
        if need_userinfo {
            let info = identity_providers::get_json("userinfo", endpoint, Some(at)).await?;
            if let Value::Object(m) = info {
                for (k, v) in m {
                    if verified_subject.is_some() && k == "sub" {
                        continue;
                    }
                    claims.entry(k).or_insert(v);
                }
            }
            if idp.preset.as_deref() == Some("github")
                && claim(&claims, "email").and_then(Value::as_str).is_none()
            {
                github_primary_email(endpoint, at, &mut claims).await;
            }
        }
    }
    identity_from_claims(idp, claims, verified_subject)
        .ok_or_else(|| AppError::Unavailable("no usable subject claim".into()))
}

/// Read the identity out of upstream claims by the provider's mappers:
/// `verified_subject` (what the provider's signature vouches for) wins over
/// the subject mapper. `None` when there is no usable subject.
pub fn identity_from_claims(
    idp: &IdentityProvider,
    claims: Map<String, Value>,
    verified_subject: Option<String>,
) -> Option<Identity> {
    let m = &idp.mappers.0;
    let subject = match verified_subject {
        Some(s) => s,
        None => claim(&claims, m.subject.as_deref().unwrap_or("sub")).and_then(scalar_text)?,
    };
    if subject.is_empty() || subject.len() > 512 {
        return None;
    }
    let email = claim(&claims, m.email.as_deref().unwrap_or("email"))
        .and_then(Value::as_str)
        .and_then(|e| users::normalize_email(e).ok());
    let email_verified = claim(
        &claims,
        m.email_verified.as_deref().unwrap_or("email_verified"),
    )
    .map(|v| v.as_bool() == Some(true) || v.as_str() == Some("true"))
    .unwrap_or(false);
    let username = claim(
        &claims,
        m.username.as_deref().unwrap_or("preferred_username"),
    )
    .and_then(scalar_text)
    .filter(|u| !u.trim().is_empty());
    Some(Identity {
        subject,
        email,
        email_verified,
        username,
        claims,
    })
}

/// GitHub keeps addresses behind `/user/emails`; take the primary verified one.
async fn github_primary_email(
    userinfo_endpoint: &str,
    access_token: &str,
    claims: &mut Map<String, Value>,
) {
    let url = format!("{}/emails", userinfo_endpoint.trim_end_matches('/'));
    match identity_providers::get_json("userinfo emails", &url, Some(access_token)).await {
        Ok(Value::Array(list)) => {
            let pick = list
                .iter()
                .find(|e| e["primary"] == true && e["verified"] == true)
                .or_else(|| list.iter().find(|e| e["verified"] == true));
            if let Some(e) = pick
                && let Some(addr) = e["email"].as_str()
            {
                claims.insert("email".into(), Value::String(addr.to_string()));
                claims.insert("email_verified".into(), Value::Bool(true));
            }
        }
        Ok(_) => {}
        Err(e) => tracing::debug!(error = %e, "GitHub emails lookup failed"),
    }
}

/// A claim by name; a dot descends into an object (`user.name.firstName`).
pub fn claim<'a>(claims: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let mut cur = claims.get(parts.next()?)?;
    for p in parts {
        cur = cur.get(p)?;
    }
    Some(cur)
}

fn scalar_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Signature against the provider's JWK set (re-fetched once for an unknown
/// `kid`), then issuer, audience, expiry and nonce.
async fn verify_id_token(
    state: &AppState,
    idp: &IdentityProvider,
    token: &str,
    nonce: &str,
) -> AppResult<Map<String, Value>> {
    let header = jsonwebtoken::decode_header(token)
        .map_err(|e| AppError::Unavailable(format!("id_token header: {e}")))?;
    if matches!(
        header.alg,
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
    ) {
        return Err(AppError::Unavailable(
            "id_token uses a symmetric algorithm".into(),
        ));
    }
    let find = |set: &[Value]| -> Option<Value> {
        match &header.kid {
            Some(kid) => set.iter().find(|j| j["kid"].as_str() == Some(kid)).cloned(),
            None if set.len() == 1 => set.first().cloned(),
            None => None,
        }
    };
    let mut jwk = find(&identity_providers::jwks(state, idp, false).await?);
    if jwk.is_none() {
        jwk = find(&identity_providers::jwks(state, idp, true).await?);
    }
    let jwk =
        jwk.ok_or_else(|| AppError::Unavailable("id_token signed with an unknown key".into()))?;
    let parsed: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk)
        .map_err(|e| AppError::Unavailable(format!("provider jwk: {e}")))?;
    let decoding = DecodingKey::from_jwk(&parsed)
        .map_err(|e| AppError::Unavailable(format!("provider jwk: {e}")))?;
    let mut validation = Validation::new(header.alg);
    validation.leeway = 60;
    validation.validate_nbf = true;
    validation.set_audience(&[&idp.client_id]);
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);
    // The issuer is checked by hand: Microsoft's `common` stands for many.
    validation.iss = None;
    let data = jsonwebtoken::decode::<Map<String, Value>>(token, &decoding, &validation)
        .map_err(|e| AppError::Unavailable(format!("id_token: {e}")))?;
    let claims = data.claims;
    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let configured = idp.issuer.as_deref().unwrap_or_default();
    if !identity_providers::issuer_matches(configured, iss) {
        return Err(AppError::Unavailable(format!(
            "id_token issuer `{iss}` is not the provider's"
        )));
    }
    if claims.get("nonce").and_then(Value::as_str) != Some(nonce) {
        return Err(AppError::Unavailable("id_token nonce mismatch".into()));
    }
    if let Some(aud) = claims.get("aud").and_then(Value::as_array)
        && aud.len() > 1
        && claims.get("azp").and_then(Value::as_str) != Some(idp.client_id.as_str())
    {
        return Err(AppError::Unavailable("id_token azp mismatch".into()));
    }
    Ok(claims)
}

// ---------------------------------------------------------------------------
// Resolving and linking users
// ---------------------------------------------------------------------------

/// The local user for an upstream identity: the one linked to it, else by
/// the provider's link policy an existing account with the same verified
/// email, or a new account.
pub(crate) async fn resolve_user(
    state: &AppState,
    tenant: &crate::models::Tenant,
    idp: &IdentityProvider,
    identity: &Identity,
) -> AppResult<Result<User, BrokerError>> {
    let tid = tenant.id;
    let mut tx = db::tenant_tx(&state.db, tid).await?;
    let existing =
        repos::federated_identities::find(&mut *tx, tid, idp.id, &identity.subject).await?;
    if let Some(link) = existing {
        let user = repos::users::find_by_id(&mut *tx, tid, link.user_id)
            .await?
            .filter(|u| u.deleted_at.is_none());
        match user {
            Some(u) if u.status == UserStatus::Active && !u.is_locked_now() => {
                repos::federated_identities::touch(
                    &mut *tx,
                    tid,
                    idp.id,
                    &identity.subject,
                    identity.email.as_deref(),
                    identity.username.as_deref(),
                )
                .await?;
                tx.commit().await?;
                return Ok(Ok(u));
            }
            Some(_) => {
                tx.commit().await?;
                return Ok(Err(BrokerError::AccountDisabled));
            }
            None => {
                // The user is gone; the link goes with them (cascade should
                // have done it) and a fresh account follows.
                repos::federated_identities::delete(&mut *tx, tid, link.user_id, idp.id).await?;
            }
        }
    }
    let upstream_verified = identity.email_verified || idp.trust_email;
    let candidate = match &identity.email {
        Some(e) => repos::users::find_by_email(&mut *tx, tid, e).await?,
        None => None,
    };
    tx.commit().await?;
    let user = match (idp.link_policy, candidate) {
        (LinkPolicy::VerifiedEmail, Some(u)) => {
            if !(upstream_verified && u.email_verified) {
                return Ok(Err(BrokerError::EmailInUse));
            }
            if u.status != UserStatus::Active || u.is_locked_now() {
                return Ok(Err(BrokerError::AccountDisabled));
            }
            u
        }
        (LinkPolicy::Explicit, Some(_)) => return Ok(Err(BrokerError::EmailInUse)),
        (LinkPolicy::AlwaysNew, Some(_)) => {
            create_user(state, tenant, idp, identity, false, upstream_verified).await?
        }
        (_, None) => create_user(state, tenant, idp, identity, true, upstream_verified).await?,
    };
    let mut tx = db::tenant_tx(&state.db, tid).await?;
    repos::federated_identities::insert(
        &mut *tx,
        tid,
        repos::federated_identities::NewLink {
            user_id: user.id,
            idp_id: idp.id,
            external_subject: &identity.subject,
            external_email: identity.email.as_deref(),
            external_username: identity.username.as_deref(),
            last_login_at: Some(Utc::now()),
        },
    )
    .await?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tid),
        Actor::User { id: user.id },
        EventKind::IdentityLinked {
            user_id: user.id,
            idp_id: idp.id,
            external_subject: identity.subject.clone(),
        },
    ));
    Ok(Ok(user))
}

/// A username for a new account: the mapped username, else the email,
/// else `{alias}-{subject}`; a taken name gets a random suffix.
fn username_candidates(
    idp: &IdentityProvider,
    identity: &Identity,
    with_email: bool,
) -> Vec<String> {
    let mut out = vec![];
    if let Some(u) = &identity.username
        && let Ok(n) = users::normalize_username(u)
    {
        out.push(n);
    }
    if with_email && let Some(e) = &identity.email {
        out.push(e.clone());
    }
    let sub: String = identity
        .subject
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(24)
        .collect::<String>()
        .to_lowercase();
    out.push(format!(
        "{}-{}",
        idp.alias,
        if sub.is_empty() { "user".into() } else { sub }
    ));
    out
}

async fn create_user(
    state: &AppState,
    tenant: &crate::models::Tenant,
    idp: &IdentityProvider,
    identity: &Identity,
    with_email: bool,
    email_verified: bool,
) -> AppResult<User> {
    let locale = identity
        .claims
        .get("locale")
        .and_then(Value::as_str)
        .map(|l| {
            crate::services::locale::negotiate(&[l.to_string()], None, &tenant.settings.locale)
        });
    let mut attributes = Map::new();
    for (attr, claim_name) in &idp.mappers.0.attributes {
        if let Some(v) = claim(&identity.claims, claim_name) {
            attributes.insert(attr.clone(), v.clone());
        }
    }
    let mut candidates = username_candidates(idp, identity, with_email);
    let last = candidates.pop().unwrap_or_default();
    let mut attempt = 0;
    loop {
        let username = match candidates.get(attempt) {
            Some(u) => u.clone(),
            None => format!("{last}-{}", &random_token(6).to_lowercase()[..6]),
        };
        let result = users::create(
            state,
            tenant.id,
            Actor::System,
            NewUser {
                username,
                email: if with_email {
                    identity.email.clone()
                } else {
                    None
                },
                email_verified: with_email && email_verified,
                status: Some(UserStatus::Active),
                attributes: Some(Value::Object(attributes.clone())),
                locale: locale.clone(),
                defer_required: true,
                ..Default::default()
            },
        )
        .await;
        match result {
            Ok(u) => return Ok(u),
            Err(AppError::Conflict(_)) if attempt < candidates.len() + 3 => attempt += 1,
            Err(AppError::Validation(errors))
                if !attributes.is_empty()
                    && errors.iter().all(|e| e.field.starts_with("attributes.")) =>
            {
                // A mapped claim the schema refuses must not block the sign-in;
                // the profile step asks for what is required.
                tracing::info!(provider = %idp.alias, ?errors, "mapped attributes refused; creating without them");
                attributes.clear();
            }
            Err(e) => return Err(e),
        }
    }
}

/// Write the mapped attributes on every sign-in (imports and mappers may
/// set any attribute); a refusal is logged, never fatal.
pub(crate) async fn apply_mappers(
    state: &AppState,
    tenant_id: Uuid,
    idp: &IdentityProvider,
    user: &User,
    identity: &Identity,
) -> AppResult<()> {
    if idp.mappers.0.attributes.is_empty() {
        return Ok(());
    }
    let mut merged = user.attributes.as_object().cloned().unwrap_or_default();
    let mut changed = false;
    for (attr, claim_name) in &idp.mappers.0.attributes {
        if let Some(v) = claim(&identity.claims, claim_name)
            && merged.get(attr) != Some(v)
        {
            merged.insert(attr.clone(), v.clone());
            changed = true;
        }
    }
    if !changed {
        return Ok(());
    }
    match users::update(
        state,
        tenant_id,
        Actor::System,
        user.id,
        UserUpdate {
            attributes: Some(Value::Object(merged)),
            ..Default::default()
        },
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(AppError::Validation(errors)) => {
            tracing::info!(provider = %idp.alias, user = %user.id, ?errors, "mapped attributes refused");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Link an upstream identity to a signed-in user (account console).
async fn link(
    state: &AppState,
    tenant: &crate::models::Tenant,
    idp: &IdentityProvider,
    user: &User,
    identity: &Identity,
) -> AppResult<Result<(), BrokerError>> {
    let tid = tenant.id;
    let mut tx = db::tenant_tx(&state.db, tid).await?;
    if let Some(existing) =
        repos::federated_identities::find(&mut *tx, tid, idp.id, &identity.subject).await?
    {
        tx.commit().await?;
        return Ok(if existing.user_id == user.id {
            Ok(())
        } else {
            Err(BrokerError::AlreadyLinked)
        });
    }
    if repos::federated_identities::find_for_user(&mut *tx, tid, user.id, idp.id)
        .await?
        .is_some()
    {
        // One identity per provider: the new one replaces it.
        repos::federated_identities::delete(&mut *tx, tid, user.id, idp.id).await?;
    }
    repos::federated_identities::insert(
        &mut *tx,
        tid,
        repos::federated_identities::NewLink {
            user_id: user.id,
            idp_id: idp.id,
            external_subject: &identity.subject,
            external_email: identity.email.as_deref(),
            external_username: identity.username.as_deref(),
            last_login_at: None,
        },
    )
    .await?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tid),
        Actor::User { id: user.id },
        EventKind::IdentityLinked {
            user_id: user.id,
            idp_id: idp.id,
            external_subject: identity.subject.clone(),
        },
    ));
    Ok(Ok(()))
}

/// A user's linked identities with their providers.
pub async fn identities_of(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<LinkedIdentity>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::federated_identities::list_for_user(&mut *tx, tenant_id, user_id).await?;
    tx.commit().await?;
    Ok(rows)
}

/// Remove the link to a provider. Returns whether there was one.
pub async fn unlink(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    user_id: Uuid,
    idp_id: Uuid,
) -> AppResult<bool> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::federated_identities::delete(&mut *tx, tenant_id, user_id, idp_id).await?;
    tx.commit().await?;
    if ok {
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::IdentityUnlinked { user_id, idp_id },
        ));
    }
    Ok(ok)
}

/// The UI page that hosts a flow's stage after a brokered sign-in.
pub fn page_for(stage: FlowStage) -> &'static str {
    match stage {
        FlowStage::Mfa => "mfa",
        FlowStage::Consent => "consent",
        FlowStage::Register | FlowStage::VerifyEmail => "register",
        _ => "login",
    }
}

/// Continue a flow whose state the callback changed: persisted by
/// `complete_authentication` already; exposed for callers that need the
/// stored copy.
pub async fn flow_after(
    state: &AppState,
    tenant_id: Uuid,
    flow_id: Uuid,
) -> AppResult<Option<LoginFlow>> {
    login_flows::get(state, tenant_id, flow_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_are_read_by_dotted_path() {
        let claims: Map<String, Value> =
            serde_json::from_str(r#"{"sub":"1","user":{"name":{"firstName":"Al"}},"id":42}"#)
                .unwrap();
        assert_eq!(claim(&claims, "sub").unwrap(), "1");
        assert_eq!(claim(&claims, "user.name.firstName").unwrap(), "Al");
        assert!(claim(&claims, "user.nope").is_none());
        assert_eq!(scalar_text(claim(&claims, "id").unwrap()).unwrap(), "42");
    }
}
