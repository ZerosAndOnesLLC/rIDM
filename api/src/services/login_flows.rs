//! Login flows: the state carried from `/authorize` through the static UI
//! (login, consent, MFA, ...) and back to the client's redirect URI.
//!
//! Phase 3.3 creates flows and finishes them; Phase 4 adds the step machine
//! in between.

use chrono::{DateTime, Utc};
use redis::AsyncCommands as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cache::keys;
use crate::error::AppResult;
use crate::state::AppState;

pub const FLOW_TTL_SECS: u64 = 10 * 60;

/// Validated authorization request, kept for the whole flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub client_id: Uuid,
    pub client_public_id: String,
    pub redirect_uri: String,
    pub response_mode: ResponseMode,
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub prompt: Vec<String>,
    pub max_age: Option<u64>,
    pub acr_values: Vec<String>,
    pub login_hint: Option<String>,
    pub ui_locales: Vec<String>,
    pub claims: Option<serde_json::Value>,
    /// Whether the client is exempt from the consent screen.
    pub skip_consent: bool,
    /// A device authorization (RFC 8628) being approved: the hash of the
    /// device code the flow's finish approves instead of issuing a code.
    #[serde(default)]
    pub device_code: Option<String>,
    /// `organization`: the slug or id of the organization the client asks the
    /// session to act in. A member is put there without being asked.
    #[serde(default)]
    pub organization: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    Query,
    Fragment,
    FormPost,
    /// JARM: response parameters inside a signed JWT (`response=`).
    QueryJwt,
    FragmentJwt,
    FormPostJwt,
}

impl ResponseMode {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "query" => Self::Query,
            "fragment" => Self::Fragment,
            "form_post" => Self::FormPost,
            // `jwt` alone: default mode for response_type=code is query.
            "jwt" | "query.jwt" => Self::QueryJwt,
            "fragment.jwt" => Self::FragmentJwt,
            "form_post.jwt" => Self::FormPostJwt,
            _ => return None,
        })
    }

    /// Delivery mechanism underneath a JARM mode.
    pub fn base(self) -> Self {
        match self {
            Self::QueryJwt => Self::Query,
            Self::FragmentJwt => Self::Fragment,
            Self::FormPostJwt => Self::FormPost,
            other => other,
        }
    }

    pub fn is_jarm(self) -> bool {
        matches!(self, Self::QueryJwt | Self::FragmentJwt | Self::FormPostJwt)
    }
}

/// Where the flow currently is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowStage {
    /// User must authenticate (fresh login, `prompt=login`, `max_age` exceeded).
    Authenticate,
    /// User must register (`prompt=create`).
    Register,
    /// Registered; the verification link must be opened before continuing.
    VerifyEmail,
    /// Password expired or flagged: a new one is required before continuing.
    PasswordChange,
    /// Second factor required (Phase 7).
    Mfa,
    /// Required profile attributes are missing.
    Profile,
    /// Terms of service must be accepted.
    Terms,
    /// The user belongs to several organizations and must choose one for this
    /// session.
    Organization,
    /// Authenticated; consent for `pending_scopes` is required.
    Consent,
    /// Everything done; `GET /flows/{id}/finish` completes the authorization.
    Done,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFlow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub request: AuthRequest,
    pub stage: FlowStage,
    /// Set once the user is authenticated within this flow.
    pub session_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    /// Scopes still needing consent.
    pub pending_scopes: Vec<String>,
    /// Require an authentication newer than this (from `max_age` / `prompt=login`).
    pub require_auth_after: Option<DateTime<Utc>>,
    /// Opaque CSRF token bound to the flow; every step must echo it.
    pub csrf: String,
    /// Failed authentication attempts within this flow.
    #[serde(default)]
    pub attempts: u32,
    /// Method that authenticated the user in this flow (`pwd`, `otp`, ...).
    #[serde(default)]
    pub amr: Vec<String>,
    /// The organization this session acts in, once chosen (or settled from a
    /// single membership, the request, or the session it resumes).
    #[serde(default)]
    pub org_id: Option<Uuid>,
    /// The browser presented a live trusted-device cookie for this user.
    #[serde(default)]
    pub trusted_device: bool,
    /// The risk policy scored this sign-in at or above the step-up
    /// threshold: the second factor is required whatever the MFA policy and
    /// the trusted-device cookie say. Decided once, when the first factor
    /// passed, and carried for the rest of the flow.
    #[serde(default)]
    pub risk_step_up: bool,
    /// The user asked to remember this browser; the device is registered
    /// (and its cookie set) when the flow finishes, never before.
    #[serde(default)]
    pub remember_device: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub async fn create(state: &AppState, mut flow: LoginFlow) -> AppResult<LoginFlow> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    flow.csrf = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes);
    flow.created_at = Utc::now();
    flow.expires_at = flow.created_at + chrono::Duration::seconds(FLOW_TTL_SECS as i64);
    save(state, &flow).await?;
    Ok(flow)
}

pub async fn save(state: &AppState, flow: &LoginFlow) -> AppResult<()> {
    let ttl = (flow.expires_at - Utc::now()).num_seconds();
    if ttl <= 0 {
        return Ok(());
    }
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(
            keys::login_flow(flow.tenant_id, flow.id),
            serde_json::to_string(flow)?,
            ttl as u64,
        )
        .await?;
    Ok(())
}

pub async fn get(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<Option<LoginFlow>> {
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = conn.get(keys::login_flow(tenant_id, id)).await?;
    Ok(raw
        .and_then(|r| serde_json::from_str::<LoginFlow>(&r).ok())
        .filter(|f| f.expires_at > Utc::now()))
}

pub async fn delete(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
    let mut conn = state.redis.get().await?;
    let _: () = conn.del(keys::login_flow(tenant_id, id)).await?;
    Ok(())
}
