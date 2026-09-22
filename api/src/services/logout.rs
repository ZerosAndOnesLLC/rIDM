//! Ending a browser session: revoke the SSO session and its refresh tokens,
//! notify relying parties (back-channel logout tokens, front-channel URLs),
//! and carry the RP-initiated logout request through the UI when confirmation
//! is needed.

use std::time::Duration;

use chrono::Utc;
use redis::AsyncCommands as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, json};
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{Client, Tenant, User};
use crate::repos;
use crate::services::{clients, keys as signing_keys, sessions, tokens};
use crate::state::AppState;
use crate::util::outbound;

pub const LOGOUT_FLOW_TTL_SECS: u64 = 10 * 60;

/// Pending RP-initiated logout awaiting user confirmation in the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutFlow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub session_id: Option<Uuid>,
    pub client_id: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
    pub ui_locales: Vec<String>,
    pub csrf: String,
}

pub async fn create_flow(state: &AppState, mut flow: LogoutFlow) -> AppResult<LogoutFlow> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    flow.csrf = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes);
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(
            keys::logout_flow(flow.tenant_id, flow.id),
            serde_json::to_string(&flow)?,
            LOGOUT_FLOW_TTL_SECS,
        )
        .await?;
    Ok(flow)
}

/// Read a logout flow without consuming it (the confirmation page).
pub async fn peek_flow(
    state: &AppState,
    tenant_id: Uuid,
    id: Uuid,
) -> AppResult<Option<LogoutFlow>> {
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = conn.get(keys::logout_flow(tenant_id, id)).await?;
    Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
}

pub async fn take_flow(
    state: &AppState,
    tenant_id: Uuid,
    id: Uuid,
) -> AppResult<Option<LogoutFlow>> {
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = redis::cmd("GETDEL")
        .arg(keys::logout_flow(tenant_id, id))
        .query_async(&mut conn)
        .await?;
    Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
}

/// Result of ending a session: what the UI must still do.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LogoutOutcome {
    /// Front-channel logout URLs (with `iss` and `sid`) for the UI to load.
    pub frontchannel_logout_uris: Vec<String>,
    pub backchannel_notified: usize,
    /// The session was live until now.
    #[serde(skip)]
    pub ended: bool,
    /// SAML SPs that took part: front-channel only, so a caller with a
    /// browser walks it through them (`saml_idp::logout_through`); without
    /// one they keep their own sessions until those expire.
    #[serde(skip)]
    pub saml_participants: Vec<crate::services::saml_idp::Participant>,
    /// The upstream SAML IdP that brokered the session: a caller with a
    /// browser sends it a `LogoutRequest` (`saml_sp::logout_upstream`);
    /// without one the IdP keeps its session.
    #[serde(skip)]
    pub saml_upstream: Option<crate::services::saml_sp::UpstreamSession>,
}

/// Terminate a session everywhere it is known: the SSO session, the refresh
/// tokens issued in it, and the relying parties that took part (back-channel
/// logout tokens are sent in the background; front-channel URLs are returned
/// for a browser to load). Every way a session ends on purpose — RP-initiated
/// logout, sign-out in the account console, an administrator's revocation,
/// a password change or reset, disabling or deleting the user — goes through
/// here so relying parties hear of it.
pub async fn end_session(
    state: &AppState,
    tenant: &Tenant,
    session_id: Uuid,
) -> AppResult<LogoutOutcome> {
    let participants = sessions::clients_of(state, tenant.id, session_id).await?;
    let saml_participants =
        crate::services::saml_idp::participants(state, tenant.id, session_id).await?;
    let saml_upstream = crate::services::saml_sp::upstream_of(state, tenant.id, session_id).await?;
    let session = sessions::get(state, tenant.id, session_id, &tenant.settings.session).await?;
    let ended = sessions::revoke(state, tenant.id, session_id).await?;

    let issuer = match &tenant.settings.custom_domain {
        Some(host) => format!("https://{host}"),
        None => state.config.issuer_for(&tenant.slug),
    };
    let mut outcome = LogoutOutcome {
        ended,
        saml_participants,
        saml_upstream,
        ..Default::default()
    };
    let Some(session) = session else {
        return Ok(outcome);
    };
    let mut backchannel: Vec<Client> = vec![];
    for public_id in participants {
        let Some(client) = clients::find_by_client_id(state, tenant.id, &public_id).await? else {
            continue;
        };
        if let Some(uri) = &client.frontchannel_logout_uri {
            let mut u = url::Url::parse(uri).ok();
            if let Some(u) = u.as_mut() {
                u.query_pairs_mut()
                    .append_pair("iss", &issuer)
                    .append_pair("sid", &session_id.to_string());
                outcome.frontchannel_logout_uris.push(u.to_string());
            }
        }
        if client.backchannel_logout_uri.is_some() {
            backchannel.push((*client).clone());
        }
    }
    outcome.backchannel_notified = backchannel.len();
    if !backchannel.is_empty() {
        // The subject is read now, soft-deleted or not: the caller may be
        // deleting the user while the tokens are on their way.
        let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
        let user = repos::users::find_by_id(&mut *tx, tenant.id, session.user_id).await?;
        tx.commit().await?;
        let Some(user) = user else {
            return Ok(outcome);
        };
        let st = state.clone();
        let tenant = tenant.clone();
        tokio::spawn(async move {
            for client in backchannel {
                if let Err(err) = send_backchannel(&st, &tenant, &client, &user, session_id).await {
                    tracing::warn!(client = %client.client_id, error = %err, "back-channel logout failed");
                }
            }
        });
    }
    Ok(outcome)
}

/// Sign a user out of every live session ("sign out everywhere"), or of all
/// but `keep`, each through [`end_session`]. Returns how many were live.
pub async fn end_sessions_for_user(
    state: &AppState,
    tenant: &Tenant,
    user_id: Uuid,
    keep: Option<Uuid>,
) -> AppResult<u64> {
    let mut ended = 0;
    for s in sessions::list_live_for_user(state, tenant.id, user_id).await? {
        if Some(s.id) == keep {
            continue;
        }
        if end_session(state, tenant, s.id).await?.ended {
            ended += 1;
        }
    }
    Ok(ended)
}

/// Build and POST a logout token (OIDC Back-Channel Logout 1.0 §2.4).
async fn send_backchannel(
    state: &AppState,
    tenant: &Tenant,
    client: &Client,
    user: &User,
    session_id: Uuid,
) -> AppResult<()> {
    let uri = client
        .backchannel_logout_uri
        .clone()
        .ok_or_else(|| AppError::Internal("no backchannel uri".into()))?;
    // A client registration (possibly a dynamic one) chose this URL: public
    // addresses only (SSRF).
    outbound::check_url(&uri).map_err(AppError::Unavailable)?;
    let tc = tokens::TokenClient::from_client(client, tenant, vec![]);
    let key = signing_keys::ensure_active(state, tenant.id, &tenant.settings.keys).await?;
    let mut claims: Map<String, serde_json::Value> = Map::new();
    let issuer = match &tenant.settings.custom_domain {
        Some(host) => format!("https://{host}"),
        None => state.config.issuer_for(&tenant.slug),
    };
    claims.insert("iss".into(), json!(issuer));
    claims.insert("sub".into(), json!(tokens::subject_for(tenant, &tc, user)));
    claims.insert("aud".into(), json!(client.client_id));
    claims.insert("iat".into(), json!(Utc::now().timestamp()));
    claims.insert("exp".into(), json!(Utc::now().timestamp() + 120));
    claims.insert("jti".into(), json!(Uuid::now_v7()));
    claims.insert("sid".into(), json!(session_id));
    claims.insert(
        "events".into(),
        json!({"http://schemas.openid.net/event/backchannel-logout": {}}),
    );
    let logout_token = tokens::sign(state, &key, "logout+jwt", &claims).await?;

    let http = outbound::client_builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let res = http
        .post(&uri)
        .form(&[("logout_token", logout_token)])
        .send()
        .await
        .map_err(|e| AppError::Unavailable(outbound::describe(&e)))?;
    if !res.status().is_success() {
        return Err(AppError::Unavailable(format!(
            "{} answered {}",
            uri,
            res.status()
        )));
    }
    tracing::info!(client = %client.client_id, "back-channel logout delivered");
    Ok(())
}
