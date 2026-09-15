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
use crate::error::AppResult;
use crate::models::{Client, Tenant};
use crate::services::{clients, keys as signing_keys, refresh_tokens, sessions, tokens};
use crate::state::AppState;

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
}

/// Terminate a session everywhere it is known.
pub async fn end_session(
    state: &AppState,
    tenant: &Tenant,
    session_id: Uuid,
) -> AppResult<LogoutOutcome> {
    let participants = sessions::clients_of(state, tenant.id, session_id).await?;
    let session = sessions::get(state, tenant.id, session_id, &tenant.settings.session).await?;
    sessions::revoke(state, tenant.id, session_id).await?;
    refresh_tokens::revoke_for_session(
        state,
        tenant.id,
        ridm_core::events::Actor::System,
        session_id,
    )
    .await?;

    let issuer = match &tenant.settings.custom_domain {
        Some(host) => format!("https://{host}"),
        None => state.config.issuer_for(&tenant.slug),
    };
    let mut outcome = LogoutOutcome::default();
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
        let st = state.clone();
        let tenant = tenant.clone();
        let user_id = session.user_id;
        tokio::spawn(async move {
            for client in backchannel {
                if let Err(err) = send_backchannel(&st, &tenant, &client, user_id, session_id).await
                {
                    tracing::warn!(client = %client.client_id, error = %err, "back-channel logout failed");
                }
            }
        });
    }
    Ok(outcome)
}

/// Build and POST a logout token (OIDC Back-Channel Logout 1.0 §2.4).
async fn send_backchannel(
    state: &AppState,
    tenant: &Tenant,
    client: &Client,
    user_id: Uuid,
    session_id: Uuid,
) -> AppResult<()> {
    let uri = client
        .backchannel_logout_uri
        .clone()
        .ok_or_else(|| crate::error::AppError::Internal("no backchannel uri".into()))?;
    let user = crate::services::users::get(state, tenant.id, user_id).await?;
    let tc = tokens::TokenClient::from_client(client, tenant, vec![]);
    let key = signing_keys::ensure_active(state, tenant.id, &tenant.settings.keys).await?;
    let mut claims: Map<String, serde_json::Value> = Map::new();
    let issuer = match &tenant.settings.custom_domain {
        Some(host) => format!("https://{host}"),
        None => state.config.issuer_for(&tenant.slug),
    };
    claims.insert("iss".into(), json!(issuer));
    claims.insert("sub".into(), json!(tokens::subject_for(tenant, &tc, &user)));
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

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    let res = http
        .post(&uri)
        .form(&[("logout_token", logout_token)])
        .send()
        .await
        .map_err(|e| crate::error::AppError::Unavailable(e.to_string()))?;
    if !res.status().is_success() {
        return Err(crate::error::AppError::Unavailable(format!(
            "{} answered {}",
            uri,
            res.status()
        )));
    }
    tracing::info!(client = %client.client_id, "back-channel logout delivered");
    Ok(())
}
