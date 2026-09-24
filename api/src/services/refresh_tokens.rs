//! Opaque refresh tokens with rotation and reuse detection (OAuth 2.0 Security
//! BCP §4.14). The client receives `rt_<random>`; only SHA-256(token) is stored.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::db;
use crate::error::{AppError, AppResult, OAuthError, OAuthErrorCode};
use crate::models::RefreshToken;
use crate::repos;
use crate::services::tokens::SenderProof;
use crate::state::AppState;

const PREFIX: &str = "rt_";

pub struct IssueRequest<'a> {
    pub client_id: &'a str,
    pub user_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub scopes: &'a [String],
    pub audiences: &'a [String],
    pub ttl: Duration,
    /// Bind the family to a DPoP key (public clients presenting a proof).
    pub dpop_jkt: Option<&'a str>,
    /// Bind the family to a client certificate (public clients registered
    /// for certificate-bound tokens, RFC 8705 §4).
    pub mtls_x5t: Option<&'a str>,
    /// Authentication context to repeat in every ID token minted from this
    /// family (OIDC Core §12.2).
    pub auth_time: Option<DateTime<Utc>>,
    pub amr: &'a [String],
    pub acr: Option<&'a str>,
    /// Organization the sign-in acted in, repeated by every token minted from
    /// this family.
    pub org_id: Option<Uuid>,
    /// `act` of an impersonated sign-in, repeated by every token minted from
    /// this family.
    pub act: Option<&'a serde_json::Value>,
}

/// A freshly minted token: the secret is only ever returned here.
#[derive(Debug)]
pub struct Issued {
    pub token: Zeroizing<String>,
    pub record: RefreshToken,
}

fn hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn random_token() -> Zeroizing<String> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    Zeroizing::new(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

async fn insert_in(
    tx: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    family_id: Uuid,
    req: &IssueRequest<'_>,
    expires_at: DateTime<Utc>,
) -> AppResult<Issued> {
    let token = random_token();
    let now = Utc::now();
    let row = RefreshToken {
        id: Uuid::now_v7(),
        tenant_id,
        family_id,
        client_id: req.client_id.to_string(),
        user_id: req.user_id,
        session_id: req.session_id,
        token_hash: hash(&token),
        scopes: req.scopes.to_vec(),
        audiences: req.audiences.to_vec(),
        auth_time: req.auth_time,
        amr: req.amr.to_vec(),
        acr: req.acr.map(str::to_string),
        org_id: req.org_id,
        act: req.act.cloned(),
        expires_at,
        dpop_jkt: req.dpop_jkt.map(str::to_string),
        mtls_x5t: req.mtls_x5t.map(str::to_string),
        consumed_at: None,
        revoked_at: None,
        created_at: now,
    };
    let record = repos::refresh_tokens::insert(&mut *tx, &row)
        .await
        .map_err(AppError::from_db)?;
    Ok(Issued { token, record })
}

/// Start a new token family (authorization code / device / client grant).
pub async fn issue(state: &AppState, tenant_id: Uuid, req: IssueRequest<'_>) -> AppResult<Issued> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let issued = insert_in(
        &mut tx,
        tenant_id,
        Uuid::now_v7(),
        &req,
        Utc::now() + req.ttl,
    )
    .await?;
    tx.commit().await?;
    Ok(issued)
}

/// Exchange a refresh token for a new one in the same family.
///
/// * unknown / expired / revoked → `invalid_grant`
/// * wrong client → `invalid_grant`
/// * already consumed → theft is assumed: the whole family is revoked and
///   `invalid_grant` is returned (the legitimate client's next attempt fails
///   too, forcing a fresh login).
/// * bound to a DPoP key (`dpop_jkt`) and the request's proof key differs →
///   `invalid_grant`, and the token stays unspent (RFC 9449 §5); the same
///   for a client certificate (`mtls_x5t`, RFC 8705 §4).
/// * issued under an SSO session that was since revoked (signed out) → the
///   family is revoked and `invalid_grant` is returned. Revoking a session
///   revokes its tokens already; this closes the window of a code exchanged
///   after its session ended.
/// * issued without `offline_access` under an SSO session that has since
///   ended in any way — signed out, or idle or absolute timeout — → the
///   family is revoked and `invalid_grant` is returned: such a token lives
///   only as long as the sign-in (OIDC Core §11 reserves outliving it for
///   `offline_access`). A refresh counts as activity and slides the
///   session's idle window. An `offline_access` family outlives an expired
///   session, though not an explicit sign-out.
/// * `resources` (RFC 8707 `resource` on the refresh request) names an
///   audience the original grant did not carry → `invalid_target`, and the
///   token stays unspent: a refresh may narrow the audience, never widen it
///   (RFC 8707 §2.2).
/// * `scopes` (the refresh request's `scope`, when sent) names a scope the
///   original grant did not carry → `invalid_scope`, and the token stays
///   unspent: a refresh may narrow the scope, never widen it (RFC 6749 §6).
pub async fn rotate(
    state: &AppState,
    tenant_id: Uuid,
    client_id: &str,
    presented: &str,
    proof: SenderProof<'_>,
    resources: &[String],
    scopes: Option<&[String]>,
) -> Result<Issued, OAuthError> {
    redeem(
        state, tenant_id, client_id, presented, proof, resources, scopes, true,
    )
    .await
}

/// [`rotate`], or with `rotate` false (a FAPI 2.0 client) every check of it
/// with the presented token left live and handed back as it is.
#[allow(clippy::too_many_arguments)]
pub async fn redeem(
    state: &AppState,
    tenant_id: Uuid,
    client_id: &str,
    presented: &str,
    proof: SenderProof<'_>,
    resources: &[String],
    scopes: Option<&[String]>,
    rotate: bool,
) -> Result<Issued, OAuthError> {
    if !presented.starts_with(PREFIX) || presented.len() > 256 {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            "invalid refresh token",
        ));
    }
    let now = Utc::now();
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let Some(current) =
        repos::refresh_tokens::find_by_hash_for_update(&mut *tx, tenant_id, &hash(presented))
            .await?
    else {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            "invalid refresh token",
        ));
    };
    if !bool::from(current.client_id.as_bytes().ct_eq(client_id.as_bytes())) {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            "refresh token was not issued to this client",
        ));
    }
    if current.consumed_at.is_some() {
        // Reuse: revoke everything descending from the same grant.
        let count =
            repos::refresh_tokens::revoke_family(&mut *tx, tenant_id, current.family_id).await?;
        tx.commit().await?;
        tracing::warn!(tenant = %tenant_id, family = %current.family_id, client = %client_id, revoked = count, "refresh token reuse detected; family revoked");
        state.events.publish(Event::new(
            Some(tenant_id),
            Actor::Client { id: Uuid::nil() },
            EventKind::RefreshTokenReuseDetected {
                family_id: current.family_id,
                client_id: client_id.to_string(),
                user_id: current.user_id,
            },
        ));
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            "refresh token reuse detected",
        ));
    }
    if current.revoked_at.is_some() {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            "refresh token revoked",
        ));
    }
    if current.expires_at <= now {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            "refresh token expired",
        ));
    }
    if let Some(bound) = current.dpop_jkt.as_deref()
        && proof.jkt != Some(bound)
    {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            "refresh token is bound to another DPoP key",
        ));
    }
    if let Some(bound) = current.mtls_x5t.as_deref()
        && proof.x5t != Some(bound)
    {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            "refresh token is bound to another client certificate",
        ));
    }
    if let Some(extra) = resources
        .iter()
        .find(|r| !current.audiences.iter().any(|a| a == *r))
    {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidTarget,
            format!("resource `{extra}` was not part of the original grant"),
        ));
    }
    if let Some(extra) = scopes
        .unwrap_or_default()
        .iter()
        .find(|s| !current.scopes.contains(s))
    {
        return Err(OAuthError::new(
            OAuthErrorCode::InvalidScope,
            format!("scope `{extra}` was not granted"),
        ));
    }
    if let Some(sid) = current.session_id {
        let ended = if current.is_offline() {
            repos::sessions::is_revoked(&mut *tx, tenant_id, sid).await?
        } else {
            let policy = crate::services::tenants::get_cached(state, tenant_id)
                .await?
                .map(|t| t.settings.session.clone())
                .unwrap_or_default();
            crate::services::sessions::get(state, tenant_id, sid, &policy)
                .await?
                .is_none()
        };
        if ended {
            repos::refresh_tokens::revoke_family(&mut *tx, tenant_id, current.family_id).await?;
            tx.commit().await?;
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidGrant,
                "the session this token was issued in has ended",
            ));
        }
    }

    if !rotate {
        tx.commit().await?;
        return Ok(Issued {
            token: Zeroizing::new(presented.to_string()),
            record: current,
        });
    }
    repos::refresh_tokens::mark_consumed(&mut *tx, tenant_id, current.id).await?;
    let req = IssueRequest {
        client_id,
        user_id: current.user_id,
        session_id: current.session_id,
        scopes: &current.scopes,
        audiences: &current.audiences,
        ttl: Duration::zero(),
        dpop_jkt: current.dpop_jkt.as_deref(),
        mtls_x5t: current.mtls_x5t.as_deref(),
        auth_time: current.auth_time,
        amr: &current.amr,
        acr: current.acr.as_deref(),
        org_id: current.org_id,
        act: current.act.as_ref(),
    };
    // The family keeps its absolute expiry (and its bindings); rotation never extends it.
    let issued = insert_in(
        &mut tx,
        tenant_id,
        current.family_id,
        &req,
        current.expires_at,
    )
    .await?;
    tx.commit().await?;
    Ok(issued)
}

/// Revoke one token (and its family) by its secret, e.g. RFC 7009 `/revoke`.
/// Unknown tokens are not an error (RFC 7009 §2.2).
pub async fn revoke(
    state: &AppState,
    tenant_id: Uuid,
    client_id: &str,
    presented: &str,
) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    if let Some(t) =
        repos::refresh_tokens::find_by_hash_for_update(&mut *tx, tenant_id, &hash(presented))
            .await?
        && t.client_id == client_id
    {
        repos::refresh_tokens::revoke_family(&mut *tx, tenant_id, t.family_id).await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn revoke_for_user(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    user_id: Uuid,
    client_id: Option<&str>,
) -> AppResult<u64> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let count =
        repos::refresh_tokens::revoke_for_user(&mut *tx, tenant_id, user_id, client_id).await?;
    tx.commit().await?;
    if count > 0 {
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::TokensRevoked {
                user_id: Some(user_id),
                session_id: None,
                count,
            },
        ));
    }
    Ok(count)
}

pub async fn revoke_for_session(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    session_id: Uuid,
) -> AppResult<u64> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let count = repos::refresh_tokens::revoke_for_session(&mut *tx, tenant_id, session_id).await?;
    tx.commit().await?;
    if count > 0 {
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::TokensRevoked {
                user_id: None,
                session_id: Some(session_id),
                count,
            },
        ));
    }
    Ok(count)
}

/// The stored record of a presented refresh token, read without locking
/// it: introspection reports on the token and changes nothing. Read from the
/// primary so a rotation or revocation shows at once.
pub async fn find(
    state: &AppState,
    tenant_id: Uuid,
    presented: &str,
) -> AppResult<Option<RefreshToken>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rec = repos::refresh_tokens::find_by_hash(&mut *tx, tenant_id, &hash(presented)).await?;
    tx.commit().await?;
    Ok(rec)
}

pub async fn list_live_for_user(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<RefreshToken>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::refresh_tokens::list_live_for_user(&mut *tx, tenant_id, user_id).await?;
    tx.commit().await?;
    Ok(rows)
}

/// Remove dead rows older than `retention` (called by the cleanup job).
pub async fn purge(state: &AppState, tenant_id: Uuid, retention: Duration) -> AppResult<u64> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let n = repos::refresh_tokens::purge(&mut *tx, tenant_id, Utc::now() - retention).await?;
    tx.commit().await?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_prefixed_random_and_hashed() {
        let a = random_token();
        let b = random_token();
        assert!(a.starts_with("rt_") && a.len() > 40);
        assert_ne!(*a, *b);
        assert_eq!(hash(&a).len(), 32);
        assert_ne!(hash(&a), hash(&b));
    }
}
