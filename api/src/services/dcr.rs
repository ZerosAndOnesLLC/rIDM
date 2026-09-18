//! Initial access tokens for dynamic client registration (RFC 7591 §1.2):
//! admin-issued bearer tokens (`iat_` + 256 random bits) that
//! `POST /t/{slug}/register` demands under `dcr.mode = initial_access_token`.
//! Stored as a SHA-256 hash, shown once, with an optional expiry and an
//! optional budget of registrations; listed and revoked by id.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{CreatedInitialAccessToken, InitialAccessToken, NewInitialAccessToken};
use crate::repos;
use crate::repos::initial_access_tokens::NewRow;
use crate::state::AppState;

const PREFIX: &str = "iat_";
/// Ten years; anything longer is a token without expiry.
const MAX_TTL_SECS: u64 = 10 * 365 * 24 * 3600;

fn hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Issue a token. The secret is only ever returned here.
pub async fn issue(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    input: NewInitialAccessToken,
) -> AppResult<CreatedInitialAccessToken> {
    let description = input
        .description
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty());
    if description.is_some_and(|d| d.chars().count() > 200) {
        return Err(AppError::BadRequest(
            "description must be at most 200 characters".into(),
        ));
    }
    let expires_at = match input.expires_in_secs {
        Some(0) => {
            return Err(AppError::BadRequest(
                "expires_in_secs must be at least 1".into(),
            ));
        }
        Some(s) if s > MAX_TTL_SECS => {
            return Err(AppError::BadRequest(format!(
                "expires_in_secs must be at most {MAX_TTL_SECS}"
            )));
        }
        Some(s) => Some(Utc::now() + Duration::seconds(s as i64)),
        None => None,
    };
    let max_uses = match input.max_uses {
        Some(0) => return Err(AppError::BadRequest("max_uses must be at least 1".into())),
        Some(n) => Some(
            i32::try_from(n).map_err(|_| AppError::BadRequest("max_uses is too large".into()))?,
        ),
        None => None,
    };
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let token = Zeroizing::new(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)));
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let record = repos::initial_access_tokens::insert(
        &mut *tx,
        NewRow {
            id: Uuid::now_v7(),
            tenant_id,
            description,
            token_hash: &hash(&token),
            max_uses,
            expires_at,
        },
    )
    .await?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::InitialAccessTokenCreated {
            token_id: record.id,
        },
    ));
    Ok(CreatedInitialAccessToken {
        record,
        token: token.to_string(),
    })
}

/// Every token of the tenant, newest first (never the secrets).
pub async fn list(state: &AppState, tenant_id: Uuid) -> AppResult<Vec<InitialAccessToken>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::initial_access_tokens::list(&mut *tx, tenant_id).await?;
    tx.commit().await?;
    Ok(rows)
}

pub async fn revoke(state: &AppState, tenant_id: Uuid, actor: Actor, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::initial_access_tokens::revoke(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    if !ok {
        return Err(AppError::NotFound("initial access token"));
    }
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::InitialAccessTokenRevoked { token_id: id },
    ));
    Ok(())
}

/// Spend one use of an initial access token. `false` when unknown, expired,
/// revoked or used up. The check and the count are one statement, so two
/// registrations racing for a token's last use cannot both have it.
pub async fn consume_initial_access_token(
    state: &AppState,
    tenant_id: Uuid,
    presented: &str,
) -> AppResult<bool> {
    if !presented.starts_with(PREFIX) || presented.len() > 128 {
        return Ok(false);
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok = repos::initial_access_tokens::consume(&mut *tx, tenant_id, &hash(presented)).await?;
    tx.commit().await?;
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_sha256_of_the_whole_token() {
        assert_eq!(hash("iat_x").len(), 32);
        assert_ne!(hash("iat_x"), hash("iat_y"));
    }
}
