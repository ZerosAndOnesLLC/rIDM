//! Passkeys (WebAuthn, `webauthn` credential rows): a discoverable credential
//! signs a user in without a password, and any passkey serves as the second
//! step of another sign-in. The serialised key (public key, counter, backup
//! flags) is encrypted per row like every other credential; the credential id
//! the authenticator presents is kept in `external_id` so a discoverable
//! assertion finds its row before the user is known. Ceremony state lives in
//! Redis for a few minutes, bound to the flow that started it, and is spent
//! by the answer whether or not it verifies.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, DiscoverableAuthentication, DiscoverableKey, Passkey,
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Webauthn, WebauthnBuilder, WebauthnError,
};
use webauthn_rs_proto::ResidentKeyRequirement;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{Credential, Tenant, User};
use crate::repos;
use crate::repos::credentials::CredentialSecret;
use crate::services::credential_secrets::{decrypt, encrypt};
use crate::services::notifications;
use crate::state::AppState;

pub const KIND: &str = "webauthn";
const CEREMONY_TTL_SECS: u64 = 5 * 60;
const DEFAULT_LABEL: &str = "Passkey";
const REGISTER: &str = "register";
const ASSERT: &str = "assert";

#[derive(Debug, Serialize, Deserialize)]
struct PasskeyData {
    key: Passkey,
}

/// A passkey assertion that verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub credential_id: Uuid,
    /// The authenticator checked the user (PIN, biometric, ...), so the
    /// assertion is worth two factors.
    pub user_verified: bool,
}

/// The credential id as kept in `credentials.external_id`.
fn external_id(id: &CredentialID) -> String {
    URL_SAFE_NO_PAD.encode(id.as_ref())
}

fn config_err(e: WebauthnError) -> AppError {
    AppError::Internal(format!("webauthn: {e}"))
}

/// The relying party the tenant's pages act for: its custom domain when it
/// has one, else the host the UI is served from. The API's own origin is
/// accepted too when it shares that host (the dev proxy setup), since the
/// browser reports whichever origin the page was loaded from.
pub fn relying_party(state: &AppState, tenant: &Tenant) -> AppResult<Webauthn> {
    let ui = &state.config.ui_url;
    let (rp_id, origin) = match &tenant.settings.custom_domain {
        Some(host) => (
            host.clone(),
            Url::parse(&format!("https://{host}"))
                .map_err(|e| AppError::Internal(format!("custom domain: {e}")))?,
        ),
        None => (
            ui.host_str()
                .ok_or_else(|| AppError::Internal("UI_URL has no host".into()))?
                .to_string(),
            ui.clone(),
        ),
    };
    let mut builder = WebauthnBuilder::new(&rp_id, &origin)
        .map_err(config_err)?
        .rp_name(&tenant.display_name);
    for extra in [ui, &state.config.public_url] {
        if extra.host_str() == Some(rp_id.as_str()) && extra.origin() != origin.origin() {
            builder = builder.append_allowed_origin(extra);
        }
    }
    builder.build().map_err(config_err)
}

async fn put_state<T: Serialize>(
    state: &AppState,
    tenant_id: Uuid,
    scope: Uuid,
    kind: &str,
    value: &T,
) -> AppResult<()> {
    let mut conn = state.redis.get().await?;
    let _: () = redis::cmd("SET")
        .arg(keys::passkey_ceremony(tenant_id, scope, kind))
        .arg(serde_json::to_string(value)?)
        .arg("EX")
        .arg(CEREMONY_TTL_SECS)
        .query_async(&mut *conn)
        .await?;
    Ok(())
}

/// Read and delete the pending ceremony: a challenge answers once.
async fn take_state<T: DeserializeOwned>(
    state: &AppState,
    tenant_id: Uuid,
    scope: Uuid,
    kind: &str,
) -> AppResult<T> {
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = redis::cmd("GETDEL")
        .arg(keys::passkey_ceremony(tenant_id, scope, kind))
        .query_async(&mut *conn)
        .await?;
    match raw {
        Some(raw) => Ok(serde_json::from_str(&raw)?),
        None => Err(AppError::BadRequest(
            "no passkey ceremony is pending; start again".into(),
        )),
    }
}

/// The user's passkeys with their rows.
async fn keys_of(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<(CredentialSecret, Passkey)>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::credentials::list_secrets_of_type(&mut *tx, tenant_id, user_id, KIND).await?;
    tx.commit().await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let data: PasskeyData = decrypt(state, tenant_id, row.id, &row.data_enc).await?;
        out.push((row, data.key));
    }
    Ok(out)
}

fn display_name_of(user: &User) -> String {
    user.attributes
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| user.username.clone())
}

/// Start registering a passkey for the user: the creation options the browser
/// passes to `navigator.credentials.create`. Passkeys already held are
/// excluded so an authenticator is not enrolled twice.
pub async fn begin_registration(
    state: &AppState,
    tenant: &Tenant,
    scope: Uuid,
    user: &User,
) -> AppResult<CreationChallengeResponse> {
    let rp = relying_party(state, tenant)?;
    let exclude: Vec<CredentialID> = keys_of(state, tenant.id, user.id)
        .await?
        .into_iter()
        .map(|(_, k)| k.cred_id().clone())
        .collect();
    let account = user.email.as_deref().unwrap_or(&user.username);
    let (mut options, pending) = rp
        .start_passkey_registration(
            user.id,
            account,
            &display_name_of(user),
            (!exclude.is_empty()).then_some(exclude),
        )
        .map_err(config_err)?;
    // webauthn-rs discourages resident keys; a passkey that can sign the user
    // in without a password has to be one, so ask for it where the
    // authenticator can (a security key without storage still enrols as a
    // second factor).
    if let Some(selection) = options.public_key.authenticator_selection.as_mut() {
        selection.resident_key = Some(ResidentKeyRequirement::Preferred);
    }
    put_state(state, tenant.id, scope, REGISTER, &pending).await?;
    Ok(options)
}

/// Verify the browser's answer to [`begin_registration`] and store the
/// passkey. `Ok(None)` means the attestation did not verify (the ceremony is
/// spent either way); a credential id already registered is a conflict.
pub async fn finish_registration(
    state: &AppState,
    tenant: &Tenant,
    scope: Uuid,
    user: &User,
    credential: &RegisterPublicKeyCredential,
    label: Option<&str>,
) -> AppResult<Option<Credential>> {
    let pending: PasskeyRegistration = take_state(state, tenant.id, scope, REGISTER).await?;
    let rp = relying_party(state, tenant)?;
    let key = match rp.finish_passkey_registration(credential, &pending) {
        Ok(k) => k,
        Err(e) => {
            tracing::debug!(error = %e, "passkey registration rejected");
            return Ok(None);
        }
    };
    let ext = external_id(key.cred_id());
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    if repos::credentials::find_secret_by_external_id(&mut *tx, tenant.id, KIND, &ext)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(
            "this passkey is already registered".into(),
        ));
    }
    let id = Uuid::now_v7();
    let enc = encrypt(state, tenant.id, id, &PasskeyData { key }).await?;
    let label = label
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| l.chars().take(80).collect::<String>())
        .unwrap_or_else(|| DEFAULT_LABEL.to_string());
    let row = repos::credentials::insert(
        &mut *tx,
        tenant.id,
        repos::credentials::NewCredential {
            id,
            user_id: user.id,
            kind: KIND,
            label: Some(&label),
            data_enc: &enc.to_bytes(),
            key_version: enc.key_version as i32,
            external_id: Some(&ext),
        },
    )
    .await?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tenant.id),
        Actor::User { id: user.id },
        EventKind::MfaChanged {
            user_id: user.id,
            change: format!("passkey added ({label})"),
        },
    ));
    notifications::mfa_changed(state, tenant.id, user.id, "A passkey was added").await;
    Ok(Some(row))
}

/// Start an assertion against the user's own passkeys (second step of a
/// sign-in). Fails when the user holds none.
pub async fn begin_authentication(
    state: &AppState,
    tenant: &Tenant,
    scope: Uuid,
    user: &User,
) -> AppResult<RequestChallengeResponse> {
    let keys: Vec<Passkey> = keys_of(state, tenant.id, user.id)
        .await?
        .into_iter()
        .map(|(_, k)| k)
        .collect();
    if keys.is_empty() {
        return Err(AppError::BadRequest("no passkey is registered".into()));
    }
    let rp = relying_party(state, tenant)?;
    let (options, pending) = rp.start_passkey_authentication(&keys).map_err(config_err)?;
    put_state(state, tenant.id, scope, ASSERT, &pending).await?;
    Ok(options)
}

/// Verify the answer to [`begin_authentication`]. `Ok(None)` is an assertion
/// that did not verify (wrong key, bad signature, replayed counter).
pub async fn finish_authentication(
    state: &AppState,
    tenant: &Tenant,
    scope: Uuid,
    user: &User,
    credential: &PublicKeyCredential,
) -> AppResult<Option<Verified>> {
    let pending: PasskeyAuthentication = take_state(state, tenant.id, scope, ASSERT).await?;
    let rp = relying_party(state, tenant)?;
    let result = match rp.finish_passkey_authentication(credential, &pending) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = %e, "passkey assertion rejected");
            return Ok(None);
        }
    };
    let Some((row, key)) = keys_of(state, tenant.id, user.id)
        .await?
        .into_iter()
        .find(|(_, k)| k.cred_id() == result.cred_id())
    else {
        return Ok(None);
    };
    record_use(state, tenant.id, row.id, key, &result).await?;
    Ok(Some(Verified {
        credential_id: row.id,
        user_verified: result.user_verified(),
    }))
}

/// Start a passwordless sign-in: an assertion with no allow list, answered
/// by whichever discoverable credential the user picks in the browser.
pub async fn begin_discoverable(
    state: &AppState,
    tenant: &Tenant,
    scope: Uuid,
) -> AppResult<RequestChallengeResponse> {
    let rp = relying_party(state, tenant)?;
    let (mut options, pending) = rp.start_discoverable_authentication().map_err(config_err)?;
    // The page asks with a button, not an autofill prompt.
    options.mediation = None;
    put_state(state, tenant.id, scope, ASSERT, &pending).await?;
    Ok(options)
}

/// Verify the answer to [`begin_discoverable`]: the credential id names the
/// row, the row's owner must match the user handle the authenticator sent.
/// `Ok(None)` when nothing verifies; the caller learns nothing about which
/// check failed.
pub async fn finish_discoverable(
    state: &AppState,
    tenant: &Tenant,
    scope: Uuid,
    credential: &PublicKeyCredential,
) -> AppResult<Option<(Uuid, Verified)>> {
    let pending: DiscoverableAuthentication = take_state(state, tenant.id, scope, ASSERT).await?;
    let rp = relying_party(state, tenant)?;
    let Ok((user_id, cred_id)) = rp.identify_discoverable_authentication(credential) else {
        return Ok(None);
    };
    let ext = URL_SAFE_NO_PAD.encode(cred_id);
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    let row =
        repos::credentials::find_secret_by_external_id(&mut *tx, tenant.id, KIND, &ext).await?;
    tx.commit().await?;
    let Some(row) = row.filter(|r| r.user_id == user_id) else {
        return Ok(None);
    };
    let data: PasskeyData = decrypt(state, tenant.id, row.id, &row.data_enc).await?;
    let result = match rp.finish_discoverable_authentication(
        credential,
        pending,
        &[DiscoverableKey::from(&data.key)],
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = %e, "discoverable passkey assertion rejected");
            return Ok(None);
        }
    };
    record_use(state, tenant.id, row.id, data.key, &result).await?;
    Ok(Some((
        user_id,
        Verified {
            credential_id: row.id,
            user_verified: result.user_verified(),
        },
    )))
}

/// Store the counter and backup flags the assertion reported and stamp the use.
async fn record_use(
    state: &AppState,
    tenant_id: Uuid,
    credential_id: Uuid,
    mut key: Passkey,
    result: &webauthn_rs::prelude::AuthenticationResult,
) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    if key.update_credential(result) == Some(true) {
        let enc = encrypt(state, tenant_id, credential_id, &PasskeyData { key }).await?;
        repos::credentials::update_data(
            &mut *tx,
            tenant_id,
            credential_id,
            &enc.to_bytes(),
            enc.key_version as i32,
        )
        .await?;
    } else {
        repos::credentials::touch_last_used(&mut *tx, tenant_id, credential_id).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Does the user hold at least one passkey?
pub async fn has_passkey(state: &AppState, tenant_id: Uuid, user_id: Uuid) -> AppResult<bool> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let n = repos::credentials::count_of_types(&mut *tx, tenant_id, user_id, &[KIND]).await?;
    tx.commit().await?;
    Ok(n > 0)
}
