//! TOTP second factor (RFC 6238) and recovery codes.
//!
//! The authenticator secret lives encrypted in a `totp` credential row (AAD
//! `credentials:{tenant}:{id}`, the same convention master-key rotation
//! re-encrypts). Recovery codes are SHA-256 hashed and kept, also encrypted,
//! in one `recovery_code` row per user; each is single-use. A TOTP code is
//! accepted once per time step (replay guard in Redis).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use redis::AsyncCommands as _;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use totp_rs::{Algorithm, Builder, Secret, Totp};
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{Tenant, User};
use crate::repos;
use crate::services::credential_secrets::{decrypt, encrypt};
use crate::services::{notifications, otp_factors, passkeys};
use crate::state::AppState;

pub const KIND_TOTP: &str = "totp";
pub const KIND_RECOVERY: &str = "recovery_code";
/// Credential types that count as a second factor.
pub const SECOND_FACTOR_KINDS: &[&str] = &[
    KIND_TOTP,
    passkeys::KIND,
    otp_factors::KIND_EMAIL,
    otp_factors::KIND_SMS,
];

pub const DIGITS: u8 = 6;
pub const PERIOD_SECS: u64 = 30;
/// Steps of clock drift accepted either side (RFC 6238 §5.2 recommends 1).
pub const SKEW: u16 = 1;
pub const RECOVERY_CODE_COUNT: usize = 10;
const RECOVERY_CODE_LEN: usize = 10;
const RECOVERY_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const ENROLMENT_TTL_SECS: u64 = 10 * 60;
const DEFAULT_LABEL: &str = "Authenticator app";

#[derive(Debug, Serialize, Deserialize)]
struct TotpData {
    /// Base32 (RFC 4648) secret.
    secret: String,
    digits: u8,
    period: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct RecoveryData {
    codes: Vec<RecoveryCode>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RecoveryCode {
    hash: String,
    used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingEnrolment {
    secret: String,
}

/// What the UI needs to add the account to an authenticator app.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct Enrolment {
    /// Base32 secret for manual entry.
    pub secret: String,
    pub otpauth_uri: String,
    pub issuer: String,
    pub account: String,
    pub digits: u8,
    pub period: u64,
}

/// Second factors a user holds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Factors {
    pub totp: bool,
    /// At least one passkey.
    pub webauthn: bool,
    /// Codes by email.
    pub email_otp: bool,
    /// Codes by text message.
    pub sms_otp: bool,
    /// Unused recovery codes left.
    pub recovery_codes: usize,
}

impl Factors {
    pub fn any(&self) -> bool {
        self.totp || self.webauthn || self.email_otp || self.sms_otp
    }
}

/// Which factor passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    Totp { credential_id: Uuid },
    RecoveryCode { remaining: usize },
}

fn hash(code: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code.as_bytes()))
}

/// otpauth labels cannot contain a colon.
fn label_safe(s: &str, fallback: &str) -> String {
    let out: String = s.trim().replace(':', " ");
    if out.is_empty() {
        fallback.to_string()
    } else {
        out
    }
}

fn issuer_of(tenant: &Tenant) -> String {
    label_safe(&tenant.display_name, &tenant.slug)
}

fn account_of(user: &User) -> String {
    label_safe(user.email.as_deref().unwrap_or(&user.username), "user")
}

fn build(secret_b32: &str, issuer: &str, account: &str) -> AppResult<Totp> {
    let secret = Secret::try_from_base32(secret_b32)
        .map_err(|e| AppError::Internal(format!("totp secret: {e}")))?;
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(DIGITS)
        .with_skew(SKEW)
        .with_step_duration(PERIOD_SECS)
        .with_secret(secret)
        .with_issuer(Some(issuer))
        .with_account_name(account)
        .build()
        .map_err(|e| AppError::Internal(format!("totp: {e}")))
}

/// Start an enrolment for the flow: a secret the user must prove once. Asking
/// again while one is pending returns the same secret (a reloaded page or a
/// repeated request must not race the QR code the user is scanning).
pub async fn begin_enrolment(
    state: &AppState,
    tenant: &Tenant,
    flow_id: Uuid,
    user: &User,
) -> AppResult<Enrolment> {
    let key = keys::totp_enrolment(tenant.id, flow_id);
    let mut conn = state.redis.get().await?;
    // Claim the slot atomically: concurrent requests (a double-fired effect,
    // a double click) must all see the one secret that won.
    let fresh = Secret::generate().to_base32();
    let claimed: Option<String> = redis::cmd("SET")
        .arg(&key)
        .arg(serde_json::to_string(&PendingEnrolment {
            secret: fresh.clone(),
        })?)
        .arg("NX")
        .arg("EX")
        .arg(ENROLMENT_TTL_SECS)
        .query_async(&mut conn)
        .await?;
    let secret = if claimed.is_some() {
        fresh
    } else {
        let raw: Option<String> = conn.get(&key).await?;
        match raw.and_then(|r| serde_json::from_str::<PendingEnrolment>(&r).ok()) {
            Some(p) => p.secret,
            None => return Err(AppError::Unavailable("enrolment slot vanished".into())),
        }
    };
    let issuer = issuer_of(tenant);
    let account = account_of(user);
    let totp = build(&secret, &issuer, &account)?;
    let otpauth_uri = totp
        .to_url()
        .map_err(|e| AppError::Internal(format!("otpauth url: {e}")))?;
    Ok(Enrolment {
        secret,
        otpauth_uri,
        issuer,
        account,
        digits: DIGITS,
        period: PERIOD_SECS,
    })
}

/// Prove the pending enrolment with a code. `Ok(None)` is a wrong code (the
/// enrolment stays pending); success stores the factor, issues a fresh set
/// of recovery codes and returns them, the only time they are readable.
pub async fn confirm_enrolment(
    state: &AppState,
    tenant: &Tenant,
    flow_id: Uuid,
    user: &User,
    code: &str,
    label: Option<&str>,
) -> AppResult<Option<Vec<String>>> {
    let key = keys::totp_enrolment(tenant.id, flow_id);
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = conn.get(&key).await?;
    let Some(raw) = raw else {
        return Err(AppError::BadRequest(
            "no authenticator enrolment is pending".into(),
        ));
    };
    let pending: PendingEnrolment = serde_json::from_str(&raw)?;
    let totp = build(&pending.secret, &issuer_of(tenant), &account_of(user))?;
    let Some(step) = totp.check_current(code.trim()) else {
        return Ok(None);
    };
    let id = Uuid::now_v7();
    let enc = encrypt(
        state,
        tenant.id,
        id,
        &TotpData {
            secret: pending.secret,
            digits: DIGITS,
            period: PERIOD_SECS,
        },
    )
    .await?;
    let label = label
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| l.chars().take(80).collect::<String>())
        .unwrap_or_else(|| DEFAULT_LABEL.to_string());
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    repos::credentials::insert(
        &mut *tx,
        tenant.id,
        repos::credentials::NewCredential {
            id,
            user_id: user.id,
            kind: KIND_TOTP,
            label: Some(&label),
            data_enc: &enc.to_bytes(),
            key_version: enc.key_version as i32,
            external_id: None,
        },
    )
    .await?;
    tx.commit().await?;
    // The proving code has been spent: it cannot double as the sign-in code.
    let _ = mark_step_used(state, tenant.id, id, step).await?;
    let _: () = conn.del(&key).await?;
    let codes = regenerate_recovery_codes(state, tenant.id, user.id).await?;
    state.events.publish(Event::new(
        Some(tenant.id),
        Actor::User { id: user.id },
        EventKind::MfaChanged {
            user_id: user.id,
            change: "TOTP enrolled".into(),
        },
    ));
    notifications::mfa_changed(state, tenant.id, user.id, "An authenticator app was added").await;
    Ok(Some(codes))
}

fn random_code() -> String {
    let mut bytes = [0u8; RECOVERY_CODE_LEN];
    rand::fill(&mut bytes);
    let raw: String = bytes
        .iter()
        .map(|b| RECOVERY_ALPHABET[(*b % 32) as usize] as char)
        .collect();
    format!("{}-{}", &raw[..5], &raw[5..])
}

/// Normalise a typed recovery code: case, separators and whitespace are free.
fn normalise_recovery(code: &str) -> String {
    code.trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

/// Replace the user's recovery codes with a new set; returns the plaintexts.
pub async fn regenerate_recovery_codes(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<String>> {
    let codes: Vec<String> = (0..RECOVERY_CODE_COUNT).map(|_| random_code()).collect();
    let data = RecoveryData {
        codes: codes
            .iter()
            .map(|c| RecoveryCode {
                hash: hash(&normalise_recovery(c)),
                used_at: None,
            })
            .collect(),
    };
    let id = Uuid::now_v7();
    let enc = encrypt(state, tenant_id, id, &data).await?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    repos::credentials::delete_of_type(&mut *tx, tenant_id, user_id, KIND_RECOVERY).await?;
    repos::credentials::insert(
        &mut *tx,
        tenant_id,
        repos::credentials::NewCredential {
            id,
            user_id,
            kind: KIND_RECOVERY,
            label: Some("Recovery codes"),
            data_enc: &enc.to_bytes(),
            key_version: enc.key_version as i32,
            external_id: None,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(codes)
}

/// Delete one of the user's credentials (with `second_factors_only`, only a
/// second factor). Removing the last second factor takes the recovery codes
/// with it: there is nothing left for them to recover. The account console
/// and the admin API both remove factors through here. Returns the removed
/// credential's kind, `None` when there is no such credential.
pub async fn remove_credential(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    credential_id: Uuid,
    second_factors_only: bool,
) -> AppResult<Option<String>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::credentials::list_for_user(&mut *tx, tenant_id, user_id).await?;
    let Some(row) = rows.iter().find(|c| c.id == credential_id) else {
        return Ok(None);
    };
    let second_factor = SECOND_FACTOR_KINDS.contains(&row.kind.as_str());
    if second_factors_only && !second_factor {
        return Ok(None);
    }
    repos::credentials::delete(&mut *tx, tenant_id, user_id, credential_id).await?;
    let others = rows
        .iter()
        .filter(|c| c.id != credential_id && SECOND_FACTOR_KINDS.contains(&c.kind.as_str()))
        .count();
    if second_factor && others == 0 {
        repos::credentials::delete_of_type(&mut *tx, tenant_id, user_id, KIND_RECOVERY).await?;
    }
    tx.commit().await?;
    Ok(Some(row.kind.clone()))
}

/// Does the user hold any second factor (TOTP or passkey)?
pub async fn has_second_factor(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<bool> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let n = repos::credentials::count_of_types(&mut *tx, tenant_id, user_id, SECOND_FACTOR_KINDS)
        .await?;
    tx.commit().await?;
    Ok(n > 0)
}

/// The user's second factors, for the UI.
pub async fn factors_of(state: &AppState, tenant_id: Uuid, user_id: Uuid) -> AppResult<Factors> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::credentials::list_for_user(&mut *tx, tenant_id, user_id).await?;
    let recovery =
        repos::credentials::list_secrets_of_type(&mut *tx, tenant_id, user_id, KIND_RECOVERY)
            .await?;
    tx.commit().await?;
    let has = |kind: &str| rows.iter().any(|c| c.kind == kind);
    let mut recovery_codes = 0;
    for row in recovery {
        let data: RecoveryData = decrypt(state, tenant_id, row.id, &row.data_enc).await?;
        recovery_codes += data.codes.iter().filter(|c| c.used_at.is_none()).count();
    }
    Ok(Factors {
        totp: has(KIND_TOTP),
        webauthn: has(passkeys::KIND),
        email_otp: has(otp_factors::KIND_EMAIL),
        sms_otp: has(otp_factors::KIND_SMS),
        recovery_codes,
    })
}

/// Claim a time step for the credential; `false` when it was already used.
async fn mark_step_used(
    state: &AppState,
    tenant_id: Uuid,
    credential_id: Uuid,
    step: u64,
) -> AppResult<bool> {
    let mut conn = state.redis.get().await?;
    let ttl = PERIOD_SECS * (2 * u64::from(SKEW) + 1);
    let set: Option<String> = redis::cmd("SET")
        .arg(keys::totp_used_step(tenant_id, credential_id, step))
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(ttl)
        .query_async(&mut conn)
        .await?;
    Ok(set.is_some())
}

/// Check a second-factor code: six digits are tried against the user's
/// authenticator apps, anything else as a recovery code. `Ok(None)` means
/// the code is wrong, replayed or spent.
pub async fn verify(
    state: &AppState,
    tenant: &Tenant,
    user: &User,
    code: &str,
) -> AppResult<Option<Verified>> {
    let trimmed = code.trim();
    if trimmed.len() == usize::from(DIGITS) && trimmed.bytes().all(|b| b.is_ascii_digit()) {
        verify_totp(state, tenant, user, trimmed).await
    } else {
        verify_recovery(state, tenant, user, trimmed).await
    }
}

async fn verify_totp(
    state: &AppState,
    tenant: &Tenant,
    user: &User,
    code: &str,
) -> AppResult<Option<Verified>> {
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    let rows =
        repos::credentials::list_secrets_of_type(&mut *tx, tenant.id, user.id, KIND_TOTP).await?;
    tx.commit().await?;
    let issuer = issuer_of(tenant);
    let account = account_of(user);
    for row in rows {
        let data: TotpData = decrypt(state, tenant.id, row.id, &row.data_enc).await?;
        let totp = build(&data.secret, &issuer, &account)?;
        let Some(step) = totp.check_current(code) else {
            continue;
        };
        if !mark_step_used(state, tenant.id, row.id, step).await? {
            return Ok(None);
        }
        let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
        repos::credentials::touch_last_used(&mut *tx, tenant.id, row.id).await?;
        tx.commit().await?;
        return Ok(Some(Verified::Totp {
            credential_id: row.id,
        }));
    }
    Ok(None)
}

async fn verify_recovery(
    state: &AppState,
    tenant: &Tenant,
    user: &User,
    code: &str,
) -> AppResult<Option<Verified>> {
    let normalised = normalise_recovery(code);
    if normalised.len() != RECOVERY_CODE_LEN {
        return Ok(None);
    }
    let wanted = hash(&normalised);
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    let rows =
        repos::credentials::list_secrets_of_type(&mut *tx, tenant.id, user.id, KIND_RECOVERY)
            .await?;
    tx.commit().await?;
    for row in rows {
        let mut data: RecoveryData = decrypt(state, tenant.id, row.id, &row.data_enc).await?;
        // Every code is compared so timing does not reveal the position of a match.
        let mut hit = None;
        for (i, c) in data.codes.iter().enumerate() {
            let same = bool::from(c.hash.as_bytes().ct_eq(wanted.as_bytes()));
            if same && c.used_at.is_none() {
                hit = Some(i);
            }
        }
        let Some(i) = hit else {
            continue;
        };
        data.codes[i].used_at = Some(Utc::now());
        let remaining = data.codes.iter().filter(|c| c.used_at.is_none()).count();
        let enc = encrypt(state, tenant.id, row.id, &data).await?;
        let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
        repos::credentials::update_data(
            &mut *tx,
            tenant.id,
            row.id,
            &enc.to_bytes(),
            enc.key_version as i32,
        )
        .await?;
        tx.commit().await?;
        state.events.publish(Event::new(
            Some(tenant.id),
            Actor::User { id: user.id },
            EventKind::MfaChanged {
                user_id: user.id,
                change: format!("recovery code used, {remaining} left"),
            },
        ));
        notifications::mfa_changed(
            state,
            tenant.id,
            user.id,
            &format!("A recovery code was used to sign in; {remaining} remain"),
        )
        .await;
        return Ok(Some(Verified::RecoveryCode { remaining }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_codes_are_well_formed_and_normalise() {
        let c = random_code();
        assert_eq!(c.len(), RECOVERY_CODE_LEN + 1);
        assert_eq!(c.as_bytes()[5], b'-');
        assert!(
            c.bytes()
                .filter(|b| *b != b'-')
                .all(|b| RECOVERY_ALPHABET.contains(&b))
        );
        let upper = c.to_uppercase().replace('-', " ");
        assert_eq!(normalise_recovery(&upper), normalise_recovery(&c));
        assert_eq!(normalise_recovery(&c).len(), RECOVERY_CODE_LEN);
    }

    #[test]
    fn labels_never_carry_a_colon() {
        assert_eq!(label_safe("Acme: Corp", "x"), "Acme  Corp");
        assert_eq!(label_safe("  ", "fallback"), "fallback");
    }

    #[test]
    fn a_generated_secret_round_trips_through_the_otpauth_uri() {
        let secret = Secret::generate().to_base32();
        let totp = build(&secret, "Acme", "alice@example.com").unwrap();
        let url = totp.to_url().unwrap();
        assert!(url.starts_with("otpauth://totp/Acme:alice%40example.com?"));
        let parsed = Totp::from_url(&url).unwrap();
        assert_eq!(parsed.secret().to_base32(), secret);
        let code = totp.generate_current().to_string();
        assert_eq!(code.len(), 6);
        assert!(parsed.check_current(&code).is_some());
    }
}
