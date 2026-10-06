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
use ridm_core::crypto::Sha256;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
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

fn build(secret_b32: &str, issuer: &str, account: &str) -> AppResult<Authenticator> {
    let secret = base32_decode(secret_b32)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Internal("totp secret: not base32".into()))?;
    Ok(Authenticator {
        secret,
        issuer: issuer.to_string(),
        account: account.to_string(),
    })
}

/// A fresh secret: 20 random bytes (160 bits, RFC 4226's recommendation) as
/// base32, the form authenticator apps take.
fn new_secret() -> String {
    base32_encode(&ridm_core::crypto::random_bytes::<20>())
}

/// One authenticator: RFC 6238 TOTP with HMAC-SHA-1, [`DIGITS`] digits and
/// [`PERIOD_SECS`]-second steps (the defaults every authenticator app
/// supports), computed with aws-lc-rs.
struct Authenticator {
    secret: Vec<u8>,
    issuer: String,
    account: String,
}

impl Authenticator {
    /// RFC 4226 HOTP for time step `counter`, as a zero-padded string.
    fn code_at(&self, counter: u64) -> String {
        let mac = ridm_core::crypto::hmac(
            ridm_core::crypto::HMAC_SHA1,
            &self.secret,
            &counter.to_be_bytes(),
        );
        // Dynamic truncation (RFC 4226 §5.3).
        let offset = usize::from(mac[mac.len() - 1] & 0x0f);
        let bin = u32::from_be_bytes([
            mac[offset],
            mac[offset + 1],
            mac[offset + 2],
            mac[offset + 3],
        ]) & 0x7fff_ffff;
        let code = bin % 10u32.pow(u32::from(DIGITS));
        format!("{code:0width$}", width = usize::from(DIGITS))
    }

    /// The time step `code` is valid for at `now` (Unix seconds), allowing
    /// [`SKEW`] steps of drift either side, or `None`.
    fn check(&self, code: &str, now: u64) -> Option<u64> {
        if code.len() != usize::from(DIGITS) || !code.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let origin = now / PERIOD_SECS;
        let skew = u64::from(SKEW);
        (origin.saturating_sub(skew)..=origin + skew)
            .find(|&counter| bool::from(self.code_at(counter).as_bytes().ct_eq(code.as_bytes())))
    }

    fn check_current(&self, code: &str) -> Option<u64> {
        self.check(code, Utc::now().timestamp().max(0) as u64)
    }

    /// The `otpauth://` URI authenticator apps scan (the Key Uri Format).
    fn to_url(&self) -> String {
        let issuer = percent_encode(&self.issuer);
        format!(
            "otpauth://totp/{issuer}:{}?secret={}&issuer={issuer}",
            percent_encode(&self.account),
            base32_encode(&self.secret),
        )
    }
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32, upper case, without padding.
fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(BASE32[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(BASE32[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// RFC 4648 base32 in either case, with or without `=` padding.
fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let v = BASE32.iter().position(|&a| a == c.to_ascii_uppercase())? as u32;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

/// Percent-encode everything but letters, digits and `-_.~`.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
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
    let fresh = new_secret();
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
    let otpauth_uri = totp.to_url();
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
    ridm_core::crypto::fill(&mut bytes);
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

/// Every credential the user holds (public views).
pub async fn credentials_of(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<crate::models::Credential>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows = repos::credentials::list_for_user(&mut *tx, tenant_id, user_id).await?;
    tx.commit().await?;
    Ok(rows)
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
        let secret = new_secret();
        assert_eq!(secret.len(), 32);
        let totp = build(&secret, "Acme", "alice@example.com").unwrap();
        assert_eq!(
            totp.to_url(),
            format!("otpauth://totp/Acme:alice%40example.com?secret={secret}&issuer=Acme")
        );
        let now = Utc::now().timestamp() as u64;
        let code = totp.code_at(now / PERIOD_SECS);
        assert_eq!(code.len(), 6);
        assert_eq!(totp.check_current(&code), Some(now / PERIOD_SECS));
    }

    /// RFC 6238 appendix B, SHA-1, truncated to six digits.
    #[test]
    fn codes_match_the_rfc_6238_test_vectors() {
        let totp = build(&base32_encode(b"12345678901234567890"), "i", "a").unwrap();
        for (time, code) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(totp.code_at(time / PERIOD_SECS), code, "T = {time}");
            assert_eq!(totp.check(code, time), Some(time / PERIOD_SECS));
        }
    }

    #[test]
    fn one_step_of_drift_is_accepted_and_two_are_not() {
        let totp = build(&new_secret(), "i", "a").unwrap();
        let now = 1_700_000_000;
        let step = now / PERIOD_SECS;
        assert_eq!(totp.check(&totp.code_at(step - 1), now), Some(step - 1));
        assert_eq!(totp.check(&totp.code_at(step + 1), now), Some(step + 1));
        assert_eq!(totp.check(&totp.code_at(step + 2), now), None);
        assert_eq!(totp.check("12345", now), None);
        assert_eq!(totp.check("+12345", now), None);
    }

    #[test]
    fn base32_matches_rfc_4648_and_reads_what_totp_rs_wrote() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("MZXW6YTBOI======").unwrap(), b"foobar");
        assert_eq!(base32_decode("mzxw6ytboi").unwrap(), b"foobar");
        assert!(base32_decode("not base32!").is_none());
        // A secret as totp-rs 6 stored it.
        let stored = "OBWGC2LOFVZXI4TJNZTS243FMNZGK5BNGEZDG";
        assert_eq!(base32_decode(stored).unwrap(), b"plain-string-secret-123");
        assert_eq!(base32_encode(b"plain-string-secret-123"), stored);
    }
}
