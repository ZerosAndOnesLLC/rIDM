//! Password hashing, verification, policy, history and transparent upgrades.
//!
//! New hashes are always argon2id. Verification also accepts the following
//! legacy formats so that users imported from other systems keep working; a
//! successful verification against any of them (or against argon2id with
//! weaker-than-configured parameters) replaces the stored hash with a fresh
//! argon2id hash.
//!
//! | Format | Example |
//! |--------|---------|
//! | argon2id PHC | `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>` (also `$argon2i$`, `$argon2d$`, upgraded) |
//! | bcrypt | `$2b$12$...` (also `$2a$`, `$2y$`) |
//! | PBKDF2 PHC (passlib) | `$pbkdf2-sha256$29000$<salt b64>$<hash b64>` (`-sha512` too) |
//! | PBKDF2 Django | `pbkdf2_sha256$600000$<salt>$<hash b64>` |
//! | salted SHA | `$sha256$<salt>$<hex of sha256(salt ‖ password)>` (`$sha512$` too) |
//! | unsalted SHA | `$sha256$<hex>` (`$sha512$` too) |
//! | MD5 | `$md5$<hex>` or `$md5$<salt>$<hex of md5(salt ‖ password)>` (migration only) |
//!
//! Hashing is CPU-bound; the service runs it on the blocking pool.

use std::sync::Arc;

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher as _, PasswordVerifier as _};
use argon2::{Algorithm, Argon2, Params, Version};
use chrono::{Duration, Utc};
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use ridm_core::providers::{PasswordHasher, PasswordVerification, ProviderError};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::Argon2Params;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{PasswordPolicy, User};
use crate::repos;
use crate::state::AppState;

pub const ALGO_ARGON2ID: &str = "argon2id";

// ---------------------------------------------------------------------------
// Hasher
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Argon2Hasher {
    params: Argon2Params,
}

impl Argon2Hasher {
    pub fn new(params: Argon2Params) -> Self {
        Self { params }
    }

    fn argon2(&self) -> Result<Argon2<'static>, ProviderError> {
        let params = Params::new(
            self.params.m_cost,
            self.params.t_cost,
            self.params.p_cost,
            None,
        )
        .map_err(ProviderError::configuration)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    fn verify_argon2(
        &self,
        password: &[u8],
        stored: &str,
    ) -> Result<PasswordVerification, ProviderError> {
        let parsed = PasswordHash::new(stored).map_err(ProviderError::rejected)?;
        let valid = match self.argon2()?.verify_password(password, &parsed) {
            Ok(()) => true,
            Err(argon2::password_hash::Error::PasswordInvalid) => false,
            Err(e) => return Err(ProviderError::rejected(e)),
        };
        // Upgrade if the stored parameters are weaker than configured, or not argon2id.
        let param = |name: &str| -> Option<u32> {
            parsed
                .params
                .get_str(name)
                .and_then(|v| v.parse::<u32>().ok())
        };
        let weaker = parsed.algorithm.as_str() != "argon2id"
            || param("m").is_none_or(|m| m < self.params.m_cost)
            || param("t").is_none_or(|t| t < self.params.t_cost)
            || param("p").is_none_or(|p| p < self.params.p_cost);
        Ok(PasswordVerification {
            valid,
            needs_rehash: valid && weaker,
        })
    }
}

impl PasswordHasher for Argon2Hasher {
    fn algorithm(&self) -> &'static str {
        ALGO_ARGON2ID
    }

    fn hash(&self, password: &Zeroizing<String>) -> Result<String, ProviderError> {
        self.argon2()?
            .hash_password(password.as_bytes())
            .map(|h| h.to_string())
            .map_err(ProviderError::rejected)
    }

    fn verify(
        &self,
        password: &Zeroizing<String>,
        stored_hash: &str,
    ) -> Result<PasswordVerification, ProviderError> {
        let pw = password.as_bytes();
        if stored_hash.starts_with("$argon2") {
            return self.verify_argon2(pw, stored_hash);
        }
        let valid = legacy::verify(pw, stored_hash)?;
        Ok(PasswordVerification {
            valid,
            needs_rehash: valid,
        })
    }
}

/// Verifiers for hashes produced by other systems.
pub mod legacy {
    use super::*;

    /// Identifier for `users.password_algo` derived from a stored hash.
    pub fn algorithm_of(stored: &str) -> &'static str {
        if stored.starts_with("$argon2id$") {
            ALGO_ARGON2ID
        } else if stored.starts_with("$argon2i$") {
            "argon2i"
        } else if stored.starts_with("$argon2d$") {
            "argon2d"
        } else if stored.starts_with("$2a$")
            || stored.starts_with("$2b$")
            || stored.starts_with("$2y$")
        {
            "bcrypt"
        } else if stored.starts_with("$pbkdf2-sha256$") || stored.starts_with("pbkdf2_sha256$") {
            "pbkdf2-sha256"
        } else if stored.starts_with("$pbkdf2-sha512$") || stored.starts_with("pbkdf2_sha512$") {
            "pbkdf2-sha512"
        } else if stored.starts_with("$sha256$") {
            "sha256"
        } else if stored.starts_with("$sha512$") {
            "sha512"
        } else if stored.starts_with("$md5$") {
            "md5"
        } else {
            "unknown"
        }
    }

    pub fn verify(password: &[u8], stored: &str) -> Result<bool, ProviderError> {
        if stored.starts_with("$2a$") || stored.starts_with("$2b$") || stored.starts_with("$2y$") {
            return bcrypt::verify(password, stored).map_err(ProviderError::rejected);
        }
        if let Some(rest) = stored.strip_prefix("$pbkdf2-sha256$") {
            return pbkdf2_phc(password, rest, pbkdf2::pbkdf2_hmac::<sha2::Sha256>);
        }
        if let Some(rest) = stored.strip_prefix("$pbkdf2-sha512$") {
            return pbkdf2_phc(password, rest, pbkdf2::pbkdf2_hmac::<sha2::Sha512>);
        }
        if let Some(rest) = stored.strip_prefix("pbkdf2_sha256$") {
            return pbkdf2_django(password, rest, pbkdf2::pbkdf2_hmac::<sha2::Sha256>);
        }
        if let Some(rest) = stored.strip_prefix("pbkdf2_sha512$") {
            return pbkdf2_django(password, rest, pbkdf2::pbkdf2_hmac::<sha2::Sha512>);
        }
        if let Some(rest) = stored.strip_prefix("$sha256$") {
            return salted_digest::<sha2::Sha256>(password, rest);
        }
        if let Some(rest) = stored.strip_prefix("$sha512$") {
            return salted_digest::<sha2::Sha512>(password, rest);
        }
        if let Some(rest) = stored.strip_prefix("$md5$") {
            return salted_digest::<md5::Md5>(password, rest);
        }
        Err(ProviderError::Rejected(
            "unsupported password hash format".into(),
        ))
    }

    fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len() && a.ct_eq(b).into()
    }

    fn decode_b64(s: &str) -> Option<Vec<u8>> {
        use base64::Engine as _;
        use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
        // passlib "ab64" uses `.` where standard base64 uses `+`.
        let normalized = s.replace('.', "+");
        STANDARD
            .decode(s)
            .or_else(|_| STANDARD_NO_PAD.decode(s))
            .or_else(|_| URL_SAFE_NO_PAD.decode(s))
            .or_else(|_| STANDARD_NO_PAD.decode(&normalized))
            .ok()
    }

    /// PBKDF2 derivation function: (password, salt, rounds, out).
    type Pbkdf2Fn = fn(&[u8], &[u8], u32, &mut [u8]);

    /// `<rounds>$<salt b64>$<hash b64>`
    fn pbkdf2_phc(password: &[u8], rest: &str, derive: Pbkdf2Fn) -> Result<bool, ProviderError> {
        let mut parts = rest.splitn(3, '$');
        let (Some(rounds), Some(salt), Some(hash)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(ProviderError::Rejected("malformed pbkdf2 hash".into()));
        };
        let rounds: u32 = rounds
            .parse()
            .map_err(|_| ProviderError::Rejected("malformed pbkdf2 rounds".into()))?;
        let salt = decode_b64(salt)
            .ok_or_else(|| ProviderError::Rejected("malformed pbkdf2 salt".into()))?;
        let expected = decode_b64(hash)
            .ok_or_else(|| ProviderError::Rejected("malformed pbkdf2 hash".into()))?;
        pbkdf2_check(password, &salt, rounds, &expected, derive)
    }

    /// Django: `<iterations>$<salt string>$<hash b64>` where the salt is used as raw ASCII.
    fn pbkdf2_django(password: &[u8], rest: &str, derive: Pbkdf2Fn) -> Result<bool, ProviderError> {
        let mut parts = rest.splitn(3, '$');
        let (Some(rounds), Some(salt), Some(hash)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(ProviderError::Rejected("malformed pbkdf2 hash".into()));
        };
        let rounds: u32 = rounds
            .parse()
            .map_err(|_| ProviderError::Rejected("malformed pbkdf2 rounds".into()))?;
        let expected = decode_b64(hash)
            .ok_or_else(|| ProviderError::Rejected("malformed pbkdf2 hash".into()))?;
        pbkdf2_check(password, salt.as_bytes(), rounds, &expected, derive)
    }

    /// The most iterations a legacy hash may ask for.
    ///
    /// The count comes from the hash itself, so an imported (or crafted) one
    /// decides how much work every verification of that account costs, and
    /// PBKDF2-SHA512 at ten million rounds takes about 25 seconds of CPU —
    /// enough for one sign-in attempt to hold a worker hostage. A million is
    /// well above what the corpora rIDM imports from use (Django's own
    /// default is 720k, Keycloak's 210k) and is bounded at roughly two and a
    /// half seconds. Found by the `jwt_decode` fuzz target, which feeds the
    /// legacy verifier its own input.
    const MAX_PBKDF2_ROUNDS: u32 = 1_000_000;

    fn pbkdf2_check(
        password: &[u8],
        salt: &[u8],
        rounds: u32,
        expected: &[u8],
        derive: Pbkdf2Fn,
    ) -> Result<bool, ProviderError> {
        if rounds == 0 || rounds > MAX_PBKDF2_ROUNDS || expected.is_empty() || expected.len() > 512
        {
            return Err(ProviderError::Rejected(
                "pbkdf2 parameters out of range".into(),
            ));
        }
        let mut out = vec![0u8; expected.len()];
        derive(password, salt, rounds, &mut out);
        Ok(ct_eq(&out, expected))
    }

    /// `<salt>$<hex>` (hash = D(salt ‖ password)) or `<hex>` (unsalted).
    fn salted_digest<D: sha2::Digest>(password: &[u8], rest: &str) -> Result<bool, ProviderError> {
        let (salt, hex_hash) = match rest.rsplit_once('$') {
            Some((salt, h)) => (salt.as_bytes(), h),
            None => (&b""[..], rest),
        };
        let expected = hex::decode(hex_hash)
            .map_err(|_| ProviderError::Rejected("malformed hex digest".into()))?;
        let mut d = D::new();
        d.update(salt);
        d.update(password);
        Ok(ct_eq(&d.finalize(), &expected))
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// Check a candidate password against the tenant policy. Returns every
/// violated rule so the UI can show all of them at once.
pub fn check_policy(policy: &PasswordPolicy, password: &str, user: Option<&User>) -> Vec<String> {
    let mut problems = vec![];
    let len = password.chars().count() as u32;
    if len < policy.min_length {
        problems.push(format!("must be at least {} characters", policy.min_length));
    }
    if len > policy.max_length {
        problems.push(format!("must be at most {} characters", policy.max_length));
    }
    if policy.require_uppercase && !password.chars().any(char::is_uppercase) {
        problems.push("must contain an uppercase letter".into());
    }
    if policy.require_lowercase && !password.chars().any(char::is_lowercase) {
        problems.push("must contain a lowercase letter".into());
    }
    if policy.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
        problems.push("must contain a digit".into());
    }
    if policy.require_symbol
        && !password
            .chars()
            .any(|c| !c.is_alphanumeric() && !c.is_whitespace())
    {
        problems.push("must contain a symbol".into());
    }
    if let Some(u) = user {
        let lower = password.to_lowercase();
        if lower.contains(&u.username.to_lowercase()) && u.username.len() >= 4 {
            problems.push("must not contain the username".into());
        }
        if let Some(local) = u.email.as_deref().and_then(|e| e.split('@').next())
            && local.len() >= 4
            && lower.contains(&local.to_lowercase())
        {
            problems.push("must not contain the email address".into());
        }
    }
    problems
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default)]
pub struct SetPasswordOptions {
    /// Force a change at next login (temporary passwords).
    pub must_change: bool,
    /// Skip policy and history checks (admin override, imports).
    pub skip_policy: bool,
    /// The user changed their own password (affects the emitted event).
    pub by_user: bool,
    /// Tell the user by email (not for initial passwords set at registration).
    pub notify: bool,
}

async fn hash_blocking(
    hasher: Arc<dyn PasswordHasher>,
    password: Zeroizing<String>,
) -> AppResult<String> {
    tokio::task::spawn_blocking(move || hasher.hash(&password))
        .await
        .map_err(|e| AppError::Internal(format!("hash task failed: {e}")))?
        .map_err(|e| AppError::Internal(format!("hashing failed: {e}")))
}

async fn verify_blocking(
    hasher: Arc<dyn PasswordHasher>,
    password: Zeroizing<String>,
    stored: String,
) -> AppResult<PasswordVerification> {
    tokio::task::spawn_blocking(move || hasher.verify(&password, &stored))
        .await
        .map_err(|e| AppError::Internal(format!("verify task failed: {e}")))?
        .map_err(|e| match e {
            // Malformed / unsupported stored hash: treat as a failed login, but log it.
            ProviderError::Rejected(msg) => {
                tracing::warn!(error = %msg, "stored password hash could not be verified");
                AppError::Unauthorized
            }
            other => AppError::Internal(format!("verification failed: {other}")),
        })
}

/// Refuse a password known from breach corpora. The lookup failing (the
/// deployment cannot reach the corpus) is logged and lets the password
/// through: an outage must not block sign-ups and resets.
pub(crate) async fn check_breached(
    state: &AppState,
    tenant_id: Uuid,
    password: &str,
) -> AppResult<()> {
    let Some(checker) = &state.breach else {
        tracing::debug!(%tenant_id, "breached-password check requested but disabled for this deployment");
        return Ok(());
    };
    let sha1 = ridm_core::providers::password_sha1_hex(password);
    match checker.count(&sha1).await {
        Ok(0) => Ok(()),
        Ok(n) => {
            tracing::info!(%tenant_id, occurrences = n, "breached password refused");
            Err(AppError::Validation(vec![crate::error::FieldError {
                field: "password".into(),
                message: "has appeared in a data breach; choose a different one".into(),
            }]))
        }
        Err(e) => {
            tracing::warn!(%tenant_id, error = %e, "breached-password check unavailable; password accepted unchecked");
            Ok(())
        }
    }
}

/// Set a user's password, enforcing the tenant policy and reuse history.
pub async fn set_password(
    state: &AppState,
    tenant_id: Uuid,
    policy: &PasswordPolicy,
    actor: Actor,
    user_id: Uuid,
    password: Zeroizing<String>,
    opts: SetPasswordOptions,
) -> AppResult<()> {
    // A directory user's password lives in the directory (written there
    // when it is writable, refused when it is read-only).
    if crate::services::ldap::set_password(
        state, tenant_id, policy, &actor, user_id, &password, opts,
    )
    .await?
    {
        return Ok(());
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let user = repos::users::find_by_id(&mut *tx, tenant_id, user_id)
        .await?
        .filter(|u| u.deleted_at.is_none())
        .ok_or(AppError::NotFound("user"))?;

    if !opts.skip_policy {
        let problems = check_policy(policy, &password, Some(&user));
        if !problems.is_empty() {
            return Err(AppError::Validation(
                problems
                    .into_iter()
                    .map(|message| crate::error::FieldError {
                        field: "password".into(),
                        message,
                    })
                    .collect(),
            ));
        }
        if policy.check_breached {
            check_breached(state, tenant_id, &password).await?;
        }
        // "history N" = the last N passwords including the current one.
        if policy.history > 0 {
            let mut previous = repos::password_history::recent(
                &mut *tx,
                tenant_id,
                user_id,
                i64::from(policy.history - 1),
            )
            .await?;
            if let Some(current) = &user.password_hash {
                previous.push(current.clone());
            }
            for old in previous {
                let v = verify_blocking(state.hasher.clone(), password.clone(), old).await;
                if matches!(v, Ok(PasswordVerification { valid: true, .. })) {
                    return Err(AppError::Validation(vec![crate::error::FieldError {
                        field: "password".into(),
                        message: format!("must differ from the last {} passwords", policy.history),
                    }]));
                }
            }
        }
    }

    let hash = hash_blocking(state.hasher.clone(), password).await?;
    let expires_at = policy
        .max_age_days
        .map(|days| Utc::now() + Duration::days(i64::from(days)));

    if let Some(old) = &user.password_hash
        && policy.history > 1
    {
        repos::password_history::insert(&mut *tx, tenant_id, user_id, old).await?;
        repos::password_history::trim(&mut *tx, tenant_id, user_id, i64::from(policy.history - 1))
            .await?;
    }
    repos::users::set_password(
        &mut *tx,
        tenant_id,
        user_id,
        &hash,
        state.hasher.algorithm(),
        opts.must_change,
        expires_at,
    )
    .await?;
    tx.commit().await?;

    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::PasswordChanged {
            user_id,
            by_user: opts.by_user,
        },
    ));
    if opts.notify {
        crate::services::notifications::password_changed(state, tenant_id, user_id).await;
    }
    Ok(())
}

/// Generate a random temporary password, set it with `must_change`, and
/// return it once (admin "reset password" / "set temporary password").
pub async fn set_temporary_password(
    state: &AppState,
    tenant_id: Uuid,
    policy: &PasswordPolicy,
    actor: Actor,
    user_id: Uuid,
) -> AppResult<Zeroizing<String>> {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut bytes = [0u8; 24];
    rand::fill(&mut bytes);
    let temp: String = bytes
        .iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect();
    let temp = Zeroizing::new(format!("{}-{}-{}", &temp[..8], &temp[8..16], &temp[16..]));
    set_password(
        state,
        tenant_id,
        policy,
        actor,
        user_id,
        temp.clone(),
        SetPasswordOptions {
            must_change: true,
            // Random 24-character passwords satisfy any sane policy; history is irrelevant.
            skip_policy: true,
            by_user: false,
            notify: false,
        },
    )
    .await?;
    Ok(temp)
}

/// Import a hash produced elsewhere (bulk migration). No policy checks; the
/// algorithm is derived from the hash format and upgraded on first login.
pub async fn import_hash(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    stored_hash: &str,
) -> AppResult<()> {
    let algo = legacy::algorithm_of(stored_hash);
    if algo == "unknown" {
        return Err(AppError::BadRequest(
            "unsupported password hash format".into(),
        ));
    }
    // A local hash would outrank the directory at sign-in.
    if crate::services::ldap::directory_of_user(state, tenant_id, user_id)
        .await?
        .is_some()
    {
        return Err(AppError::BadRequest(
            "the user's password is managed by a directory".into(),
        ));
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let ok =
        repos::users::set_password(&mut *tx, tenant_id, user_id, stored_hash, algo, false, None)
            .await?;
    tx.commit().await?;
    if !ok {
        return Err(AppError::NotFound("user"));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Correct password.
    Valid {
        /// The policy requires a change before the session may continue.
        must_change: bool,
    },
    /// Wrong password (or the user has none).
    Invalid,
}

/// Verify a password for login. On success, legacy or weaker hashes are
/// replaced with a fresh argon2id hash (transparent upgrade). Lockout and
/// attempt counting are handled by the login flow, not here.
pub async fn verify_and_upgrade(
    state: &AppState,
    tenant_id: Uuid,
    policy: &PasswordPolicy,
    user: &User,
    password: Zeroizing<String>,
) -> AppResult<VerifyOutcome> {
    let Some(stored) = user.password_hash.clone() else {
        // A directory user has no local hash: the directory decides, by a
        // bind as their entry.
        if let Some(valid) =
            crate::services::ldap::verify_password(state, tenant_id, user, &password).await?
        {
            return Ok(if valid {
                VerifyOutcome::Valid {
                    must_change: user.must_change_password,
                }
            } else {
                VerifyOutcome::Invalid
            });
        }
        // Burn comparable time so "no password" is not distinguishable by timing.
        let _ = verify_blocking(state.hasher.clone(), password, DUMMY_HASH.to_string()).await;
        return Ok(VerifyOutcome::Invalid);
    };

    let verification = match verify_blocking(state.hasher.clone(), password.clone(), stored).await {
        Ok(v) => v,
        Err(AppError::Unauthorized) => return Ok(VerifyOutcome::Invalid),
        Err(e) => return Err(e),
    };
    if !verification.valid {
        return Ok(VerifyOutcome::Invalid);
    }

    if verification.needs_rehash {
        let from_algo = user
            .password_algo
            .clone()
            .unwrap_or_else(|| "unknown".into());
        let hash = hash_blocking(state.hasher.clone(), password).await?;
        let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
        // Keep must_change and expiry as they were: this is not a user-initiated change.
        sqlx::query(
            "UPDATE users SET password_hash = $3, password_algo = $4, updated_at = now() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(user.id)
        .bind(&hash)
        .bind(state.hasher.algorithm())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        state.events.publish(Event::new(
            Some(tenant_id),
            Actor::System,
            EventKind::PasswordHashUpgraded {
                user_id: user.id,
                from_algo,
            },
        ));
    }

    let expired = user.password_expires_at.is_some_and(|t| t <= Utc::now())
        || policy.max_age_days.is_some_and(|days| {
            user.password_changed_at
                .is_some_and(|changed| changed + Duration::days(i64::from(days)) <= Utc::now())
        });
    Ok(VerifyOutcome::Valid {
        must_change: user.must_change_password || expired,
    })
}

/// A valid argon2id hash of an unguessable value, used to equalize timing when
/// a user has no password.
const DUMMY_HASH: &str = "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$Q2Y4c4mT4xN2sGmC1UkVwb8kk4z5j7nKqXhFq7d1e6A";

#[cfg(test)]
mod tests {
    use sha2::Digest as _;

    use super::*;

    fn hasher() -> Argon2Hasher {
        Argon2Hasher::new(Argon2Params {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        })
    }

    fn pw(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    #[test]
    fn argon2_round_trip_and_param_upgrade() {
        let h = hasher();
        let stored = h.hash(&pw("correct horse")).unwrap();
        assert!(stored.starts_with("$argon2id$v=19$m=8192,t=1,p=1$"));
        let v = h.verify(&pw("correct horse"), &stored).unwrap();
        assert!(v.valid && !v.needs_rehash);
        let v = h.verify(&pw("wrong"), &stored).unwrap();
        assert!(!v.valid && !v.needs_rehash);

        let stronger = Argon2Hasher::new(Argon2Params {
            m_cost: 16 * 1024,
            t_cost: 2,
            p_cost: 1,
        });
        let v = stronger.verify(&pw("correct horse"), &stored).unwrap();
        assert!(
            v.valid && v.needs_rehash,
            "weaker params must trigger a rehash"
        );
    }

    #[test]
    fn bcrypt_legacy() {
        let stored = bcrypt::hash("s3cret", 4).unwrap();
        let v = hasher().verify(&pw("s3cret"), &stored).unwrap();
        assert!(v.valid && v.needs_rehash);
        assert!(!hasher().verify(&pw("nope"), &stored).unwrap().valid);
        assert_eq!(legacy::algorithm_of(&stored), "bcrypt");
    }

    #[test]
    fn pbkdf2_phc_and_django() {
        use base64::Engine as _;
        let salt = b"saltsalt";
        let mut out = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(b"pw", salt, 1000, &mut out);
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD;
        let phc = format!(
            "$pbkdf2-sha256$1000${}${}",
            b64.encode(salt),
            b64.encode(out)
        );
        assert!(hasher().verify(&pw("pw"), &phc).unwrap().valid);
        assert!(!hasher().verify(&pw("px"), &phc).unwrap().valid);

        let django = format!(
            "pbkdf2_sha256$1000$saltsalt${}",
            base64::engine::general_purpose::STANDARD.encode(out)
        );
        assert!(hasher().verify(&pw("pw"), &django).unwrap().valid);
        assert_eq!(legacy::algorithm_of(&django), "pbkdf2-sha256");

        let mut out512 = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(b"pw", salt, 500, &mut out512);
        let phc512 = format!(
            "$pbkdf2-sha512$500${}${}",
            b64.encode(salt),
            b64.encode(out512)
        );
        assert!(hasher().verify(&pw("pw"), &phc512).unwrap().valid);
    }

    #[test]
    fn salted_and_unsalted_digests() {
        let salted = format!(
            "$sha256$mysalt${}",
            hex::encode(sha2::Sha256::digest(b"mysaltpw"))
        );
        assert!(hasher().verify(&pw("pw"), &salted).unwrap().valid);
        assert!(!hasher().verify(&pw("pW"), &salted).unwrap().valid);
        let unsalted = format!("$sha512${}", hex::encode(sha2::Sha512::digest(b"pw")));
        assert!(hasher().verify(&pw("pw"), &unsalted).unwrap().valid);
        let md5 = format!("$md5${}", hex::encode(md5::Md5::digest(b"pw")));
        assert!(hasher().verify(&pw("pw"), &md5).unwrap().valid);
        let md5s = format!("$md5$s${}", hex::encode(md5::Md5::digest(b"spw")));
        assert!(hasher().verify(&pw("pw"), &md5s).unwrap().valid);
        assert_eq!(legacy::algorithm_of(&md5s), "md5");
    }

    #[test]
    fn unsupported_format_is_rejected_not_accepted() {
        assert!(matches!(
            hasher().verify(&pw("pw"), "plaintext"),
            Err(ProviderError::Rejected(_))
        ));
        assert_eq!(legacy::algorithm_of("plaintext"), "unknown");
    }

    #[test]
    fn argon2_variants_are_labelled_by_their_own_name() {
        let tail = "v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaA";
        assert_eq!(
            legacy::algorithm_of(&format!("$argon2id${tail}")),
            "argon2id"
        );
        assert_eq!(legacy::algorithm_of(&format!("$argon2i${tail}")), "argon2i");
        assert_eq!(legacy::algorithm_of(&format!("$argon2d${tail}")), "argon2d");
        assert_eq!(legacy::algorithm_of(&format!("$argon2x${tail}")), "unknown");
    }

    #[test]
    fn policy_reports_every_violation() {
        let policy = PasswordPolicy {
            min_length: 10,
            require_uppercase: true,
            require_digit: true,
            require_symbol: true,
            ..Default::default()
        };
        let problems = check_policy(&policy, "short", None);
        assert_eq!(problems.len(), 4, "{problems:?}");
        assert!(check_policy(&policy, "LongEnough1!", None).is_empty());
        assert!(
            check_policy(
                &PasswordPolicy {
                    max_length: 4,
                    min_length: 1,
                    ..Default::default()
                },
                "toolong",
                None
            )
            .iter()
            .any(|p| p.contains("at most"))
        );
    }

    #[test]
    fn dummy_hash_parses() {
        assert!(PasswordHash::new(DUMMY_HASH).is_ok());
    }
}
