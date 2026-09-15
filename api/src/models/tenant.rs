use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use uuid::Uuid;

/// Fixed id of the `master` tenant (seeded by migration 0001).
pub const MASTER_TENANT_ID: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0001);
pub const MASTER_TENANT_SLUG: &str = "master";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum TenantStatus {
    Active,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Tenant {
    pub id: Uuid,
    pub slug: String,
    pub display_name: String,
    pub status: TenantStatus,
    pub settings: Json<TenantSettings>,
    /// Random per-tenant salt for pairwise subject identifiers. Never exported.
    #[serde(skip)]
    pub pairwise_salt: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Tenant {
    pub fn is_active(&self) -> bool {
        self.status == TenantStatus::Active
    }
}

/// Per-tenant configuration stored as JSONB. Every field has a default so that
/// settings written by older versions keep deserializing.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TenantSettings {
    pub password: PasswordPolicy,
    pub session: SessionPolicy,
    pub mfa: MfaPolicy,
    pub registration: RegistrationPolicy,
    pub locale: LocaleSettings,
    pub branding: Branding,
    pub keys: KeyPolicy,
    pub discovery: DiscoverySettings,
    pub dcr: DcrPolicy,
    pub auth: AuthMethods,
    pub lockout: LockoutPolicy,
    pub captcha: CaptchaPolicy,
    pub notifications: NotificationPolicy,
    /// Custom issuer host (Phase 9.3). `None` means `{PUBLIC_URL}/t/{slug}`.
    pub custom_domain: Option<String>,
}

/// Which security notices users receive (email, or SMS when they have no email).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationPolicy {
    pub new_device: bool,
    pub password_changed: bool,
    pub mfa_changed: bool,
    pub email_changed: bool,
}

impl Default for NotificationPolicy {
    fn default() -> Self {
        Self {
            new_device: true,
            password_changed: true,
            mfa_changed: true,
            email_changed: true,
        }
    }
}

/// Which first-factor login methods the tenant offers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthMethods {
    pub password: bool,
    pub magic_link: bool,
    pub email_otp: bool,
    pub sms_otp: bool,
    pub passkey: bool,
}

impl Default for AuthMethods {
    fn default() -> Self {
        Self {
            password: true,
            magic_link: false,
            email_otp: false,
            sms_otp: false,
            passkey: false,
        }
    }
}

/// When to demand a CAPTCHA (the provider itself is configured with its
/// secret in `tenant_provider_settings`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptchaPolicy {
    /// Require a challenge after this many failed attempts in a flow (0 = never).
    pub after_failures: u32,
    pub on_registration: bool,
}

impl Default for CaptchaPolicy {
    fn default() -> Self {
        Self {
            after_failures: 3,
            on_registration: true,
        }
    }
}

/// Brute-force protection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LockoutPolicy {
    /// Consecutive failures before a user is temporarily locked (0 = off).
    pub max_failures: u32,
    pub lock_minutes: u32,
    /// Failures from one IP within the window before it is throttled (0 = off).
    pub ip_max_failures: u32,
    pub ip_window_minutes: u32,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self {
            max_failures: 10,
            lock_minutes: 15,
            ip_max_failures: 100,
            ip_window_minutes: 15,
        }
    }
}

/// Dynamic client registration policy (RFC 7591).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DcrPolicy {
    pub mode: DcrMode,
    /// Grant types a dynamically registered client may request.
    pub allowed_grants: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DcrMode {
    #[default]
    Disabled,
    /// Anyone may register (rate limited; public clients only by default).
    Open,
    /// Registration requires an admin-issued initial access token.
    InitialAccessToken,
}

/// WebFinger issuer discovery (OIDC Discovery §2).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DiscoverySettings {
    /// `acct:user@<domain>` resources with one of these domains resolve to
    /// this tenant's issuer.
    pub email_domains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordPolicy {
    pub min_length: u32,
    pub max_length: u32,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_symbol: bool,
    /// A new password must differ from the last `history` passwords, counting
    /// the current one (0 = off, 1 = only the current password).
    pub history: u32,
    /// Days until a password expires (None = never).
    pub max_age_days: Option<u32>,
    /// Reject passwords found in breach corpora (Phase 7.5).
    pub check_breached: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            max_length: 128,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_symbol: false,
            history: 5,
            max_age_days: None,
            check_breached: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionPolicy {
    pub idle_timeout_secs: u64,
    pub absolute_timeout_secs: u64,
    /// 0 = unlimited.
    pub max_concurrent: u32,
    pub remember_device_days: u32,
    pub access_token_ttl_secs: u64,
    pub refresh_token_ttl_secs: u64,
    pub id_token_ttl_secs: u64,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            idle_timeout_secs: 30 * 60,
            absolute_timeout_secs: 12 * 60 * 60,
            max_concurrent: 0,
            remember_device_days: 30,
            access_token_ttl_secs: 5 * 60,
            refresh_token_ttl_secs: 30 * 24 * 60 * 60,
            id_token_ttl_secs: 5 * 60,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum MfaPolicy {
    #[default]
    Off,
    Optional,
    Required,
    RequiredForAdmins,
    RequiredForRoles {
        roles: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RegistrationPolicy {
    pub enabled: bool,
    pub require_email_verification: bool,
    pub require_terms: bool,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    /// Only these email domains may self-register (empty = any).
    pub allowed_email_domains: Vec<String>,
    pub captcha: bool,
}

impl Default for RegistrationPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            require_email_verification: true,
            require_terms: false,
            terms_url: None,
            privacy_url: None,
            allowed_email_domains: vec![],
            captcha: false,
        }
    }
}

/// Signing key lifecycle policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct KeyPolicy {
    /// Algorithm for new keys created by rotation / on demand.
    pub default_alg: crate::models::SigningAlg,
    pub rsa_bits: crate::models::RsaBits,
    /// Rotate the active key after this many days (0 = never automatically).
    pub rotation_interval_days: u32,
    /// How long a retired key stays published for verification.
    pub retire_overlap_hours: u32,
}

impl Default for KeyPolicy {
    fn default() -> Self {
        Self {
            default_alg: crate::models::SigningAlg::RS256,
            rsa_bits: crate::models::RsaBits::B2048,
            rotation_interval_days: 90,
            retire_overlap_hours: 24,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocaleSettings {
    pub default: String,
    pub supported: Vec<String>,
}

impl Default for LocaleSettings {
    fn default() -> Self {
        Self {
            default: "en".into(),
            supported: vec!["en".into()],
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Branding {
    pub logo_url: Option<String>,
    pub favicon_url: Option<String>,
    pub primary_color: Option<String>,
    pub background_color: Option<String>,
    pub support_url: Option<String>,
    pub custom_css: Option<String>,
    pub links: Vec<BrandingLink>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrandingLink {
    pub label: String,
    pub url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_settings_document_deserializes_to_defaults() {
        let s: TenantSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(s, TenantSettings::default());
        assert_eq!(s.password.min_length, 12);
        assert_eq!(s.mfa, MfaPolicy::Off);
    }

    #[test]
    fn unknown_fields_are_ignored_for_forward_compat() {
        let s: TenantSettings =
            serde_json::from_str(r#"{"future_feature": {"x": 1}, "locale": {"default": "de"}}"#)
                .unwrap();
        assert_eq!(s.locale.default, "de");
    }

    #[test]
    fn mfa_policy_is_tagged() {
        let json = serde_json::to_value(MfaPolicy::RequiredForRoles {
            roles: vec!["admin".into()],
        })
        .unwrap();
        assert_eq!(json["mode"], "required_for_roles");
    }
}
