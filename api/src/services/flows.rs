//! Login flow state machine.
//!
//! A flow starts at `/authorize` and carries the validated request through
//! the static UI. Each step validates the CSRF token bound to the flow,
//! performs its action, then [`advance`] recomputes the next stage from
//! policy and user state until `Done`, when `GET /flows/{id}/finish` issues
//! the authorization code in the browser's context.

use chrono::{Duration, Utc};
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::Serialize;
use serde_json::Value;
use subtle::ConstantTimeEq as _;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::db;
use crate::error::{AppError, AppResult, FieldError};
use crate::middleware::TenantCtx;
use crate::models::{
    AttributeDef, Client, MfaPolicy, RiskAssessment, Tenant, TrustedDevice, User, UserStatus,
};
use crate::repos;
use crate::services::geoip::Location;
use crate::services::login_flows::{self, FlowStage, LoginFlow};
use crate::services::password::{self, SetPasswordOptions, VerifyOutcome};
use crate::services::sessions::{self, NewSession, SsoSession};
use crate::services::{
    admin_access, clients, consents, locale, notifications, organizations, otp_factors, passkeys,
    profile_schema, risk, roles, totp, trusted_devices, users,
};
use crate::state::AppState;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

/// What the UI needs to render the current step.
#[derive(Debug, Clone, Serialize)]
pub struct PublicFlow {
    pub id: Uuid,
    pub stage: FlowStage,
    pub csrf: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub client: PublicClient,
    pub methods: Vec<&'static str>,
    pub login_hint: Option<String>,
    pub ui_locales: Vec<String>,
    /// Negotiated locale (`ui_locales` → user locale → tenant default).
    pub locale: String,
    /// `ltr` or `rtl` for the negotiated locale.
    pub dir: &'static str,
    /// Locales the tenant offers, for a language switcher.
    pub locales: Vec<String>,
    /// Consent stage: scopes awaiting approval with descriptions.
    pub pending_scopes: Vec<ScopeInfo>,
    /// Profile stage: attribute definitions still missing.
    pub missing_attributes: Vec<AttributeDef>,
    /// Terms stage.
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    /// Authenticated user (after the authenticate stage).
    pub user: Option<PublicUser>,
    pub attempts: u32,
    /// Present when the next authentication attempt must include a CAPTCHA token.
    pub captcha: Option<CaptchaChallenge>,
    /// Mfa stage: what the user can verify with, or whether they must enrol first.
    pub mfa: Option<MfaInfo>,
    /// Organization stage: the organizations the user may act in.
    pub organizations: Vec<PublicOrganization>,
    /// Upstream providers offered on the login page ("Continue with ...").
    pub identity_providers: Vec<crate::models::PublicIdentityProvider>,
}

/// An organization offered at the `organization` stage.
#[derive(Debug, Clone, Serialize)]
pub struct PublicOrganization {
    pub id: Uuid,
    pub slug: String,
    pub display_name: String,
}

/// Second-factor state of the signed-in user, shown at the `mfa` stage.
#[derive(Debug, Clone, Serialize)]
pub struct MfaInfo {
    /// Enrolled factor kinds (`totp`, `webauthn`, `email_otp`, `sms_otp`).
    pub factors: Vec<&'static str>,
    /// Factor kinds the tenant offers this user for enrolment.
    pub methods: Vec<&'static str>,
    /// No factor yet: the user must enrol one now.
    pub enroll: bool,
    /// Unused recovery codes remain, so the recovery-code option is worth showing.
    pub recovery_codes: bool,
    /// The phone an SMS enrolment would use, masked; `None` asks for one.
    pub phone: Option<String>,
}

/// Second factors the tenant offers `user` for enrolment.
fn offered_factors(tenant: &Tenant, user: &User) -> Vec<&'static str> {
    let m = &tenant.settings.mfa_methods;
    let mut out = vec![];
    if m.totp {
        out.push(totp::KIND_TOTP);
    }
    if tenant.settings.auth.passkey {
        out.push(passkeys::KIND);
    }
    if m.email_otp && user.email.is_some() {
        out.push(otp_factors::KIND_EMAIL);
    }
    if m.sms_otp {
        out.push(otp_factors::KIND_SMS);
    }
    out
}

/// `acr` recorded on a session once a second factor passed, unless the client
/// asked for another `*:mfa` class.
pub const ACR_MFA: &str = "urn:ridm:acr:mfa";
/// `acr` recorded on a session established with one factor. A session always
/// carries a class, so a request that asked for `acr_values` gets an `acr`
/// claim back (OIDC Core §3.1.2.1) even when nothing it named was met.
pub const ACR_SINGLE: &str = "urn:ridm:acr:single";
/// Wrong second-factor codes tolerated per flow before it is discarded.
pub const MFA_MAX_ATTEMPTS: u32 = 5;

#[derive(Debug, Clone, Serialize)]
pub struct CaptchaChallenge {
    pub provider: ridm_core::providers::CaptchaKind,
    pub site_key: String,
}

/// Is a CAPTCHA required for the next attempt in this flow?
pub async fn captcha_required(
    state: &AppState,
    tenant: &Tenant,
    flow: &LoginFlow,
) -> AppResult<Option<CaptchaChallenge>> {
    let policy = &tenant.settings.captcha;
    let needed = (policy.after_failures > 0 && flow.attempts >= policy.after_failures)
        || (policy.on_registration && flow.stage == FlowStage::Register);
    if !needed {
        return Ok(None);
    }
    let provider = crate::services::captcha::provider_for(state, tenant.id).await?;
    Ok(provider.site_key().map(|k| CaptchaChallenge {
        provider: provider.kind(),
        site_key: k.to_string(),
    }))
}

/// Verify a CAPTCHA token when one is required; `Ok(())` when none is needed.
pub async fn enforce_captcha(
    state: &AppState,
    tenant: &Tenant,
    flow: &LoginFlow,
    token: Option<&str>,
    ip: Option<&str>,
) -> AppResult<()> {
    if captcha_required(state, tenant, flow).await?.is_none() {
        return Ok(());
    }
    let Some(token) = token.filter(|t| !t.is_empty()) else {
        return Err(AppError::Validation(vec![FieldError {
            field: "captcha_token".into(),
            message: "captcha_required".into(),
        }]));
    };
    let provider = crate::services::captcha::provider_for(state, tenant.id).await?;
    let outcome = provider
        .verify(token, ip.and_then(|s| s.parse().ok()))
        .await
        .map_err(|e| AppError::Unavailable(format!("captcha verification failed: {e}")))?;
    if !outcome.success {
        return Err(AppError::Validation(vec![FieldError {
            field: "captcha_token".into(),
            message: "captcha_failed".into(),
        }]));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicClient {
    pub client_id: String,
    pub name: String,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicUser {
    pub username: String,
    pub email: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopeInfo {
    pub name: String,
    pub description: Option<String>,
}

pub fn check_csrf(flow: &LoginFlow, presented: &str) -> AppResult<()> {
    if flow.csrf.is_empty() || !bool::from(flow.csrf.as_bytes().ct_eq(presented.as_bytes())) {
        return Err(AppError::Forbidden("invalid csrf token".into()));
    }
    Ok(())
}

pub async fn load(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<LoginFlow> {
    login_flows::get(state, tenant_id, id)
        .await?
        .ok_or(AppError::NotFound("flow"))
}

async fn client_of(state: &AppState, flow: &LoginFlow) -> AppResult<std::sync::Arc<Client>> {
    clients::find_by_client_id(state, flow.tenant_id, &flow.request.client_public_id)
        .await?
        .filter(|c| c.is_active())
        .ok_or(AppError::NotFound("client"))
}

pub async fn public_state(
    state: &AppState,
    tenant: &Tenant,
    flow: &LoginFlow,
) -> AppResult<PublicFlow> {
    let client = client_of(state, flow).await?;
    let auth = &tenant.settings.auth;
    let mut methods = vec![];
    if auth.password {
        methods.push("password");
    }
    if auth.magic_link {
        methods.push("magic_link");
    }
    if auth.email_otp {
        methods.push("email_otp");
    }
    if auth.sms_otp {
        methods.push("sms_otp");
    }
    if auth.passkey {
        methods.push("passkey");
    }
    let all_scopes = crate::services::scopes::list(state, tenant.id).await?;
    let pending_scopes = flow
        .pending_scopes
        .iter()
        .map(|n| ScopeInfo {
            name: n.clone(),
            description: all_scopes
                .iter()
                .find(|s| &s.name == n)
                .and_then(|s| s.description.clone()),
        })
        .collect();
    let (missing_attributes, user, user_locale, mfa) = match flow.user_id {
        Some(uid) => {
            let u = users::get(state, tenant.id, uid).await?;
            let missing = if flow.stage == FlowStage::Profile {
                missing_required(state, tenant.id, &u).await?
            } else {
                vec![]
            };
            let mfa = if flow.stage == FlowStage::Mfa {
                let f = totp::factors_of(state, tenant.id, uid).await?;
                let mut factors = vec![];
                if f.totp {
                    factors.push(totp::KIND_TOTP);
                }
                if f.webauthn {
                    factors.push(passkeys::KIND);
                }
                if f.email_otp {
                    factors.push(otp_factors::KIND_EMAIL);
                }
                if f.sms_otp {
                    factors.push(otp_factors::KIND_SMS);
                }
                Some(MfaInfo {
                    factors,
                    methods: offered_factors(tenant, &u),
                    enroll: !f.any(),
                    recovery_codes: f.any() && f.recovery_codes > 0,
                    phone: u.phone.as_deref().map(otp_factors::mask_phone),
                })
            } else {
                None
            };
            (
                missing,
                Some(PublicUser {
                    username: u.username,
                    email: u.email,
                }),
                u.locale,
                mfa,
            )
        }
        None => (vec![], None, None, None),
    };
    let locale = locale::negotiate(
        &flow.request.ui_locales,
        user_locale.as_deref(),
        &tenant.settings.locale,
    );
    Ok(PublicFlow {
        id: flow.id,
        stage: flow.stage,
        csrf: flow.csrf.clone(),
        expires_at: flow.expires_at,
        client: PublicClient {
            client_id: client.client_id.clone(),
            name: client.name.clone(),
            logo_uri: client.logo_uri.clone(),
            client_uri: client.client_uri.clone(),
            tos_uri: client.tos_uri.clone(),
            policy_uri: client.policy_uri.clone(),
        },
        methods,
        login_hint: flow.request.login_hint.clone(),
        ui_locales: flow.request.ui_locales.clone(),
        dir: locale::direction(&locale),
        locales: locale::supported_of(&tenant.settings.locale),
        locale,
        pending_scopes,
        missing_attributes,
        terms_url: tenant.settings.registration.terms_url.clone(),
        privacy_url: tenant.settings.registration.privacy_url.clone(),
        user,
        attempts: flow.attempts,
        captcha: captcha_required(state, tenant, flow).await?,
        mfa,
        organizations: if flow.stage == FlowStage::Organization {
            selectable_organizations(state, tenant.id, flow.user_id)
                .await?
                .into_iter()
                .map(|o| PublicOrganization {
                    id: o.id,
                    slug: o.slug,
                    display_name: o.display_name,
                })
                .collect()
        } else {
            vec![]
        },
        identity_providers: crate::services::identity_providers::offered(state, tenant.id).await?,
    })
}

async fn missing_required(
    state: &AppState,
    tenant_id: Uuid,
    user: &User,
) -> AppResult<Vec<AttributeDef>> {
    let schema = profile_schema::get(state, tenant_id).await?;
    Ok(schema
        .attributes
        .iter()
        .filter(|a| a.required && a.editable_by != crate::models::EditableBy::None)
        .filter(|a| {
            !user
                .attributes
                .get(&a.name)
                .is_some_and(|v| !v.is_null() && v.as_str().is_none_or(|s| !s.trim().is_empty()))
        })
        .cloned()
        .collect())
}

/// The organizations a user may sign in as a member of: their memberships,
/// minus the disabled ones.
async fn selectable_organizations(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Option<Uuid>,
) -> AppResult<Vec<crate::models::Organization>> {
    let Some(user_id) = user_id else {
        return Ok(vec![]);
    };
    Ok(organizations::of_user(state, tenant_id, user_id)
        .await?
        .into_iter()
        .filter(|o| o.status == crate::models::OrganizationStatus::Active)
        .collect())
}

/// Records the organization on the flow and on the session behind it, so every
/// token issued through this sign-in carries it.
async fn bind_organization(
    state: &AppState,
    tenant: &Tenant,
    flow: &mut LoginFlow,
    org_id: Uuid,
) -> AppResult<()> {
    if let Some(sid) = flow.session_id
        && let Some(mut session) =
            sessions::get(state, tenant.id, sid, &tenant.settings.session).await?
    {
        sessions::bind_organization(state, &mut session, org_id).await?;
    }
    flow.org_id = Some(org_id);
    Ok(())
}

/// Which organization this session acts in. One membership settles itself, as
/// does an `organization` request parameter naming one the user belongs to;
/// several unnamed memberships need the user. Returns true when the flow must
/// stop and ask.
async fn organization_pending(
    state: &AppState,
    tenant: &Tenant,
    flow: &mut LoginFlow,
    user_id: Uuid,
) -> AppResult<bool> {
    if flow.org_id.is_some() {
        return Ok(false);
    }
    // A session that already acts in an organization is not asked again.
    if let Some(sid) = flow.session_id
        && let Some(session) =
            sessions::get(state, tenant.id, sid, &tenant.settings.session).await?
        && let Some(org_id) = session.org_id
    {
        flow.org_id = Some(org_id);
        return Ok(false);
    }
    let orgs = selectable_organizations(state, tenant.id, Some(user_id)).await?;
    if orgs.is_empty() {
        return Ok(false);
    }
    if let [only] = orgs.as_slice() {
        bind_organization(state, tenant, flow, only.id).await?;
        return Ok(false);
    }
    if let Some(requested) = flow.request.organization.as_deref() {
        let wanted = requested.trim();
        if let Some(org) = orgs
            .iter()
            .find(|o| o.slug == wanted || o.id.to_string() == wanted)
        {
            bind_organization(state, tenant, flow, org.id).await?;
            return Ok(false);
        }
        // The request named an organization this user is not a member of.
        // Asking is better than silently acting somewhere else.
    }
    Ok(true)
}

/// Recompute the stage after the user is authenticated. `must_change_password`
/// takes precedence over everything else.
pub async fn advance(
    state: &AppState,
    tenant: &Tenant,
    flow: &mut LoginFlow,
    must_change_password: bool,
) -> AppResult<()> {
    let (Some(user_id), Some(_session_id)) = (flow.user_id, flow.session_id) else {
        flow.stage = FlowStage::Authenticate;
        return Ok(());
    };
    let user = users::get(state, tenant.id, user_id).await?;
    if must_change_password {
        flow.stage = FlowStage::PasswordChange;
        return Ok(());
    }
    if mfa_required(state, tenant, flow, &user).await? {
        flow.stage = FlowStage::Mfa;
        return Ok(());
    }
    if !missing_required(state, tenant.id, &user).await?.is_empty() {
        flow.stage = FlowStage::Profile;
        return Ok(());
    }
    if tenant.settings.registration.require_terms && user.terms_accepted_at.is_none() {
        flow.stage = FlowStage::Terms;
        return Ok(());
    }
    if organization_pending(state, tenant, flow, user_id).await? {
        flow.stage = FlowStage::Organization;
        return Ok(());
    }
    let client = client_of(state, flow).await?;
    let force_consent = flow.request.prompt.iter().any(|p| p == "consent");
    let pending = if flow.request.skip_consent && !force_consent {
        vec![]
    } else if force_consent && flow.pending_scopes.is_empty() && flow.stage != FlowStage::Consent {
        flow.request.scopes.clone()
    } else {
        consents::missing_scopes(state, tenant.id, user_id, client.id, &flow.request.scopes).await?
    };
    if !pending.is_empty() && flow.stage != FlowStage::Done {
        flow.pending_scopes = pending;
        flow.stage = FlowStage::Consent;
        return Ok(());
    }
    flow.pending_scopes.clear();
    flow.stage = FlowStage::Done;
    Ok(())
}

/// Outcome of an authentication step.
pub enum AuthStep {
    /// Session cookie to set and the updated flow.
    Authenticated {
        session: Box<SsoSession>,
        flow: Box<LoginFlow>,
    },
    /// Wrong credentials; the flow (with its attempt counter) was saved.
    Rejected { flow: Box<LoginFlow>, locked: bool },
    /// The credentials were right, but the tenant's risk policy refused the
    /// sign-in. The flow is gone and no session was opened; the browser goes
    /// back to the client with `access_denied`.
    Blocked { redirect_to: String },
}

/// Inputs of a password authentication attempt.
pub struct PasswordAttempt {
    pub identifier: String,
    pub password: Zeroizing<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    /// An SSO session the browser already has (re-authentication).
    pub existing_session: Option<SsoSession>,
    /// CAPTCHA response, required once the tenant policy demands one.
    pub captcha_token: Option<String>,
    /// Trusted-device cookie value, if the browser sent one.
    pub device_secret: Option<String>,
    /// "Remember this device" was ticked.
    pub remember_device: bool,
    /// Where the request came from, for the risk policy.
    pub location: Option<Location>,
}

/// `POST /flows/{id}/password`
pub async fn password_step(
    state: &AppState,
    tenant: &TenantCtx,
    mut flow: LoginFlow,
    attempt: PasswordAttempt,
) -> AppResult<AuthStep> {
    let PasswordAttempt {
        identifier,
        password,
        ip,
        user_agent,
        existing_session,
        captcha_token,
        device_secret,
        remember_device,
        location,
    } = attempt;
    if flow.stage != FlowStage::Authenticate {
        return Err(AppError::BadRequest(
            "flow is not at the authenticate step".into(),
        ));
    }
    if !tenant.tenant.settings.auth.password {
        return Err(AppError::BadRequest(
            "password login is disabled for this tenant".into(),
        ));
    }
    let tid = tenant.id();
    let lockout = &tenant.tenant.settings.lockout;
    let identifier = identifier.trim().to_lowercase();
    if identifier.is_empty() || password.is_empty() {
        return Err(AppError::Validation(vec![FieldError {
            field: "identifier".into(),
            message: "identifier and password are required".into(),
        }]));
    }

    enforce_captcha(
        state,
        &tenant.tenant,
        &flow,
        captcha_token.as_deref(),
        ip.as_deref(),
    )
    .await?;

    // IP throttle.
    if lockout.ip_max_failures > 0
        && let Some(ip) = &ip
    {
        let mut tx = db::tenant_tx(&state.db, tid).await?;
        let since = Utc::now() - Duration::minutes(i64::from(lockout.ip_window_minutes.max(1)));
        let n = repos::login_attempts::failures_from_ip(&mut *tx, tid, ip, since).await?;
        tx.commit().await?;
        if n >= i64::from(lockout.ip_max_failures) {
            return Err(AppError::RateLimited {
                retry_after_secs: u64::from(lockout.ip_window_minutes) * 60,
            });
        }
    }

    let mut user = users::find_by_identifier(state, tid, &identifier).await?;
    // No local account: one of the tenant's directories may know the
    // identifier, and a bind with this password imports the user.
    let mut directory_verified = false;
    if user.is_none()
        && let Some(u) =
            crate::services::ldap::sign_in_unknown(state, &tenant.tenant, &identifier, &password)
                .await?
    {
        user = Some(u);
        directory_verified = true;
    }
    let verdict = match &user {
        Some(u) if u.status == UserStatus::Disabled => Err("disabled"),
        Some(u) if u.is_locked_now() => Err("locked"),
        Some(u) if directory_verified => Ok(u.must_change_password),
        Some(u) => match password::verify_and_upgrade(
            state,
            tid,
            &tenant.tenant.settings.password,
            u,
            password,
        )
        .await?
        {
            VerifyOutcome::Valid { must_change } => Ok(must_change),
            VerifyOutcome::Invalid => Err("invalid_credentials"),
        },
        None => {
            // Equalise timing with a real verification.
            let _ = password::verify_and_upgrade(
                state,
                tid,
                &tenant.tenant.settings.password,
                &dummy_user(tid),
                password,
            )
            .await;
            Err("invalid_credentials")
        }
    };

    match verdict {
        Ok(must_change) => {
            let user = user.expect("user present");
            let ctx = RequestContext {
                ip: ip.clone(),
                user_agent,
                existing_session,
                device_secret,
                remember_device,
                location,
            };
            // Scored before anything is written: a refused sign-in leaves no
            // session, no flow and no successful attempt behind it.
            let assessment = assess(state, &tenant.tenant, &user, &ctx).await?;
            if assessment.risk.is_blocked() {
                return refuse(state, &tenant.tenant, &flow, &user, &assessment.risk, &ctx).await;
            }
            let mut tx = db::tenant_tx(&state.db, tid).await?;
            repos::users::record_login_success(&mut *tx, tid, user.id).await?;
            repos::login_attempts::record(&mut *tx, tid, &identifier, ip.as_deref(), true, None)
                .await?;
            tx.commit().await?;
            metrics::counter!("ridm_logins_total", "method" => "password", "outcome" => "success")
                .increment(1);

            let session = open_session(
                state,
                &tenant.tenant,
                &mut flow,
                &user,
                vec!["pwd".into()],
                ctx,
                assessment,
            )
            .await?;
            advance(state, &tenant.tenant, &mut flow, must_change).await?;
            login_flows::save(state, &flow).await?;
            state.events.publish(
                Event::new(
                    Some(tid),
                    Actor::User { id: user.id },
                    EventKind::LoginSucceeded {
                        user_id: user.id,
                        method: "pwd".into(),
                    },
                )
                .with_request(ip, None),
            );
            Ok(AuthStep::Authenticated {
                session: Box::new(session),
                flow: Box::new(flow),
            })
        }
        Err(reason) => {
            let mut locked = false;
            let mut tx = db::tenant_tx(&state.db, tid).await?;
            repos::login_attempts::record(
                &mut *tx,
                tid,
                &identifier,
                ip.as_deref(),
                false,
                Some(reason),
            )
            .await?;
            metrics::counter!("ridm_logins_total", "method" => "password", "outcome" => reason.to_string())
                .increment(1);
            if let Some(u) = &user
                && reason == "invalid_credentials"
                && lockout.max_failures > 0
            {
                let failures = repos::users::record_login_failure(
                    &mut *tx,
                    tid,
                    u.id,
                    lockout.max_failures as i32,
                    i64::from(lockout.lock_minutes) * 60,
                )
                .await?;
                if failures >= lockout.max_failures as i32 {
                    locked = true;
                    state.events.publish(Event::new(
                        Some(tid),
                        Actor::System,
                        EventKind::UserLocked {
                            user_id: u.id,
                            until_secs: i64::from(lockout.lock_minutes) * 60,
                        },
                    ));
                }
            }
            tx.commit().await?;
            flow.attempts += 1;
            login_flows::save(state, &flow).await?;
            state.events.publish(
                Event::new(
                    Some(tid),
                    Actor::System,
                    EventKind::LoginFailed {
                        identifier: identifier.clone(),
                        reason: reason.into(),
                    },
                )
                .with_request(ip, None),
            );
            Ok(AuthStep::Rejected {
                flow: Box::new(flow),
                locked: locked || reason == "locked",
            })
        }
    }
}

fn dummy_user(tenant_id: Uuid) -> User {
    User {
        id: Uuid::nil(),
        tenant_id,
        org_id: None,
        username: String::new(),
        email: None,
        email_verified: false,
        phone: None,
        phone_verified: false,
        password_hash: None,
        password_algo: None,
        must_change_password: false,
        password_expires_at: None,
        password_changed_at: None,
        status: UserStatus::Active,
        attributes: Value::Object(Default::default()),
        locale: None,
        external_id: None,
        last_login_at: None,
        failed_attempts: 0,
        locked_until: None,
        deleted_at: None,
        terms_accepted_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// `POST /flows/{id}/password-change`: set a new password at the `PasswordChange` stage.
pub async fn password_change_step(
    state: &AppState,
    tenant: &Tenant,
    mut flow: LoginFlow,
    new_password: Zeroizing<String>,
) -> AppResult<LoginFlow> {
    if flow.stage != FlowStage::PasswordChange {
        return Err(AppError::BadRequest(
            "flow is not at the password change step".into(),
        ));
    }
    let user_id = flow.user_id.ok_or(AppError::Unauthorized)?;
    password::set_password(
        state,
        tenant.id,
        &tenant.settings.password,
        Actor::User { id: user_id },
        user_id,
        new_password,
        SetPasswordOptions {
            must_change: false,
            skip_policy: false,
            by_user: true,
            notify: true,
        },
    )
    .await?;
    advance(state, tenant, &mut flow, false).await?;
    login_flows::save(state, &flow).await?;
    Ok(flow)
}

/// `POST /flows/{id}/profile`: fill required attributes.
pub async fn profile_step(
    state: &AppState,
    tenant: &Tenant,
    mut flow: LoginFlow,
    attributes: Value,
) -> AppResult<LoginFlow> {
    if flow.stage != FlowStage::Profile {
        return Err(AppError::BadRequest(
            "flow is not at the profile step".into(),
        ));
    }
    let user_id = flow.user_id.ok_or(AppError::Unauthorized)?;
    users::update(
        state,
        tenant.id,
        Actor::User { id: user_id },
        user_id,
        crate::models::UserUpdate {
            attributes: Some(attributes),
            ..Default::default()
        },
    )
    .await?;
    advance(state, tenant, &mut flow, false).await?;
    login_flows::save(state, &flow).await?;
    Ok(flow)
}

/// `POST /flows/{id}/terms`
pub async fn terms_step(
    state: &AppState,
    tenant: &Tenant,
    mut flow: LoginFlow,
    accepted: bool,
) -> AppResult<LoginFlow> {
    if flow.stage != FlowStage::Terms {
        return Err(AppError::BadRequest("flow is not at the terms step".into()));
    }
    if !accepted {
        return Err(AppError::Forbidden(
            "terms must be accepted to continue".into(),
        ));
    }
    let user_id = flow.user_id.ok_or(AppError::Unauthorized)?;
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    repos::users::set_terms_accepted(&mut *tx, tenant.id, user_id).await?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tenant.id),
        Actor::User { id: user_id },
        EventKind::TermsAccepted { user_id },
    ));
    advance(state, tenant, &mut flow, false).await?;
    login_flows::save(state, &flow).await?;
    Ok(flow)
}

/// `POST /flows/{id}/organization`
pub async fn organization_step(
    state: &AppState,
    tenant: &Tenant,
    mut flow: LoginFlow,
    org_id: Uuid,
) -> AppResult<LoginFlow> {
    if flow.stage != FlowStage::Organization {
        return Err(AppError::BadRequest(
            "flow is not at the organization step".into(),
        ));
    }
    let user_id = flow.user_id.ok_or(AppError::Unauthorized)?;
    // Only a live membership of an organization that is not disabled, and only
    // one this user holds: the choice comes from the browser.
    if !selectable_organizations(state, tenant.id, Some(user_id))
        .await?
        .iter()
        .any(|o| o.id == org_id)
    {
        return Err(AppError::BadRequest(
            "not a member of that organization".into(),
        ));
    }
    bind_organization(state, tenant, &mut flow, org_id).await?;
    advance(state, tenant, &mut flow, false).await?;
    login_flows::save(state, &flow).await?;
    Ok(flow)
}

/// `POST /flows/{id}/consent`: approve (all pending or a subset that must
/// include every non-optional scope) or deny.
pub async fn consent_step(
    state: &AppState,
    tenant: &Tenant,
    mut flow: LoginFlow,
    approve: bool,
    granted: Option<Vec<String>>,
) -> AppResult<ConsentOutcome> {
    if flow.stage != FlowStage::Consent {
        return Err(AppError::BadRequest(
            "flow is not at the consent step".into(),
        ));
    }
    let user_id = flow.user_id.ok_or(AppError::Unauthorized)?;
    if !approve {
        deny_device(state, &flow).await?;
        return Ok(ConsentOutcome::Denied {
            redirect_to: denial_redirect(state, tenant, &flow).await?,
        });
    }
    // Consent is the user's to give; an administrator signed in as them
    // may only use what the user already agreed to.
    if let Some(sid) = flow.session_id
        && sessions::get(state, tenant.id, sid, &tenant.settings.session)
            .await?
            .is_some_and(|s| s.impersonator.is_some())
    {
        return Err(AppError::ImpersonationForbidden);
    }
    let client = client_of(state, &flow).await?;
    let granted = granted.unwrap_or_else(|| flow.pending_scopes.clone());
    // `openid` can never be dropped; anything not requested is ignored.
    let mut effective: Vec<String> = flow
        .request
        .scopes
        .iter()
        .filter(|s| *s == "openid" || granted.contains(s) || !flow.pending_scopes.contains(s))
        .cloned()
        .collect();
    effective.dedup();
    consents::grant(state, tenant.id, user_id, client.id, &effective).await?;
    flow.request.scopes = effective;
    flow.pending_scopes.clear();
    flow.stage = FlowStage::Done;
    advance(state, tenant, &mut flow, false).await?;
    login_flows::save(state, &flow).await?;
    Ok(ConsentOutcome::Granted {
        flow: Box::new(flow),
    })
}

pub enum ConsentOutcome {
    Granted { flow: Box<LoginFlow> },
    Denied { redirect_to: String },
}

/// Client-facing error redirect used by cancel and consent denial. A SAML
/// SP gets a `RequestDenied` response instead, posted through a one-time
/// URL of rIDM's.
pub async fn denial_redirect(
    state: &AppState,
    tenant: &Tenant,
    flow: &LoginFlow,
) -> AppResult<String> {
    if flow.request.saml.is_some() {
        return crate::services::saml_idp::denial_url(state, tenant, &flow.request).await;
    }
    Ok(error_redirect(flow, "the user denied the request"))
}

/// `access_denied` back to the client, with a reason the client may show.
fn error_redirect(flow: &LoginFlow, description: &str) -> String {
    let mut u = url::Url::parse(&flow.request.redirect_uri).expect("validated redirect uri");
    {
        let mut q = u.query_pairs_mut();
        q.append_pair("error", "access_denied");
        q.append_pair("error_description", description);
        if let Some(s) = &flow.request.state {
            q.append_pair("state", s);
        }
    }
    u.to_string()
}

/// `POST /flows/{id}/cancel`
pub async fn cancel(state: &AppState, tenant: &Tenant, flow: &LoginFlow) -> AppResult<String> {
    deny_device(state, flow).await?;
    login_flows::delete(state, flow.tenant_id, flow.id).await?;
    denial_redirect(state, tenant, flow).await
}

/// A device authorization the flow was approving is denied with it.
async fn deny_device(state: &AppState, flow: &LoginFlow) -> AppResult<()> {
    if let Some(hash) = &flow.request.device_code {
        crate::services::device_codes::deny(state, flow.tenant_id, hash).await?;
    }
    Ok(())
}

/// Request-derived facts an authentication step needs.
#[derive(Default)]
pub struct RequestContext {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    /// An SSO session the browser already has (re-authentication).
    pub existing_session: Option<SsoSession>,
    /// Trusted-device cookie value, if the browser sent one.
    pub device_secret: Option<String>,
    /// "Remember this device" was ticked.
    pub remember_device: bool,
    /// Where the address is, for the risk policy's location signals; `None`
    /// when the deployment has no geo source or it knows nothing about this
    /// address.
    pub location: Option<Location>,
}

/// What a sign-in is judged on, worked out before any session exists so that
/// a refused sign-in leaves nothing behind.
pub struct Assessment {
    /// The browser's trusted-device cookie, if it holds a live one.
    pub trusted: Option<TrustedDevice>,
    /// The user has signed in before, but never from this browser.
    pub new_browser: bool,
    pub risk: RiskAssessment,
}

/// Verify the device cookie, recognise the browser and score the sign-in.
/// Nothing here writes anything: the caller decides whether this sign-in
/// happens at all.
async fn assess(
    state: &AppState,
    tenant: &Tenant,
    user: &User,
    ctx: &RequestContext,
) -> AppResult<Assessment> {
    let trusted = match &ctx.device_secret {
        Some(secret) => {
            trusted_devices::verify_secret(state, tenant, user.id, secret, ctx.ip.as_deref())
                .await?
        }
        None => None,
    };
    let new_browser = trusted.is_none()
        && is_new_browser(state, tenant.id, user.id, ctx.user_agent.as_deref(), None).await?;
    let risk = risk::evaluate(
        state,
        tenant,
        user.id,
        &risk::Inputs {
            ip: ctx.ip.as_deref(),
            location: ctx.location.as_ref(),
            new_device: new_browser,
        },
    )
    .await?;
    Ok(Assessment {
        trusted,
        new_browser,
        risk,
    })
}

/// A sign-in the risk policy refused: the credentials were right, but this
/// attempt is not allowed to become a session. The flow is discarded and the
/// browser is sent back to the client with `access_denied`.
async fn refuse(
    state: &AppState,
    tenant: &Tenant,
    flow: &LoginFlow,
    user: &User,
    assessment: &RiskAssessment,
    ctx: &RequestContext,
) -> AppResult<AuthStep> {
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    repos::login_attempts::record(
        &mut *tx,
        tenant.id,
        &user.username,
        ctx.ip.as_deref(),
        false,
        Some("risk_blocked"),
    )
    .await?;
    tx.commit().await?;
    metrics::counter!("ridm_logins_total", "method" => "risk", "outcome" => "blocked").increment(1);
    risk::announce(
        state,
        tenant.id,
        user.id,
        assessment,
        ctx.ip.clone(),
        ctx.user_agent.clone(),
    );
    tracing::info!(
        tenant_id = %tenant.id,
        user_id = %user.id,
        score = assessment.score,
        signals = ?assessment.signal_names(),
        "sign-in refused by the risk policy"
    );
    deny_device(state, flow).await?;
    login_flows::delete(state, flow.tenant_id, flow.id).await?;
    let redirect_to = if flow.request.saml.is_some() {
        crate::services::saml_idp::refusal_url(
            state,
            tenant,
            &flow.request,
            crate::saml::ns::status::AUTHN_FAILED,
            "the sign-in was refused",
        )
        .await?
    } else {
        error_redirect(flow, "the sign-in was refused")
    };
    Ok(AuthStep::Blocked { redirect_to })
}

/// Is `acr` an authentication context class that means "a second factor
/// passed"? rIDM's own is [`ACR_MFA`]; any class ending in `:mfa` counts, so
/// a client may name its own.
pub fn is_mfa_acr(acr: &str) -> bool {
    acr.ends_with(":mfa")
}

/// The MFA class a request asks for, if any.
///
/// `acr_values` is a preference list, most preferred first (OIDC Core
/// §3.1.2.1), and rIDM honours the first class it recognises: an MFA class
/// there is a step-up request, while a weaker class ahead of it means the
/// client will settle for that. Classes rIDM cannot assert are skipped, and
/// asking for none of them is voluntary either way — the session's actual
/// class is what the token reports.
pub fn requested_mfa_class(acr_values: &[String]) -> Option<&str> {
    acr_values
        .iter()
        .map(String::as_str)
        .find(|a| is_mfa_acr(a) || *a == ACR_SINGLE)
        .filter(|a| is_mfa_acr(a))
}

/// Whether the flow must pass a second factor before continuing.
///
/// A step-up the client asked for (an `acr_values` class ending in `:mfa`)
/// is always honoured, even on a trusted device, and so is one the risk
/// policy demanded when this sign-in was scored: the device cookie says
/// which browser this is, not who is holding it. Policy-driven MFA is
/// skipped on a trusted device: `required` asks everyone (enrolling first
/// when needed); `required_for_roles` asks holders of any listed role
/// (direct, through groups or composites) and `required_for_admins` asks
/// anyone holding an admin-console permission, both treating everyone else
/// as `optional`, which asks users who enrolled a factor.
pub async fn mfa_required(
    state: &AppState,
    tenant: &Tenant,
    flow: &LoginFlow,
    user: &User,
) -> AppResult<bool> {
    if flow.amr.iter().any(|m| m == "mfa") {
        return Ok(false);
    }
    if requested_mfa_class(&flow.request.acr_values).is_some() || flow.risk_step_up {
        return Ok(true);
    }
    if flow.trusted_device {
        return Ok(false);
    }
    policy_requires_mfa(state, tenant, user).await
}

/// The tenant's MFA policy alone, for `user`: `required` asks everyone,
/// `required_for_roles` / `required_for_admins` ask the users they name and
/// treat everyone else as `optional`, which asks users who enrolled a factor.
/// Trusted devices and client step-ups are the caller's business.
pub async fn policy_requires_mfa(
    state: &AppState,
    tenant: &Tenant,
    user: &User,
) -> AppResult<bool> {
    let required = match &tenant.settings.mfa {
        MfaPolicy::Off => return Ok(false),
        MfaPolicy::Required => true,
        MfaPolicy::Optional => false,
        MfaPolicy::RequiredForRoles { roles } => {
            let held = roles::effective_role_names(state, tenant.id, user.id, None).await?;
            roles.iter().any(|r| held.iter().any(|h| h == r))
        }
        MfaPolicy::RequiredForAdmins => {
            // An organization's administrator is an administrator too, and no
            // organization has been chosen at this point in the flow.
            !admin_access::permissions_of_user(
                state,
                tenant.id,
                user.id,
                admin_access::OrgScope::Anywhere,
            )
            .await?
            .is_empty()
        }
    };
    Ok(required || totp::has_second_factor(state, tenant.id, user.id).await?)
}

/// What a live SSO session still owes before anything may be issued on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owed {
    /// Nothing: the session may be used as it is.
    Nothing,
    /// This step, first.
    Step(FlowStage),
    /// The risk policy refused to let this session be used from here. There
    /// is nothing the browser can do about it in this request.
    Blocked,
}

impl Owed {
    pub fn step(self) -> Option<FlowStage> {
        match self {
            Self::Step(s) => Some(s),
            _ => None,
        }
    }
}

/// The step a live SSO session still owes before anything may be issued on
/// it, or [`Owed::Nothing`] when it is complete.
///
/// A flow opens the session as soon as the first factor passes and then
/// walks the remaining steps, so a browser that abandons the flow holds a
/// session that never passed them. Every place that turns a session into a
/// grant asks this first, from the policy as it stands now (so a policy
/// tightened after sign-in, or a role granted since, counts too): a password
/// the user must change, then the second factor the tenant's policy demands.
/// A trusted device (the browser's device cookie, exactly as the flow reads
/// it) waives policy MFA the same way it does in the flow. A user who is
/// gone or no longer active owes a fresh sign-in (`Authenticate`).
///
/// The risk policy is asked here too, because a session that opened from a
/// safe place can be reused from anywhere: a silent sign-in from a new
/// country steps up to the second factor, and one the policy blocks cannot
/// be used at all. The session itself is the browser's history, so the
/// device signal never fires on this path — location and velocity do.
pub async fn unfinished_stage(
    state: &AppState,
    tenant: &Tenant,
    session: &SsoSession,
    headers: &axum::http::HeaderMap,
    origin: (Option<&str>, Option<&Location>),
) -> AppResult<Owed> {
    let user = match users::get(state, tenant.id, session.user_id).await {
        Ok(u) if matches!(u.status, UserStatus::Active | UserStatus::Pending) => u,
        Ok(_) | Err(AppError::NotFound(_)) => return Ok(Owed::Step(FlowStage::Authenticate)),
        Err(e) => return Err(e),
    };
    // An administrator's session as the user owes none of the user's steps:
    // they could not pass them, and the policy judges the user's own
    // sign-ins. Opening it was checked and audited instead.
    if session.impersonator.is_some() {
        return Ok(Owed::Nothing);
    }
    if user.must_change_password && tenant.settings.auth.password {
        return Ok(Owed::Step(FlowStage::PasswordChange));
    }
    let (ip, location) = origin;
    let risk = risk::evaluate(
        state,
        tenant,
        user.id,
        &risk::Inputs {
            ip,
            location,
            new_device: false,
        },
    )
    .await?;
    if risk.is_blocked() {
        risk::announce(
            state,
            tenant.id,
            user.id,
            &risk,
            ip.map(str::to_string),
            None,
        );
        return Ok(Owed::Blocked);
    }
    let stepped_up = session.amr.iter().any(|m| m == "mfa");
    if risk.steps_up() && !stepped_up {
        risk::announce(
            state,
            tenant.id,
            user.id,
            &risk,
            ip.map(str::to_string),
            None,
        );
        return Ok(Owed::Step(FlowStage::Mfa));
    }
    if stepped_up || !policy_requires_mfa(state, tenant, &user).await? {
        return Ok(Owed::Nothing);
    }
    if trusted_devices::is_trusted(state, tenant, user.id, headers, None)
        .await?
        .is_some()
    {
        return Ok(Owed::Nothing);
    }
    Ok(Owed::Step(FlowStage::Mfa))
}

/// Outcome of a second-factor step.
pub enum MfaStep {
    /// The factor passed; `recovery_codes` is set once, right after enrolment.
    Passed {
        flow: Box<LoginFlow>,
        recovery_codes: Option<Vec<String>>,
    },
    /// Wrong code; the flow (with its attempt counter) was saved, or discarded
    /// once [`MFA_MAX_ATTEMPTS`] is reached.
    Rejected { flow: Box<LoginFlow> },
}

/// The signed-in user of a flow waiting at the `mfa` stage.
async fn mfa_user(state: &AppState, tenant: &TenantCtx, flow: &LoginFlow) -> AppResult<User> {
    if flow.stage != FlowStage::Mfa {
        return Err(AppError::BadRequest(
            "flow is not at the second-factor step".into(),
        ));
    }
    let user_id = flow.user_id.ok_or(AppError::Unauthorized)?;
    let user = users::get(state, tenant.id(), user_id).await?;
    if user.status != UserStatus::Active && user.status != UserStatus::Pending {
        return Err(AppError::Forbidden("account is not active".into()));
    }
    Ok(user)
}

/// `POST /flows/{id}/mfa/totp/enroll`: a fresh authenticator secret for a
/// user who has none yet.
pub async fn mfa_enrol_begin(
    state: &AppState,
    tenant: &TenantCtx,
    flow: &LoginFlow,
) -> AppResult<totp::Enrolment> {
    let user = mfa_user(state, tenant, flow).await?;
    if !tenant.tenant.settings.mfa_methods.totp {
        return Err(AppError::BadRequest(
            "authenticator apps are disabled for this tenant".into(),
        ));
    }
    if totp::factors_of(state, tenant.id(), user.id).await?.totp {
        return Err(AppError::BadRequest(
            "an authenticator app is already enrolled".into(),
        ));
    }
    totp::begin_enrolment(state, &tenant.tenant, flow.id, &user).await
}

/// `POST /flows/{id}/mfa/{email|sms}/enroll`: a code to the address or
/// number that is about to become the user's second factor.
pub async fn mfa_otp_enrol_begin(
    state: &AppState,
    tenant: &TenantCtx,
    flow: &LoginFlow,
    channel: otp_factors::Channel,
    phone: Option<&str>,
) -> AppResult<otp_factors::Sent> {
    let user = mfa_user(state, tenant, flow).await?;
    otp_factors::begin_enrolment(
        state,
        &tenant.tenant,
        otp_scope(flow),
        &user,
        channel,
        phone,
    )
    .await
}

/// `POST /flows/{id}/mfa/{email|sms}/confirm`: prove the pending enrolment;
/// the factor then counts as passed for this sign-in.
pub async fn mfa_otp_enrol_confirm(
    state: &AppState,
    tenant: &TenantCtx,
    mut flow: LoginFlow,
    channel: otp_factors::Channel,
    code: &str,
    remember_device: bool,
    ip: Option<String>,
) -> AppResult<MfaStep> {
    let user = mfa_user(state, tenant, &flow).await?;
    if otp_factors::confirm_enrolment(
        state,
        &tenant.tenant,
        otp_scope(&flow),
        &user,
        channel,
        code,
    )
    .await?
    {
        let recovery_codes = first_recovery_codes(state, tenant, &user).await?;
        pass_second_factor(
            state,
            tenant,
            &mut flow,
            &user,
            channel.amr(),
            remember_device,
        )
        .await?;
        Ok(MfaStep::Passed {
            flow: Box::new(flow),
            recovery_codes,
        })
    } else {
        mfa_reject(state, tenant, flow, &user, ip).await
    }
}

/// `POST /flows/{id}/mfa/{email|sms}/send`: a sign-in code to the enrolled channel.
pub async fn mfa_otp_send(
    state: &AppState,
    tenant: &TenantCtx,
    flow: &LoginFlow,
    channel: otp_factors::Channel,
) -> AppResult<otp_factors::Sent> {
    let user = mfa_user(state, tenant, flow).await?;
    otp_factors::send_code(state, &tenant.tenant, otp_scope(flow), &user, channel).await
}

/// `POST /flows/{id}/mfa/{email|sms}/verify`
pub async fn mfa_otp_verify(
    state: &AppState,
    tenant: &TenantCtx,
    mut flow: LoginFlow,
    channel: otp_factors::Channel,
    code: &str,
    remember_device: bool,
    ip: Option<String>,
) -> AppResult<MfaStep> {
    let user = mfa_user(state, tenant, &flow).await?;
    if otp_factors::verify(
        state,
        &tenant.tenant,
        otp_scope(&flow),
        &user,
        channel,
        code,
    )
    .await?
    {
        pass_second_factor(
            state,
            tenant,
            &mut flow,
            &user,
            channel.amr(),
            remember_device,
        )
        .await?;
        Ok(MfaStep::Passed {
            flow: Box::new(flow),
            recovery_codes: None,
        })
    } else {
        mfa_reject(state, tenant, flow, &user, ip).await
    }
}

/// Codes of a flow live under its id, in the locales it asked for.
fn otp_scope(flow: &LoginFlow) -> otp_factors::Scope<'_> {
    otp_factors::Scope {
        id: flow.id,
        ui_locales: &flow.request.ui_locales,
    }
}

/// A user's first second factor comes with recovery codes, shown once.
async fn first_recovery_codes(
    state: &AppState,
    tenant: &TenantCtx,
    user: &User,
) -> AppResult<Option<Vec<String>>> {
    if totp::factors_of(state, tenant.id(), user.id)
        .await?
        .recovery_codes
        == 0
    {
        Ok(Some(
            totp::regenerate_recovery_codes(state, tenant.id(), user.id).await?,
        ))
    } else {
        Ok(None)
    }
}

/// `POST /flows/{id}/mfa/totp/confirm`: prove the pending enrolment; the
/// factor then counts as passed for this sign-in.
pub async fn mfa_enrol_confirm(
    state: &AppState,
    tenant: &TenantCtx,
    mut flow: LoginFlow,
    code: &str,
    label: Option<&str>,
    remember_device: bool,
    ip: Option<String>,
) -> AppResult<MfaStep> {
    let user = mfa_user(state, tenant, &flow).await?;
    match totp::confirm_enrolment(state, &tenant.tenant, flow.id, &user, code, label).await? {
        Some(codes) => {
            pass_second_factor(state, tenant, &mut flow, &user, &["otp"], remember_device).await?;
            Ok(MfaStep::Passed {
                flow: Box::new(flow),
                recovery_codes: Some(codes),
            })
        }
        None => mfa_reject(state, tenant, flow, &user, ip).await,
    }
}

/// `POST /flows/{id}/mfa/verify`: an authenticator code or a recovery code.
pub async fn mfa_verify_step(
    state: &AppState,
    tenant: &TenantCtx,
    mut flow: LoginFlow,
    code: &str,
    remember_device: bool,
    ip: Option<String>,
) -> AppResult<MfaStep> {
    let user = mfa_user(state, tenant, &flow).await?;
    match totp::verify(state, &tenant.tenant, &user, code).await? {
        Some(totp::Verified::Totp { .. }) => {
            pass_second_factor(state, tenant, &mut flow, &user, &["otp"], remember_device).await?;
            Ok(MfaStep::Passed {
                flow: Box::new(flow),
                recovery_codes: None,
            })
        }
        Some(totp::Verified::RecoveryCode { .. }) => {
            pass_second_factor(state, tenant, &mut flow, &user, &[], remember_device).await?;
            Ok(MfaStep::Passed {
                flow: Box::new(flow),
                recovery_codes: None,
            })
        }
        None => mfa_reject(state, tenant, flow, &user, ip).await,
    }
}

/// Record the second factor on the session (`amr` gains `mfa` plus the
/// method, `acr` the requested or default MFA class) and move the flow on.
async fn pass_second_factor(
    state: &AppState,
    tenant: &TenantCtx,
    flow: &mut LoginFlow,
    user: &User,
    methods: &[&str],
    remember_device: bool,
) -> AppResult<()> {
    let session_id = flow.session_id.ok_or(AppError::Unauthorized)?;
    let mut session = sessions::get(
        state,
        tenant.id(),
        session_id,
        &tenant.tenant.settings.session,
    )
    .await?
    .filter(|s| s.user_id == user.id)
    .ok_or(AppError::Unauthorized)?;
    let mut amr = flow.amr.clone();
    for m in methods.iter().copied().chain(std::iter::once("mfa")) {
        if !amr.iter().any(|a| a == m) {
            amr.push(m.to_string());
        }
    }
    let acr = requested_mfa_acr(flow);
    sessions::refresh_auth(state, &mut session, amr.clone(), Some(acr)).await?;
    flow.amr = amr;
    flow.remember_device = (flow.remember_device || remember_device) && !flow.trusted_device;
    flow.attempts = 0;
    advance(state, &tenant.tenant, flow, false).await?;
    login_flows::save(state, flow).await
}

/// The MFA class the session asserts: the `*:mfa` class the client asked
/// for, else the default.
fn requested_mfa_acr(flow: &LoginFlow) -> String {
    requested_mfa_class(&flow.request.acr_values)
        .unwrap_or(ACR_MFA)
        .to_string()
}

/// `POST /flows/{id}/mfa/passkey/register`: creation options for a new
/// passkey as the user's second factor.
pub async fn mfa_passkey_register_begin(
    state: &AppState,
    tenant: &TenantCtx,
    flow: &LoginFlow,
) -> AppResult<CreationChallengeResponse> {
    let user = mfa_user(state, tenant, flow).await?;
    require_passkeys_enabled(tenant)?;
    passkeys::begin_registration(state, &tenant.tenant, flow.id, &user).await
}

/// `POST /flows/{id}/mfa/passkey/register/finish`: store the passkey; it
/// counts as passed for this sign-in. A user without recovery codes gets a
/// set now, shown once.
pub async fn mfa_passkey_register_finish(
    state: &AppState,
    tenant: &TenantCtx,
    mut flow: LoginFlow,
    credential: &RegisterPublicKeyCredential,
    label: Option<&str>,
    remember_device: bool,
    ip: Option<String>,
) -> AppResult<MfaStep> {
    let user = mfa_user(state, tenant, &flow).await?;
    require_passkeys_enabled(tenant)?;
    match passkeys::finish_registration(state, &tenant.tenant, flow.id, &user, credential, label)
        .await?
    {
        Some(_) => {
            let recovery_codes = first_recovery_codes(state, tenant, &user).await?;
            pass_second_factor(
                state,
                tenant,
                &mut flow,
                &user,
                &["hwk", "user"],
                remember_device,
            )
            .await?;
            Ok(MfaStep::Passed {
                flow: Box::new(flow),
                recovery_codes,
            })
        }
        None => mfa_reject(state, tenant, flow, &user, ip).await,
    }
}

/// `POST /flows/{id}/mfa/passkey/start`: an assertion challenge against the
/// user's passkeys.
pub async fn mfa_passkey_begin(
    state: &AppState,
    tenant: &TenantCtx,
    flow: &LoginFlow,
) -> AppResult<RequestChallengeResponse> {
    let user = mfa_user(state, tenant, flow).await?;
    passkeys::begin_authentication(state, &tenant.tenant, flow.id, &user).await
}

/// `POST /flows/{id}/mfa/passkey/finish`
pub async fn mfa_passkey_finish(
    state: &AppState,
    tenant: &TenantCtx,
    mut flow: LoginFlow,
    credential: &PublicKeyCredential,
    remember_device: bool,
    ip: Option<String>,
) -> AppResult<MfaStep> {
    let user = mfa_user(state, tenant, &flow).await?;
    match passkeys::finish_authentication(state, &tenant.tenant, flow.id, &user, credential).await?
    {
        Some(v) => {
            let methods: &[&str] = if v.user_verified {
                &["hwk", "user"]
            } else {
                &["hwk"]
            };
            pass_second_factor(state, tenant, &mut flow, &user, methods, remember_device).await?;
            Ok(MfaStep::Passed {
                flow: Box::new(flow),
                recovery_codes: None,
            })
        }
        None => mfa_reject(state, tenant, flow, &user, ip).await,
    }
}

fn require_passkeys_enabled(tenant: &TenantCtx) -> AppResult<()> {
    if tenant.tenant.settings.auth.passkey {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "passkeys are disabled for this tenant".into(),
        ))
    }
}

/// `POST /flows/{id}/passkey/start`: a challenge any discoverable passkey of
/// the tenant may answer (passwordless sign-in).
pub async fn passkey_begin(
    state: &AppState,
    tenant: &TenantCtx,
    flow: &LoginFlow,
) -> AppResult<RequestChallengeResponse> {
    if flow.stage != FlowStage::Authenticate {
        return Err(AppError::BadRequest(
            "flow is not at the authenticate step".into(),
        ));
    }
    require_passkeys_enabled(tenant)?;
    passkeys::begin_discoverable(state, &tenant.tenant, flow.id).await
}

/// `POST /flows/{id}/passkey/finish`: sign the passkey's owner in. With user
/// verification the assertion is two factors (`hwk`, `user`, `mfa`), so no
/// second step follows.
pub async fn passkey_finish(
    state: &AppState,
    tenant: &TenantCtx,
    mut flow: LoginFlow,
    credential: &PublicKeyCredential,
    ctx: RequestContext,
) -> AppResult<AuthStep> {
    if flow.stage != FlowStage::Authenticate {
        return Err(AppError::BadRequest(
            "flow is not at the authenticate step".into(),
        ));
    }
    require_passkeys_enabled(tenant)?;
    let Some((user_id, verified)) =
        passkeys::finish_discoverable(state, &tenant.tenant, flow.id, credential).await?
    else {
        flow.attempts += 1;
        login_flows::save(state, &flow).await?;
        state.events.publish(
            Event::new(
                Some(tenant.id()),
                Actor::System,
                EventKind::LoginFailed {
                    identifier: String::new(),
                    reason: "passkey_invalid".into(),
                },
            )
            .with_request(ctx.ip.clone(), None),
        );
        return Ok(AuthStep::Rejected {
            flow: Box::new(flow),
            locked: false,
        });
    };
    let user = users::get(state, tenant.id(), user_id).await?;
    if user.status != UserStatus::Active && user.status != UserStatus::Pending {
        return Err(AppError::Forbidden("account is not active".into()));
    }
    let mut amr = vec!["hwk".to_string()];
    if verified.user_verified {
        amr.push("user".into());
        amr.push("mfa".into());
    }
    let must_change = user.must_change_password && tenant.tenant.settings.auth.password;
    complete_authentication(state, tenant, flow, &user, amr, ctx, must_change).await
}

async fn mfa_reject(
    state: &AppState,
    tenant: &TenantCtx,
    mut flow: LoginFlow,
    user: &User,
    ip: Option<String>,
) -> AppResult<MfaStep> {
    flow.attempts += 1;
    if flow.attempts >= MFA_MAX_ATTEMPTS {
        login_flows::delete(state, tenant.id(), flow.id).await?;
    } else {
        login_flows::save(state, &flow).await?;
    }
    state.events.publish(
        Event::new(
            Some(tenant.id()),
            Actor::User { id: user.id },
            EventKind::LoginFailed {
                identifier: user.username.clone(),
                reason: "mfa_invalid".into(),
            },
        )
        .with_request(ip, None),
    );
    Ok(MfaStep::Rejected {
        flow: Box::new(flow),
    })
}

/// Open (or re-authenticate) the browser's session for `user_id`, recognise
/// a trusted device, and record both on the flow.
async fn open_session(
    state: &AppState,
    tenant: &Tenant,
    flow: &mut LoginFlow,
    user: &User,
    amr: Vec<String>,
    ctx: RequestContext,
    assessment: Assessment,
) -> AppResult<SsoSession> {
    let user_id = user.id;
    let RequestContext {
        ip,
        user_agent,
        existing_session,
        device_secret: _,
        remember_device,
        location,
    } = ctx;
    let Assessment {
        trusted,
        new_browser,
        risk,
    } = assessment;
    // A first factor that is itself multi-factor (a passkey with user
    // verification) asserts the MFA class straight away.
    let acr = Some(if amr.iter().any(|m| m == "mfa") {
        requested_mfa_acr(flow)
    } else {
        ACR_SINGLE.to_string()
    });
    let mut session = match existing_session {
        Some(mut s) if s.user_id == user_id => {
            sessions::refresh_auth(state, &mut s, amr.clone(), acr).await?;
            s
        }
        _ => {
            let session = sessions::create(
                state,
                tenant.id,
                NewSession {
                    user_id,
                    amr: amr.clone(),
                    acr,
                    ip: ip.clone(),
                    user_agent: user_agent.clone(),
                    policy: &tenant.settings.session,
                },
            )
            .await?;
            // A returning user on an unrecognised browser: tell them.
            if new_browser {
                state.events.publish(
                    Event::new(
                        Some(tenant.id),
                        Actor::User { id: user_id },
                        EventKind::NewDeviceLogin {
                            user_id,
                            session_id: session.id,
                        },
                    )
                    .with_request(ip.clone(), user_agent.clone()),
                );
                notifications::new_device_login(
                    state,
                    tenant,
                    user,
                    ip.as_deref(),
                    user_agent.as_deref(),
                )
                .await;
            }
            session
        }
    };
    if let Some(d) = &trusted
        && session.device_id != Some(d.id)
    {
        sessions::bind_device(state, &mut session, d.id).await?;
    }
    // This sign-in was allowed, so where it came from becomes part of what
    // the next one is judged against.
    risk::record_location(state, tenant, user_id, location.as_ref()).await?;
    risk::announce(
        state,
        tenant.id,
        user_id,
        &risk,
        ip.clone(),
        user_agent.clone(),
    );
    // A verified address at a verified auto-join domain joins its organization
    // as the session opens, so enabling a domain reaches the users a tenant
    // already has. Before the stage is computed, so the new membership counts.
    organizations::ensure_auto_join(state, tenant.id, user).await?;
    flow.user_id = Some(user_id);
    flow.session_id = Some(session.id);
    flow.amr = amr;
    flow.trusted_device = trusted.is_some();
    flow.risk_step_up = risk.steps_up();
    // Already trusted: nothing to register at the end of the flow.
    flow.remember_device = remember_device && trusted.is_none();
    Ok(session)
}

/// True when the user has signed in before but never from this browser.
/// Without a user agent nothing can be compared, so nothing is claimed.
///
/// `exclude_session` leaves one session out of the comparison; asked before
/// a session exists, there is nothing to leave out.
async fn is_new_browser(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    user_agent: Option<&str>,
    exclude_session: Option<Uuid>,
) -> AppResult<bool> {
    let Some(ua) = user_agent else {
        return Ok(false);
    };
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let (any_before, same_browser) = repos::sessions::browser_history(
        &mut *tx,
        tenant_id,
        user_id,
        ua,
        exclude_session.unwrap_or(Uuid::nil()),
    )
    .await?;
    tx.commit().await?;
    Ok(any_before && !same_browser)
}

/// Shared tail of every successful first-factor authentication: session,
/// flow bookkeeping, stage evaluation.
pub async fn complete_authentication(
    state: &AppState,
    tenant: &TenantCtx,
    mut flow: LoginFlow,
    user: &User,
    amr: Vec<String>,
    ctx: RequestContext,
    must_change_password: bool,
) -> AppResult<AuthStep> {
    let ip = ctx.ip.clone();
    let tid = tenant.id();
    // Scored before anything is written: a refused sign-in leaves no session,
    // no flow and no successful attempt behind it.
    let assessment = assess(state, &tenant.tenant, user, &ctx).await?;
    if assessment.risk.is_blocked() {
        return refuse(state, &tenant.tenant, &flow, user, &assessment.risk, &ctx).await;
    }
    let mut tx = db::tenant_tx(&state.db, tid).await?;
    repos::users::record_login_success(&mut *tx, tid, user.id).await?;
    repos::login_attempts::record(&mut *tx, tid, &user.username, ip.as_deref(), true, None).await?;
    tx.commit().await?;
    metrics::counter!(
        "ridm_logins_total",
        "method" => amr.first().cloned().unwrap_or_else(|| "unknown".into()),
        "outcome" => "success"
    )
    .increment(1);
    let session = open_session(
        state,
        &tenant.tenant,
        &mut flow,
        user,
        amr.clone(),
        ctx,
        assessment,
    )
    .await?;
    advance(state, &tenant.tenant, &mut flow, must_change_password).await?;
    login_flows::save(state, &flow).await?;
    state.events.publish(
        Event::new(
            Some(tid),
            Actor::User { id: user.id },
            EventKind::LoginSucceeded {
                user_id: user.id,
                method: amr.first().cloned().unwrap_or_default(),
            },
        )
        .with_request(ip, None),
    );
    Ok(AuthStep::Authenticated {
        session: Box::new(session),
        flow: Box::new(flow),
    })
}

/// `POST /flows/{id}/{magic-link|email-otp|sms-otp}`: send a passwordless factor.
pub async fn passwordless_send_step(
    state: &AppState,
    tenant: &TenantCtx,
    flow: &LoginFlow,
    method: crate::services::passwordless::Method,
    identifier: &str,
    captcha_token: Option<&str>,
    ip: Option<&str>,
) -> AppResult<()> {
    if flow.stage != FlowStage::Authenticate {
        return Err(AppError::BadRequest(
            "flow is not at the authenticate step".into(),
        ));
    }
    enforce_captcha(state, &tenant.tenant, flow, captcha_token, ip).await?;
    crate::services::passwordless::send(state, &tenant.tenant, flow, method, identifier).await
}

/// `POST /flows/{id}/{email-otp|sms-otp}/verify` and `/magic-link/verify`.
pub async fn passwordless_verify_step(
    state: &AppState,
    tenant: &TenantCtx,
    mut flow: LoginFlow,
    method: crate::services::passwordless::Method,
    secret: &str,
    ctx: RequestContext,
) -> AppResult<AuthStep> {
    use crate::services::passwordless::{self, Method};
    if flow.stage != FlowStage::Authenticate {
        return Err(AppError::BadRequest(
            "flow is not at the authenticate step".into(),
        ));
    }
    let verified = match method {
        Method::MagicLink => {
            passwordless::verify_magic_link(state, &tenant.tenant, &flow, secret).await?
        }
        Method::EmailOtp | Method::SmsOtp => {
            passwordless::verify_otp(state, &tenant.tenant, &flow, method, secret).await?
        }
    };
    let Some(v) = verified else {
        flow.attempts += 1;
        login_flows::save(state, &flow).await?;
        state.events.publish(
            Event::new(
                Some(tenant.id()),
                Actor::System,
                EventKind::LoginFailed {
                    identifier: String::new(),
                    reason: format!("{}_invalid", method.as_str()),
                },
            )
            .with_request(ctx.ip.clone(), None),
        );
        return Ok(AuthStep::Rejected {
            flow: Box::new(flow),
            locked: false,
        });
    };
    let user = users::get(state, tenant.id(), v.user_id).await?;
    if user.status != UserStatus::Active && user.status != UserStatus::Pending {
        return Err(AppError::Forbidden("account is not active".into()));
    }
    passwordless::mark_contact_verified(state, tenant.id(), user.id, method).await?;
    let amr = match method {
        Method::SmsOtp => vec!["otp".into(), "sms".into()],
        _ => vec!["otp".into()],
    };
    let must_change = user.must_change_password && tenant.tenant.settings.auth.password;
    complete_authentication(state, tenant, flow, &user, amr, ctx, must_change).await
}

/// `POST /flows/{id}/register`: create the account from the login or
/// registration page. With email verification on, the flow waits at
/// `VerifyEmail` until the link is opened; otherwise the user is signed in.
pub async fn register_step(
    state: &AppState,
    tenant: &TenantCtx,
    mut flow: LoginFlow,
    input: crate::services::registration::RegistrationInput,
    captcha_token: Option<&str>,
    ctx: RequestContext,
) -> AppResult<AuthStep> {
    if !matches!(flow.stage, FlowStage::Authenticate | FlowStage::Register) {
        return Err(AppError::BadRequest(
            "flow does not accept registration at this step".into(),
        ));
    }
    // Registration always counts as the CAPTCHA-protected path when configured.
    if tenant.tenant.settings.captcha.on_registration {
        let mut probe = flow.clone();
        probe.stage = FlowStage::Register;
        enforce_captcha(
            state,
            &tenant.tenant,
            &probe,
            captcha_token,
            ctx.ip.as_deref(),
        )
        .await?;
    }
    let (user, pending) = crate::services::registration::register(
        state,
        &tenant.tenant,
        input,
        Some(flow.id),
        &flow.request.ui_locales,
    )
    .await?;
    if pending {
        flow.user_id = Some(user.id);
        flow.stage = FlowStage::VerifyEmail;
        login_flows::save(state, &flow).await?;
        return Ok(AuthStep::Rejected {
            flow: Box::new(flow),
            locked: false,
        });
    }
    complete_authentication(state, tenant, flow, &user, vec!["pwd".into()], ctx, false).await
}

/// After the verification link was opened for a flow waiting at `VerifyEmail`,
/// sign the user in (proof of email control) and continue.
pub async fn resume_after_verification(
    state: &AppState,
    tenant: &TenantCtx,
    flow_id: Uuid,
    user: &User,
    ctx: RequestContext,
) -> AppResult<Option<AuthStep>> {
    let Some(flow) = login_flows::get(state, tenant.id(), flow_id).await? else {
        return Ok(None);
    };
    if flow.stage != FlowStage::VerifyEmail || flow.user_id != Some(user.id) {
        return Ok(None);
    }
    Ok(Some(
        complete_authentication(state, tenant, flow, user, vec!["otp".into()], ctx, false).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_first_recognised_acr_class_decides_a_step_up() {
        // Nothing asked for, or nothing rIDM knows: voluntary.
        assert_eq!(requested_mfa_class(&v(&[])), None);
        assert_eq!(requested_mfa_class(&v(&["urn:example:gold"])), None);
        // An MFA class alone, or preferred over a weaker one, is a step-up.
        assert_eq!(requested_mfa_class(&v(&[ACR_MFA])), Some(ACR_MFA));
        assert_eq!(
            requested_mfa_class(&v(&["urn:example:gold", ACR_MFA, ACR_SINGLE])),
            Some(ACR_MFA)
        );
        assert_eq!(
            requested_mfa_class(&v(&["urn:rp:own:mfa"])),
            Some("urn:rp:own:mfa")
        );
        // A class the session already reaches, preferred first, is enough.
        assert_eq!(requested_mfa_class(&v(&[ACR_SINGLE, ACR_MFA])), None);
    }
}
