//! rIDM as the SAML 2.0 service provider of an upstream identity provider
//! (an `identity_providers` row of kind `saml`).
//!
//! * [`start`] sends the browser to the IdP with an `AuthnRequest` (signed
//!   with the tenant's SAML key) and remembers, under a one-time
//!   `RelayState`, what the sign-in continues: a login flow, or linking to
//!   the account-console user.
//! * [`acs`] reads the `Response` the IdP posts back and checks it
//!   (`saml::sp::validate_response`). It remembers the assertion ID against
//!   replay and parks the proven identity for a same-site GET
//!   ([`resume`]): the session and trusted-device cookies are
//!   `SameSite=Lax`, so the cross-site POST carries neither. From there the
//!   sign-in is the broker's (`broker::conclude`), like any upstream kind.
//!   An unsolicited response, when the provider allows one, signs in
//!   without a flow and lands on a client's `initiate_login_uri` or the
//!   account console.
//! * Single Logout, front channel, both ways. The NameID and `SessionIndex`
//!   of every brokered session are kept with it. The IdP's `LogoutRequest`
//!   ends the matching sessions and walks the browser through their
//!   downstream SAML SPs before answering. A sign-out that starts at rIDM
//!   (`end_session`, the logout page) sends the IdP a `LogoutRequest` once
//!   the downstream SPs had their turn ([`logout_upstream`]).
//! * [`refresh_metadata`] re-reads an IdP's metadata URL: its endpoints and
//!   certificates replace the stored ones (the daily job and the admin API).

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::Utc;
use redis::AsyncCommands as _;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Digest as _;
use uuid::Uuid;

use crate::cache::keys as cache_keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::middleware::TenantCtx;
use crate::models::{IdentityProvider, IdpKind, SamlUpstream, SloBinding, Tenant};
use crate::oidc::authorize::error_page;
use crate::repos;
use crate::saml::binding::{self, Kind, Received};
use crate::saml::cert::Certificate;
use crate::saml::error::SamlError;
use crate::saml::protocol::{self, NameId};
use crate::saml::sp::{self, Asserted, Expected, ResponseError};
use crate::saml::xml::El;
use crate::saml::{dsig, metadata, ns, xml};
use crate::services::broker::{self, BrokerError, Identity, Mode, Outcome};
use crate::services::flows::RequestContext;
use crate::services::login_flows::{self, AuthRequest, FlowStage, LoginFlow, ResponseMode};
use crate::services::sessions::SsoSession;
use crate::services::{account_console, clients, identity_providers, saml_keys, tokens};
use crate::state::AppState;

/// How long the browser has to come back from the IdP.
const REQUEST_TTL_SECS: u64 = 10 * 60;
/// A proven identity waiting for the same-site GET.
const PARKED_TTL_SECS: u64 = 5 * 60;
/// A sign-out step waiting for the browser.
const LOGOUT_TTL_SECS: u64 = 10 * 60;
/// How long an upstream `LogoutRequest` ID is remembered against replay.
const REPLAY_TTL_SECS: u64 = 15 * 60;
const MAX_REQUEST_AGE: chrono::Duration = chrono::Duration::minutes(10);

/// rIDM's own SAML URLs for one upstream IdP. The entity ID is the
/// metadata URL, so an IdP administrator can fetch what it names.
pub struct SpEndpoints {
    pub entity_id: String,
    pub metadata_url: String,
    pub acs_url: String,
    pub slo_url: String,
}

pub fn endpoints(state: &AppState, tenant: &Tenant, alias: &str) -> SpEndpoints {
    let base = format!("{}/broker/{alias}/saml", tokens::issuer(state, tenant));
    SpEndpoints {
        entity_id: format!("{base}/metadata"),
        metadata_url: format!("{base}/metadata"),
        acs_url: format!("{base}/acs"),
        slo_url: format!("{base}/slo"),
    }
}

fn settings(idp: &IdentityProvider) -> AppResult<&SamlUpstream> {
    match (&idp.kind, &idp.saml) {
        (IdpKind::Saml, Some(s)) => Ok(s),
        _ => Err(AppError::NotFound("SAML identity provider")),
    }
}

fn certificates(s: &SamlUpstream) -> Vec<Certificate> {
    s.signing_certificates
        .iter()
        .filter_map(|c| Certificate::parse(c).ok())
        .collect()
}

fn key(tenant_id: Uuid, what: &str, id: &str) -> String {
    format!("{}:t:{tenant_id}:saml_sp:{what}:{id}", cache_keys::PREFIX)
}

fn hashed(s: &str) -> String {
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

fn random_token() -> String {
    let mut buf = [0u8; 32];
    rand::fill(&mut buf);
    hex::encode(buf)
}

async fn put<T: Serialize>(state: &AppState, k: String, v: &T, ttl: u64) -> AppResult<()> {
    let mut conn = state.redis.get().await?;
    let _: () = conn.set_ex(k, serde_json::to_string(v)?, ttl).await?;
    Ok(())
}

async fn take<T: serde::de::DeserializeOwned>(state: &AppState, k: String) -> AppResult<Option<T>> {
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = redis::cmd("GETDEL").arg(k).query_async(&mut conn).await?;
    Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
}

/// Remember `id` until `ttl`; false when it was seen before (a replay).
async fn first_sighting(state: &AppState, k: String, ttl: u64) -> AppResult<bool> {
    let mut conn = state.redis.get().await?;
    Ok(redis::cmd("SET")
        .arg(k)
        .arg(1)
        .arg("NX")
        .arg("EX")
        .arg(ttl.max(1))
        .query_async::<Option<String>>(&mut conn)
        .await?
        .is_some())
}

fn html_headers(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    res
}

fn saml_page(status: StatusCode, err: &SamlError) -> Response {
    tracing::info!(error = %err, "SAML message from an upstream IdP refused");
    error_page(status, "invalid_saml_message", &err.to_string())
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

/// rIDM's SP metadata for one upstream IdP.
pub async fn metadata(
    state: &AppState,
    tenant: &Tenant,
    idp: &IdentityProvider,
) -> AppResult<String> {
    let s = settings(idp)?;
    let ep = endpoints(state, tenant, &idp.alias);
    let certs = saml_keys::certificates(state, tenant).await?;
    Ok(metadata::sp_metadata(&metadata::SpMetadataOut {
        entity_id: &ep.entity_id,
        acs_url: &ep.acs_url,
        slo_url: &ep.slo_url,
        certificates: &certs,
        name_id_format: s.name_id_format.map(|f| f.urn()),
        authn_requests_signed: s.sign_requests,
        want_assertions_signed: s.want_assertions_signed,
    }))
}

// ---------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------

/// What a sign-in continues once the IdP answers.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingRequest {
    idp_id: Uuid,
    mode: Mode,
    request_id: String,
    /// The hash of the browser's binding cookie (`broker::binding_cookie`).
    browser: String,
}

/// Send the browser to the IdP with an `AuthnRequest`.
pub async fn start(
    state: &AppState,
    tenant: &TenantCtx,
    idp: &IdentityProvider,
    mode: Mode,
) -> AppResult<Response> {
    let s = settings(idp)?;
    if !idp.enabled {
        return Err(AppError::NotFound("identity provider"));
    }
    if let Mode::Flow { flow_id } = &mode {
        let flow = crate::services::flows::load(state, tenant.id(), *flow_id).await?;
        if !matches!(flow.stage, FlowStage::Authenticate | FlowStage::Register) {
            return Err(AppError::BadRequest(
                "flow does not accept a sign-in at this step".into(),
            ));
        }
    }
    let ep = endpoints(state, &tenant.tenant, &idp.alias);
    let (mut el, request_id) = sp::authn_request(&sp::AuthnRequestOut {
        sp_entity_id: &ep.entity_id,
        destination: &s.sso_url,
        acs_url: &ep.acs_url,
        name_id_format: s.name_id_format.map(|f| f.urn()),
        force_authn: s.force_authn,
        class_refs: &s.authn_context_class_refs,
        now: Utc::now(),
    });
    let relay = random_token();
    let (browser, browser_hash) = broker::new_binding();
    put(
        state,
        key(tenant.id(), "request", &hashed(&relay)),
        &PendingRequest {
            idp_id: idp.id,
            mode,
            request_id,
            browser: browser_hash,
        },
        REQUEST_TTL_SECS,
    )
    .await?;
    let signer = if s.sign_requests {
        Some(saml_keys::signer(state, &tenant.tenant).await?)
    } else {
        None
    };
    let internal = |e: SamlError| AppError::Internal(e.to_string());
    let res = match s.sso_binding {
        SloBinding::Redirect => {
            let url = binding::to_redirect(
                &s.sso_url,
                Kind::Request,
                &el.to_string(),
                Some(&relay),
                signer.as_deref(),
            )
            .map_err(internal)?;
            Redirect::to(&url).into_response()
        }
        SloBinding::Post => {
            if let Some(signer) = &signer {
                signer.sign_enveloped(&mut el, 1).map_err(internal)?;
            }
            binding::to_post(&s.sso_url, Kind::Request, &el.to_document(), Some(&relay))
        }
    };
    let mut res = html_headers(res);
    let cookie = broker::binding_cookie(state, &tenant.tenant, &browser, broker::BINDING_TTL_SECS);
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        res.headers_mut().append(header::SET_COOKIE, v);
    }
    Ok(res)
}

/// What the IdP said about the session, kept with the rIDM session for
/// Single Logout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamSession {
    pub idp_id: Uuid,
    pub name_id: String,
    pub name_id_format: Option<String>,
    pub name_qualifier: Option<String>,
    pub sp_name_qualifier: Option<String>,
    pub session_index: Option<String>,
}

/// What an accepted response continues.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Continues {
    Mode(Mode),
    /// An unsolicited response: sign in without a flow.
    Unsolicited,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Parked {
    idp_id: Uuid,
    continues: Continues,
    identity: Identity,
    upstream: UpstreamSession,
    /// The binding cookie's hash; none for an unsolicited response, which
    /// no browser started.
    browser: Option<String>,
}

/// What the assertion consumer service does with a response.
pub enum AcsStep {
    /// Accepted: the browser continues at this same-site URL.
    Continue(String),
    /// Refused: where to tell it (the flow's login page, or the account
    /// console for a link) and why.
    Failed {
        flow_id: Option<Uuid>,
        return_to: Option<String>,
        error: BrokerError,
    },
}

/// Well-known attribute names of the claims the broker reads by default
/// (the SAML attribute profiles, eduPerson, and Microsoft's claim URIs), so
/// most IdPs need no mappers.
const ALIASES: &[(&str, &[&str])] = &[
    (
        "email",
        &[
            "mail",
            "emailAddress",
            "urn:oid:0.9.2342.19200300.100.1.3",
            "urn:oid:1.2.840.113549.1.9.1",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        ],
    ),
    (
        "preferred_username",
        &[
            "uid",
            "username",
            "urn:oid:0.9.2342.19200300.100.1.1",
            "eduPersonPrincipalName",
            "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
        ],
    ),
    (
        "given_name",
        &[
            "givenName",
            "urn:oid:2.5.4.42",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
        ],
    ),
    (
        "family_name",
        &[
            "sn",
            "surname",
            "urn:oid:2.5.4.4",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
        ],
    ),
    (
        "name",
        &[
            "displayName",
            "cn",
            "urn:oid:2.16.840.1.113730.3.1.241",
            "urn:oid:2.5.4.3",
            "http://schemas.microsoft.com/identity/claims/displayname",
        ],
    ),
];

/// The assertion as claims for the broker's mappers: each attribute under
/// its `Name` (and its `FriendlyName`), one value as a string and several
/// as an array; the well-known names also under the claim the broker reads
/// by default; the NameID as `nameid` (and as the email for an
/// `emailAddress` NameID the IdP sent no address with).
fn claims_of(a: &Asserted) -> Map<String, Value> {
    let mut claims = Map::new();
    for attr in &a.attributes {
        let v = match attr.values.as_slice() {
            [one] => Value::String(one.clone()),
            many => Value::from(many.to_vec()),
        };
        if let Some(f) = &attr.friendly_name {
            claims.entry(f.clone()).or_insert_with(|| v.clone());
        }
        claims.insert(attr.name.clone(), v);
    }
    for (claim, names) in ALIASES {
        if claims.contains_key(*claim) {
            continue;
        }
        if let Some(v) = names.iter().find_map(|n| claims.get(*n)).cloned() {
            claims.insert((*claim).to_string(), v);
        }
    }
    if !claims.contains_key("email") && a.name_id.format.as_deref() == Some(ns::nameid::EMAIL) {
        claims.insert("email".into(), Value::String(a.name_id.value.clone()));
    }
    claims.insert("nameid".into(), Value::String(a.name_id.value.clone()));
    if let Some(f) = &a.name_id.format {
        claims.insert("nameid_format".into(), Value::String(f.clone()));
    }
    claims
}

/// The identity an assertion proves: the NameID is the subject unless a
/// subject mapper names an attribute. A transient NameID changes every
/// time, so it cannot identify anyone without one.
fn identity_of(idp: &IdentityProvider, a: &Asserted) -> Result<Identity, String> {
    let mapped = idp.mappers.0.subject.is_some();
    if !mapped && a.name_id.format.as_deref() == Some(ns::nameid::TRANSIENT) {
        return Err(
            "the IdP sent a transient NameID and no subject mapper names a stable attribute".into(),
        );
    }
    let verified = (!mapped).then(|| a.name_id.value.clone());
    broker::identity_from_claims(idp, claims_of(a), verified)
        .ok_or_else(|| "the assertion carries no usable subject".into())
}

fn outcome_metric(outcome: &'static str) {
    metrics::counter!("ridm_saml_sp_responses_total", "outcome" => outcome).increment(1);
}

/// Check a `Response` posted to the assertion consumer service.
pub async fn acs(
    state: &AppState,
    tenant: &TenantCtx,
    idp: &IdentityProvider,
    received: &Received,
) -> AppResult<AcsStep> {
    let s = settings(idp)?;
    let pending: Option<PendingRequest> = match &received.relay_state {
        Some(r) if r.len() <= 128 => take(state, key(tenant.id(), "request", &hashed(r))).await?,
        _ => None,
    };
    let (continues, request_id, browser) = match pending {
        Some(p) if p.idp_id == idp.id => {
            (Continues::Mode(p.mode), Some(p.request_id), Some(p.browser))
        }
        Some(_) => {
            return Ok(AcsStep::Failed {
                flow_id: None,
                return_to: None,
                error: BrokerError::InvalidState,
            });
        }
        None if s.allow_unsolicited => (Continues::Unsolicited, None, None),
        None => {
            outcome_metric("no_request");
            return Ok(AcsStep::Failed {
                flow_id: None,
                return_to: None,
                error: BrokerError::InvalidState,
            });
        }
    };
    let (flow_id, return_to) = match &continues {
        Continues::Mode(Mode::Flow { flow_id }) => (Some(*flow_id), None),
        Continues::Mode(Mode::Link { return_to, .. }) => (None, return_to.clone()),
        Continues::Unsolicited => (None, None),
    };
    let failed = |error: BrokerError| AcsStep::Failed {
        flow_id,
        return_to: return_to.clone(),
        error,
    };
    if !idp.enabled || received.kind != Kind::Response {
        return Ok(failed(BrokerError::InvalidState));
    }

    let ep = endpoints(state, &tenant.tenant, &idp.alias);
    let certs = certificates(s);
    let keys = saml_keys::decryption_keys(state, &tenant.tenant).await?;
    let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
    let checked = sp::validate_response(
        &received.xml,
        &Expected {
            idp_entity_id: &s.entity_id,
            sp_entity_id: &ep.entity_id,
            acs_url: &ep.acs_url,
            in_response_to: request_id.as_deref(),
            certificates: &certs,
            decryption_keys: &key_refs,
            want_assertions_signed: s.want_assertions_signed,
            require_encrypted: s.require_encrypted_assertions,
            now: Utc::now(),
        },
    );
    let asserted = match checked {
        Ok(a) => a,
        Err(ResponseError::Status {
            code,
            second,
            message,
        }) => {
            tracing::info!(provider = %idp.alias, %code, second = second.as_deref().unwrap_or(""), message = message.as_deref().unwrap_or(""), "upstream SAML sign-in refused");
            outcome_metric("status");
            let denied = matches!(
                second.as_deref(),
                Some(ns::status::REQUEST_DENIED | ns::status::AUTHN_FAILED)
            );
            return Ok(failed(if denied {
                BrokerError::Denied
            } else {
                BrokerError::Upstream
            }));
        }
        Err(ResponseError::Invalid(e)) => {
            tracing::warn!(provider = %idp.alias, error = %e, "upstream SAML response refused");
            outcome_metric("invalid");
            return Ok(failed(BrokerError::Upstream));
        }
    };
    // Once per assertion, for as long as it could be presented.
    let ttl = (asserted.valid_until - Utc::now() + sp::CLOCK_SKEW)
        .num_seconds()
        .max(60) as u64;
    let seen = key(
        tenant.id(),
        &format!("assertion:{}", idp.id),
        &hashed(&asserted.assertion_id),
    );
    if !first_sighting(state, seen, ttl).await? {
        tracing::warn!(provider = %idp.alias, "a SAML assertion was presented twice");
        outcome_metric("replay");
        return Ok(failed(BrokerError::Upstream));
    }
    let identity = match identity_of(idp, &asserted) {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(provider = %idp.alias, error = %e, "upstream SAML identity could not be established");
            outcome_metric("no_subject");
            return Ok(failed(BrokerError::Upstream));
        }
    };
    outcome_metric("accepted");
    let parked_id = Uuid::new_v4();
    put(
        state,
        key(tenant.id(), "parked", &parked_id.to_string()),
        &Parked {
            idp_id: idp.id,
            continues,
            identity,
            upstream: UpstreamSession {
                idp_id: idp.id,
                name_id: asserted.name_id.value.clone(),
                name_id_format: asserted.name_id.format.clone(),
                name_qualifier: None,
                sp_name_qualifier: asserted.name_id.sp_name_qualifier.clone(),
                session_index: asserted.session_index.clone(),
            },
            browser,
        },
        PARKED_TTL_SECS,
    )
    .await?;
    Ok(AcsStep::Continue(format!(
        "{}?continue={parked_id}",
        ep.acs_url
    )))
}

/// What the same-site GET after the assertion consumer service leads to.
pub enum Resumed {
    /// A flow or a link: as for any upstream kind.
    Broker(Outcome),
    /// An unsolicited sign-in: set the session cookie and go to `to`.
    Landed {
        session: Box<SsoSession>,
        to: String,
    },
}

/// Continue a response [`acs`] accepted.
pub async fn resume(
    state: &AppState,
    tenant: &TenantCtx,
    idp: &IdentityProvider,
    parked_id: Uuid,
    browser: Option<&str>,
    ctx: RequestContext,
) -> AppResult<Resumed> {
    let parked: Option<Parked> =
        take(state, key(tenant.id(), "parked", &parked_id.to_string())).await?;
    let Some(parked) = parked.filter(|p| p.idp_id == idp.id) else {
        return Ok(Resumed::Broker(Outcome::Failed {
            flow_id: None,
            return_to: None,
            error: BrokerError::InvalidState,
        }));
    };
    let Parked {
        continues,
        identity,
        upstream,
        browser: bound_to,
        ..
    } = parked;
    if let Some(expected) = bound_to
        && !broker::binding_matches(browser, &expected)
    {
        tracing::warn!(provider = %idp.alias, "a SAML sign-in was continued by another browser than the one that started it");
        let flow_id = match &continues {
            Continues::Mode(Mode::Flow { flow_id }) => Some(*flow_id),
            _ => None,
        };
        let return_to = match &continues {
            Continues::Mode(Mode::Link { return_to, .. }) => return_to.clone(),
            _ => None,
        };
        return Ok(Resumed::Broker(Outcome::Failed {
            flow_id,
            return_to,
            error: BrokerError::InvalidState,
        }));
    }
    match continues {
        Continues::Mode(mode) => {
            let outcome = broker::conclude(state, tenant, idp, mode, identity, ctx).await?;
            if let Outcome::Authenticated { session, .. } = &outcome {
                record_upstream(state, session, &upstream).await?;
            }
            Ok(Resumed::Broker(outcome))
        }
        Continues::Unsolicited => unsolicited(state, tenant, idp, identity, upstream, ctx).await,
    }
}

/// An IdP-initiated sign-in. It runs through a login flow of the account
/// console's client, so risk scoring, the link policy and the audit trail
/// are the same as a solicited one; the flow is then dropped, and whatever
/// the session still owes (a second factor, terms) is asked when a client
/// resumes it at `/authorize`.
async fn unsolicited(
    state: &AppState,
    tenant: &TenantCtx,
    idp: &IdentityProvider,
    identity: Identity,
    upstream: UpstreamSession,
    ctx: RequestContext,
) -> AppResult<Resumed> {
    let s = settings(idp)?;
    let console =
        match clients::find_by_client_id(state, tenant.id(), account_console::ACCOUNT_CLIENT_ID)
            .await?
        {
            Some(c) => (*c).clone(),
            None => account_console::ensure(state, &tenant.tenant).await?,
        };
    let now = Utc::now();
    let flow = login_flows::create(
        state,
        LoginFlow {
            id: Uuid::new_v4(),
            tenant_id: tenant.id(),
            request: AuthRequest {
                client_id: console.id,
                client_public_id: console.client_id.clone(),
                redirect_uri: account_console::callback_uri(&state.config),
                response_mode: ResponseMode::Query,
                scopes: vec!["openid".into()],
                audiences: vec![],
                state: None,
                nonce: None,
                code_challenge: None,
                prompt: vec![],
                max_age: None,
                acr_values: vec![],
                login_hint: None,
                ui_locales: vec![],
                claims: None,
                skip_consent: true,
                device_code: None,
                organization: None,
                saml: None,
            },
            stage: FlowStage::Authenticate,
            session_id: None,
            user_id: None,
            pending_scopes: vec![],
            require_auth_after: None,
            csrf: String::new(),
            attempts: 0,
            amr: vec![],
            org_id: None,
            trusted_device: false,
            risk_step_up: false,
            remember_device: false,
            created_at: now,
            expires_at: now,
        },
    )
    .await?;
    let flow_id = flow.id;
    let outcome =
        broker::conclude(state, tenant, idp, Mode::Flow { flow_id }, identity, ctx).await?;
    login_flows::delete(state, tenant.id(), flow_id).await?;
    let session = match outcome {
        Outcome::Authenticated { session, .. } => session,
        Outcome::Failed { error, .. } => {
            return Ok(Resumed::Broker(Outcome::Failed {
                flow_id: None,
                return_to: None,
                error,
            }));
        }
        other => return Ok(Resumed::Broker(other)),
    };
    record_upstream(state, &session, &upstream).await?;
    let to = match &s.unsolicited_client_id {
        Some(client_id) => {
            match clients::find_by_client_id(state, tenant.id(), client_id)
                .await?
                .filter(|c| c.is_active())
                .and_then(|c| c.initiate_login_uri.clone())
                .and_then(|u| url::Url::parse(&u).ok())
            {
                Some(mut u) => {
                    u.query_pairs_mut()
                        .append_pair("iss", &tokens::issuer(state, &tenant.tenant));
                    u.to_string()
                }
                None => account_home(state, &tenant.tenant),
            }
        }
        None => account_home(state, &tenant.tenant),
    };
    Ok(Resumed::Landed { session, to })
}

fn account_home(state: &AppState, tenant: &Tenant) -> String {
    state.ui_page(tenant, "account", &[("tenant", tenant.slug.as_str())])
}

// ---------------------------------------------------------------------------
// The upstream session of a brokered session
// ---------------------------------------------------------------------------

fn upstream_key(tenant_id: Uuid, session_id: Uuid) -> String {
    format!(
        "{}:t:{tenant_id}:session:{session_id}:saml_upstream",
        cache_keys::PREFIX
    )
}

fn by_name_id_key(tenant_id: Uuid, idp_id: Uuid, name_id: &str) -> String {
    key(tenant_id, &format!("sessions:{idp_id}"), &hashed(name_id))
}

async fn record_upstream(
    state: &AppState,
    session: &SsoSession,
    up: &UpstreamSession,
) -> AppResult<()> {
    let ttl = (session.expires_at - Utc::now()).num_seconds().max(60);
    let index = by_name_id_key(session.tenant_id, up.idp_id, &up.name_id);
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(
            upstream_key(session.tenant_id, session.id),
            serde_json::to_string(up)?,
            ttl as u64,
        )
        .await?;
    let _: () = conn.sadd(&index, session.id.to_string()).await?;
    // The set lives as long as its longest session; ended ones in it are
    // skipped when read.
    let current: i64 = conn.ttl(&index).await?;
    if current < ttl {
        let _: () = conn.expire(&index, ttl).await?;
    }
    Ok(())
}

/// The upstream SAML session behind a rIDM session, if it was brokered.
pub async fn upstream_of(
    state: &AppState,
    tenant_id: Uuid,
    session_id: Uuid,
) -> AppResult<Option<UpstreamSession>> {
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = conn.get(upstream_key(tenant_id, session_id)).await?;
    Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
}

// ---------------------------------------------------------------------------
// Single Logout
// ---------------------------------------------------------------------------

/// Sign `el` and send it to the IdP's logout service by its binding.
/// Logout messages are always signed: an IdP must be able to tell them
/// from a forged one, which would end the user's session there.
async fn deliver(
    state: &AppState,
    tenant: &Tenant,
    s: &SamlUpstream,
    kind: Kind,
    mut el: El,
    relay: Option<&str>,
) -> AppResult<Response> {
    let url = s
        .slo_url
        .as_deref()
        .ok_or_else(|| AppError::Internal("the identity provider has no logout service".into()))?;
    let signer = saml_keys::signer(state, tenant).await?;
    let internal = |e: SamlError| AppError::Internal(e.to_string());
    let res = match s.slo_binding {
        SloBinding::Redirect => {
            let to = binding::to_redirect(url, kind, &el.to_string(), relay, Some(&signer))
                .map_err(internal)?;
            Redirect::to(&to).into_response()
        }
        SloBinding::Post => {
            signer.sign_enveloped(&mut el, 1).map_err(internal)?;
            binding::to_post(url, kind, &el.to_document(), relay)
        }
    };
    Ok(html_headers(res))
}

/// A sign-out that started at rIDM, on its way to the IdP.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OutboundLogout {
    upstream: UpstreamSession,
    target: String,
}

/// A `LogoutRequest` rIDM sent, waiting for the IdP's answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AwaitedLogout {
    idp_id: Uuid,
    request_id: String,
    target: String,
}

/// Where a sign-out that started at rIDM goes when the session was
/// brokered by a SAML IdP with a logout service: through the IdP, then on
/// to `target`. `target` itself otherwise.
pub async fn logout_upstream(
    state: &AppState,
    tenant: &Tenant,
    upstream: Option<UpstreamSession>,
    target: String,
) -> AppResult<String> {
    let Some(up) = upstream else {
        return Ok(target);
    };
    let idp = match identity_providers::get(state, tenant.id, &up.idp_id.to_string()).await {
        Ok(i) => i,
        Err(AppError::NotFound(_)) => return Ok(target),
        Err(e) => return Err(e),
    };
    let reachable = idp.enabled && idp.saml.as_ref().is_some_and(|s| s.slo_url.is_some());
    if !reachable {
        return Ok(target);
    }
    let id = Uuid::new_v4();
    put(
        state,
        key(tenant.id, "out", &id.to_string()),
        &OutboundLogout {
            upstream: up,
            target,
        },
        LOGOUT_TTL_SECS,
    )
    .await?;
    Ok(format!(
        "{}/out/{id}",
        endpoints(state, tenant, &idp.alias).slo_url
    ))
}

/// `GET …/saml/slo/out/{id}`: send the IdP the `LogoutRequest` of a
/// sign-out [`logout_upstream`] started.
pub async fn send_logout(
    state: &AppState,
    tenant: &TenantCtx,
    idp: &IdentityProvider,
    id: Uuid,
) -> Response {
    let out: Option<OutboundLogout> =
        match take(state, key(tenant.id(), "out", &id.to_string())).await {
            Ok(o) => o,
            Err(e) => return e.into_response(),
        };
    let Some(out) = out.filter(|o| o.upstream.idp_id == idp.id) else {
        return saml_page(
            StatusCode::NOT_FOUND,
            &SamlError::malformed("this sign-out has finished or expired"),
        );
    };
    let Ok(s) = settings(idp) else {
        return Redirect::to(&out.target).into_response();
    };
    let Some(slo_url) = s.slo_url.as_deref() else {
        return Redirect::to(&out.target).into_response();
    };
    let ep = endpoints(state, &tenant.tenant, &idp.alias);
    let up = &out.upstream;
    let el = protocol::logout_request(
        &ep.entity_id,
        slo_url,
        &NameId {
            value: up.name_id.clone(),
            format: up.name_id_format.clone(),
            sp_name_qualifier: up.sp_name_qualifier.clone(),
        },
        up.session_index.as_deref(),
        Utc::now(),
    );
    let request_id = el.attribute("ID").unwrap_or_default().to_string();
    let relay = random_token();
    if let Err(e) = put(
        state,
        key(tenant.id(), "awaited", &hashed(&relay)),
        &AwaitedLogout {
            idp_id: idp.id,
            request_id,
            target: out.target.clone(),
        },
        LOGOUT_TTL_SECS,
    )
    .await
    {
        return e.into_response();
    }
    match deliver(state, &tenant.tenant, s, Kind::Request, el, Some(&relay)).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(provider = %idp.alias, error = %e, "upstream SAML logout could not be sent");
            Redirect::to(&out.target).into_response()
        }
    }
}

/// A message at `…/saml/slo`: the IdP asking to end sessions, or answering
/// a `LogoutRequest` rIDM sent.
pub async fn slo(
    state: &AppState,
    tenant: &TenantCtx,
    idp: &IdentityProvider,
    received: Received,
) -> Response {
    let Ok(s) = settings(idp) else {
        return AppError::NotFound("SAML identity provider").into_response();
    };
    let doc = match xml::parse(&received.xml) {
        Ok(d) => d,
        Err(e) => return saml_page(StatusCode::BAD_REQUEST, &e),
    };
    match received.kind {
        Kind::Request => logout_request(state, tenant, idp, s, &received, &doc).await,
        Kind::Response => logout_response(state, tenant, idp, s, &received, &doc).await,
    }
}

/// Whether a logout message is signed by the IdP (by the Redirect binding's
/// query signature or an enveloped one); `Err` when a signature is there
/// and does not verify.
fn signed_by_idp(
    s: &SamlUpstream,
    received: &Received,
    doc: &roxmltree::Document,
) -> Result<bool, SamlError> {
    let certs = certificates(s);
    let enveloped = dsig::signature_of(doc.root_element())?.is_some();
    match (&received.signature, enveloped) {
        (Some(_), true) => Err(SamlError::signature(
            "signed both in the query string and in the XML",
        )),
        (Some(sig), false) => sig.verify(&certs).map(|_| true),
        (None, true) => dsig::verify_enveloped(doc, doc.root_element(), &certs).map(|_| true),
        (None, false) => Ok(false),
    }
}

/// A `LogoutResponse` rIDM owes the IdP once the browser has been through
/// the downstream SPs.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OwedResponse {
    idp_id: Uuid,
    in_response_to: String,
    relay_state: Option<String>,
}

async fn logout_request(
    state: &AppState,
    tenant: &TenantCtx,
    idp: &IdentityProvider,
    s: &SamlUpstream,
    received: &Received,
    doc: &roxmltree::Document<'_>,
) -> Response {
    let page = |e: SamlError| saml_page(StatusCode::BAD_REQUEST, &e);
    let req = match protocol::parse_logout_request(doc) {
        Ok(r) => r,
        Err(e) => return page(e),
    };
    if req.issuer != s.entity_id {
        return page(SamlError::malformed(
            "the Issuer is not the registered identity provider",
        ));
    }
    // A forged request would sign the user out everywhere: it must be
    // signed, whatever the IdP does for its sign-in responses.
    match signed_by_idp(s, received, doc) {
        Ok(true) => {}
        Ok(false) => {
            return page(SamlError::signature(
                "a LogoutRequest from an identity provider must be signed",
            ));
        }
        Err(e) => return page(e),
    }
    let ep = endpoints(state, &tenant.tenant, &idp.alias);
    if req.destination.as_deref().is_some_and(|d| d != ep.slo_url)
        || (received.signature.is_none() && req.destination.is_none())
    {
        return page(SamlError::malformed(
            "Destination is not this service provider's logout URL",
        ));
    }
    let now = Utc::now();
    if req.issue_instant < now - MAX_REQUEST_AGE - sp::CLOCK_SKEW
        || req.issue_instant > now + sp::CLOCK_SKEW
    {
        return page(SamlError::malformed(
            "IssueInstant is outside the accepted window (check the IdP's clock)",
        ));
    }
    if req
        .not_on_or_after
        .is_some_and(|t| t <= now - sp::CLOCK_SKEW)
    {
        return page(SamlError::malformed("the request has expired"));
    }
    let seen = key(tenant.id(), &format!("logout:{}", idp.id), &hashed(&req.id));
    match first_sighting(state, seen, REPLAY_TTL_SECS).await {
        Ok(true) => {}
        Ok(false) => return page(SamlError::malformed("this request was already used")),
        Err(e) => return e.into_response(),
    }

    // The sessions this NameID has through this IdP, narrowed to the
    // `SessionIndex`es named (none named: all of them).
    let sids: Vec<String> = match state.redis.get().await {
        Ok(mut conn) => match conn
            .smembers(by_name_id_key(tenant.id(), idp.id, &req.name_id.value))
            .await
        {
            Ok(v) => v,
            Err(e) => return AppError::from(e).into_response(),
        },
        Err(e) => return e.into_response(),
    };
    let mut downstream = vec![];
    let mut ended_any = false;
    for sid in sids.iter().filter_map(|s| Uuid::parse_str(s).ok()) {
        let up = match upstream_of(state, tenant.id(), sid).await {
            Ok(Some(u)) => u,
            Ok(None) => continue,
            Err(e) => return e.into_response(),
        };
        let matches = up.idp_id == idp.id
            && up.name_id == req.name_id.value
            && (req.session_indexes.is_empty()
                || up
                    .session_index
                    .as_ref()
                    .is_some_and(|i| req.session_indexes.contains(i)));
        if !matches {
            continue;
        }
        match crate::services::logout::end_session(state, &tenant.tenant, sid).await {
            Ok(outcome) => {
                ended_any |= outcome.ended;
                downstream.extend(outcome.saml_participants);
            }
            Err(e) => return e.into_response(),
        }
    }
    if ended_any {
        state.events.publish(Event::new(
            Some(tenant.id()),
            Actor::System,
            EventKind::UpstreamLogout {
                idp_id: idp.id,
                provider: idp.alias.clone(),
            },
        ));
    }
    let owed_id = Uuid::new_v4();
    if let Err(e) = put(
        state,
        key(tenant.id(), "owed", &owed_id.to_string()),
        &OwedResponse {
            idp_id: idp.id,
            in_response_to: req.id,
            relay_state: received.relay_state.clone(),
        },
        LOGOUT_TTL_SECS,
    )
    .await
    {
        return e.into_response();
    }
    let done = format!("{}/done/{owed_id}", ep.slo_url);
    let next =
        match crate::services::saml_idp::logout_through(state, &tenant.tenant, downstream, done)
            .await
        {
            Ok(n) => n,
            Err(e) => return e.into_response(),
        };
    let mut res = html_headers(Redirect::to(&next).into_response());
    if let Ok(v) = HeaderValue::from_str(&crate::services::sessions::clear_cookie_header(
        state,
        &tenant.tenant,
    )) {
        res.headers_mut().append(header::SET_COOKIE, v);
    }
    res
}

/// `GET …/saml/slo/done/{id}`: answer the IdP's `LogoutRequest` once the
/// downstream SPs had their turn.
pub async fn answer_logout(
    state: &AppState,
    tenant: &TenantCtx,
    idp: &IdentityProvider,
    id: Uuid,
) -> Response {
    let owed: Option<OwedResponse> =
        match take(state, key(tenant.id(), "owed", &id.to_string())).await {
            Ok(o) => o,
            Err(e) => return e.into_response(),
        };
    let Some(owed) = owed.filter(|o| o.idp_id == idp.id) else {
        return saml_page(
            StatusCode::NOT_FOUND,
            &SamlError::malformed("this sign-out has finished or expired"),
        );
    };
    let Ok(s) = settings(idp) else {
        return AppError::NotFound("SAML identity provider").into_response();
    };
    let Some(slo_url) = s.slo_url.as_deref() else {
        return Redirect::to(&account_home(state, &tenant.tenant)).into_response();
    };
    let ep = endpoints(state, &tenant.tenant, &idp.alias);
    let el = protocol::logout_response(
        &ep.entity_id,
        slo_url,
        &owed.in_response_to,
        (ns::status::SUCCESS, None),
        Utc::now(),
    );
    match deliver(
        state,
        &tenant.tenant,
        s,
        Kind::Response,
        el,
        owed.relay_state.as_deref(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

async fn logout_response(
    state: &AppState,
    tenant: &TenantCtx,
    idp: &IdentityProvider,
    s: &SamlUpstream,
    received: &Received,
    doc: &roxmltree::Document<'_>,
) -> Response {
    let page = |e: SamlError| saml_page(StatusCode::BAD_REQUEST, &e);
    let res = match protocol::parse_logout_response(doc) {
        Ok(r) => r,
        Err(e) => return page(e),
    };
    let awaited: Option<AwaitedLogout> = match &received.relay_state {
        Some(r) if r.len() <= 128 => {
            match take(state, key(tenant.id(), "awaited", &hashed(r))).await {
                Ok(a) => a,
                Err(e) => return e.into_response(),
            }
        }
        _ => None,
    };
    let Some(awaited) = awaited.filter(|a| a.idp_id == idp.id) else {
        return page(SamlError::malformed(
            "no sign-out is waiting for this answer",
        ));
    };
    // The rIDM session already ended; a bad answer only means the IdP's
    // may not have, which the user cannot fix here. It is logged, and the
    // browser goes on.
    let problem = if res.issuer != s.entity_id {
        Some("the answer is not from the identity provider that was asked".to_string())
    } else if res.in_response_to.as_deref() != Some(awaited.request_id.as_str()) {
        Some("InResponseTo does not match the request".into())
    } else if let Err(e) = signed_by_idp(s, received, doc) {
        Some(e.to_string())
    } else if res.status != ns::status::SUCCESS {
        Some(format!("the identity provider answered {}", res.status))
    } else {
        None
    };
    if let Some(p) = problem {
        tracing::warn!(provider = %idp.alias, problem = %p, "upstream SAML logout not confirmed");
    }
    html_headers(Redirect::to(&awaited.target).into_response())
}

// ---------------------------------------------------------------------------
// Metadata refresh
// ---------------------------------------------------------------------------

/// Re-read a provider's metadata URL: its endpoints and certificates
/// replace the stored ones. The entity ID must not change (that would be
/// another IdP). Returns whether anything changed; a failure is recorded
/// on the provider (and the old settings stay) before it is returned.
pub async fn refresh_metadata(
    state: &AppState,
    tenant_id: Uuid,
    idp: &IdentityProvider,
) -> AppResult<bool> {
    let s = settings(idp)?;
    let Some(url) = s.metadata_url.clone() else {
        return Err(AppError::BadRequest(
            "the provider has no metadata URL".into(),
        ));
    };
    let read = async {
        let text = identity_providers::get_text("SAML metadata", &url).await?;
        let m =
            metadata::parse_idp_metadata(&text).map_err(|e| AppError::BadRequest(e.to_string()))?;
        if m.entity_id != s.entity_id {
            return Err(AppError::BadRequest(format!(
                "the metadata names another entity ID (`{}`)",
                m.entity_id
            )));
        }
        Ok(m)
    }
    .await;
    let count = |outcome: &'static str| {
        metrics::counter!("ridm_saml_metadata_refresh_total", "outcome" => outcome).increment(1);
    };
    let m = match read {
        Ok(m) => m,
        Err(e) => {
            let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
            repos::identity_providers::record_refresh(
                &mut *tx,
                tenant_id,
                idp.id,
                &url,
                Err(&e.to_string()),
            )
            .await?;
            tx.commit().await?;
            count("failed");
            return Err(e);
        }
    };
    let sso_binding = if m.sso.1 {
        SloBinding::Redirect
    } else {
        SloBinding::Post
    };
    let (slo_url, slo_binding) = match &m.slo {
        Some((u, redirect)) => (
            Some(identity_providers::validate_endpoint("slo_url", u)?),
            if *redirect {
                SloBinding::Redirect
            } else {
                SloBinding::Post
            },
        ),
        None => (None, s.slo_binding),
    };
    let sso_url = identity_providers::validate_endpoint("sso_url", &m.sso.0)?;
    let changed = sso_url != s.sso_url
        || sso_binding != s.sso_binding
        || slo_url != s.slo_url
        || slo_binding != s.slo_binding
        || m.signing_certificates != s.signing_certificates;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    repos::identity_providers::record_refresh(
        &mut *tx,
        tenant_id,
        idp.id,
        &url,
        Ok(repos::identity_providers::RefreshedMetadata {
            sso_url: &sso_url,
            sso_binding,
            slo_url: slo_url.as_deref(),
            slo_binding,
            signing_certificates: &m.signing_certificates,
        }),
    )
    .await?;
    tx.commit().await?;
    count(if changed { "changed" } else { "unchanged" });
    if changed {
        state.events.publish(Event::new(
            Some(tenant_id),
            Actor::System,
            EventKind::IdentityProviderUpdated { idp_id: idp.id },
        ));
    }
    Ok(changed)
}

/// One pass of the refresh job over every provider whose metadata was not
/// read in the last day (failed ones are retried each pass). Returns how
/// many were refreshed.
pub async fn refresh_due(state: &AppState) -> AppResult<usize> {
    let before = Utc::now() - chrono::Duration::hours(23);
    let mut done = 0;
    let relocating = state.db.relocating().await?;
    for database in state.db.all() {
        let mut cursor = (Uuid::nil(), Uuid::nil());
        loop {
            let mut tx = db::bypass_tx(&database.primary).await?;
            let page =
                repos::identity_providers::due_metadata_refresh(&mut *tx, before, cursor, 100)
                    .await?;
            tx.commit().await?;
            let Some(last) = page.last().copied() else {
                break;
            };
            cursor = last;
            for (tenant_id, idp_id) in page {
                if relocating.contains(&tenant_id) {
                    continue;
                }
                let idp = match identity_providers::get(state, tenant_id, &idp_id.to_string()).await
                {
                    Ok(i) => i,
                    Err(AppError::NotFound(_)) => continue,
                    Err(e) => return Err(e),
                };
                match refresh_metadata(state, tenant_id, &idp).await {
                    Ok(_) => done += 1,
                    Err(e) => {
                        tracing::warn!(%tenant_id, provider = %idp.alias, error = %e, "SAML metadata refresh failed")
                    }
                }
            }
        }
    }
    Ok(done)
}
