//! rIDM as a SAML 2.0 identity provider: the Web Browser SSO profile
//! (SP-initiated over HTTP-Redirect or HTTP-POST, IdP-initiated when an SP
//! opts in) and front-channel Single Logout.
//!
//! A SAML request becomes an ordinary authorization request against the
//! SP's `saml` client and goes through the same step machine as OIDC
//! (`oidc::authorize::decide`): sessions, second factors, risk, consent and
//! organizations work the same. Only the ends differ: the request is read
//! from SAML, and the answer is a signed `Response` posted to the SP's
//! assertion consumer service.

use std::sync::Arc;

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use redis::AsyncCommands as _;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Digest as _;
use uuid::Uuid;

use crate::cache::keys as cache_keys;
use crate::error::{AppError, AppResult, OAuthErrorCode};
use crate::middleware::TenantCtx;
use crate::models::{
    AttributeNameFormat, Client, Exposure, NameIdFormat, SamlServiceProvider, SloBinding, Tenant,
    TokenKind, User,
};
use crate::oidc::authorize::{self, Failure, Validated, error_page};
use crate::saml::binding::{self, Kind, Received};
use crate::saml::cert::Certificate;
use crate::saml::error::SamlError;
use crate::saml::protocol::{self, AuthnRequest, NameId};
use crate::saml::{dsig, ns, xml, xmlenc};
use crate::services::claims::{ClaimContext, apply_mappers, profile_claims, scope_claims};
use crate::services::login_flows::{AuthRequest, ResponseMode};
use crate::services::sessions::{self, SsoSession};
use crate::services::{
    flows, geoip, groups, ip_rules, profile_schema, roles, saml_keys, saml_sps, scopes, tokens,
    users,
};
use crate::state::AppState;

/// How old a request may be, and how far ahead of our clock.
const MAX_REQUEST_AGE: chrono::Duration = chrono::Duration::minutes(10);
const CLOCK_SKEW: chrono::Duration = chrono::Duration::minutes(3);
/// How long a request ID is remembered against replay (past its age limit).
const REPLAY_TTL_SECS: u64 = 15 * 60;
/// A POST-binding request waiting for the browser's same-site GET.
const PENDING_TTL_SECS: u64 = 10 * 60;
const TICKET_TTL_SECS: u64 = 10 * 60;
const CHAIN_TTL_SECS: u64 = 10 * 60;

/// The IdP's own URLs for a tenant, as metadata publishes them.
pub struct Endpoints {
    pub entity_id: String,
    pub sso_url: String,
    pub slo_url: String,
    pub metadata_url: String,
}

pub fn endpoints(state: &AppState, tenant: &Tenant) -> Endpoints {
    let issuer = tokens::issuer(state, tenant);
    Endpoints {
        sso_url: format!("{issuer}/saml/sso"),
        slo_url: format!("{issuer}/saml/slo"),
        metadata_url: format!("{issuer}/saml/metadata"),
        entity_id: issuer,
    }
}

/// The IdP metadata document.
pub async fn metadata(state: &AppState, tenant: &Tenant) -> AppResult<String> {
    let ep = endpoints(state, tenant);
    let certs = saml_keys::certificates(state, tenant).await?;
    Ok(crate::saml::metadata::idp_metadata(
        &crate::saml::metadata::IdpMetadata {
            entity_id: &ep.entity_id,
            sso_url: &ep.sso_url,
            slo_url: &ep.slo_url,
            certificates: &certs,
            name_id_formats: &[
                ns::nameid::PERSISTENT,
                ns::nameid::TRANSIENT,
                ns::nameid::EMAIL,
                ns::nameid::UNSPECIFIED,
            ],
        },
    ))
}

/// The SAML side of an authorization request, carried through the flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamlRequestContext {
    pub entity_id: String,
    /// The `AuthnRequest` ID (`InResponseTo`); none when IdP-initiated.
    pub request_id: Option<String>,
    pub relay_state: Option<String>,
    pub name_id_format: NameIdFormat,
    /// `AuthnContextClassRef`s the SP asked for.
    #[serde(default)]
    pub requested_classes: Vec<String>,
}

/// Where an answer goes before a flow exists or after it ends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipient {
    client_id: Uuid,
    acs_url: String,
    in_response_to: Option<String>,
    relay_state: Option<String>,
}

fn saml_page(status: StatusCode, err: &SamlError) -> Response {
    tracing::info!(error = %err, "SAML message refused");
    error_page(status, "invalid_saml_request", &err.to_string())
}

fn html_headers(res: &mut Response) {
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

/// Whether a request is too old or from the future.
fn check_instant(issued: DateTime<Utc>, now: DateTime<Utc>) -> Result<(), SamlError> {
    if issued < now - MAX_REQUEST_AGE - CLOCK_SKEW || issued > now + CLOCK_SKEW {
        return Err(SamlError::malformed(
            "IssueInstant is outside the accepted window (check the SP's clock)",
        ));
    }
    Ok(())
}

/// The SP's signature policy: a signature that is present must verify
/// against a registered certificate; one that is required must be present.
/// An SP with no certificate registered cannot be checked, so a signature
/// from it is ignored rather than trusted.
fn check_signature(
    sp: &SamlServiceProvider,
    received: &Received,
    doc: &roxmltree::Document,
) -> Result<bool, SamlError> {
    let certs: Vec<Certificate> = sp
        .signing_certificates
        .iter()
        .filter_map(|c| Certificate::parse(c).ok())
        .collect();
    let enveloped = dsig::signature_of(doc.root_element())?.is_some();
    let signed = match (&received.signature, enveloped) {
        (Some(_), true) => {
            return Err(SamlError::signature(
                "signed both in the query string and in the XML",
            ));
        }
        (Some(sig), false) if !certs.is_empty() => {
            sig.verify(&certs)?;
            true
        }
        (None, true) if !certs.is_empty() => {
            dsig::verify_enveloped(doc, doc.root_element(), &certs)?;
            true
        }
        _ => false,
    };
    if sp.require_signed_requests && !signed {
        return Err(SamlError::signature(
            "this service provider's requests must be signed",
        ));
    }
    Ok(signed)
}

/// Remember a message ID; false when it was seen before (a replay).
async fn first_sighting(state: &AppState, tenant_id: Uuid, sp: Uuid, id: &str) -> AppResult<bool> {
    let key = format!(
        "{}:t:{tenant_id}:saml:seen:{sp}:{}",
        cache_keys::PREFIX,
        hex::encode(sha2::Sha256::digest(id.as_bytes()))
    );
    let mut conn = state.redis.get().await?;
    let fresh: bool = redis::cmd("SET")
        .arg(&key)
        .arg(1)
        .arg("NX")
        .arg("EX")
        .arg(REPLAY_TTL_SECS)
        .query_async::<Option<String>>(&mut conn)
        .await?
        .is_some();
    Ok(fresh)
}

/// A request that passed every check that needs no session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Admitted {
    client_public_id: String,
    recipient: Recipient,
    context: SamlRequestContext,
    force_authn: bool,
    is_passive: bool,
    mfa: bool,
}

/// Why a request was not admitted: shown to the user when the SP cannot be
/// trusted with an answer, sent to the SP as a status otherwise.
pub enum Refusal {
    Page(StatusCode, SamlError),
    Status(Box<StatusRefusal>),
    Internal(AppError),
}

/// A failure status for the SP: top-level and second-level codes and a
/// message.
pub struct StatusRefusal {
    recipient: Recipient,
    top: &'static str,
    second: Option<&'static str>,
    message: String,
}

fn status_refusal(
    recipient: Recipient,
    top: &'static str,
    second: Option<&'static str>,
    message: impl Into<String>,
) -> Refusal {
    Refusal::Status(Box::new(StatusRefusal {
        recipient,
        top,
        second,
        message: message.into(),
    }))
}

impl From<AppError> for Refusal {
    fn from(e: AppError) -> Self {
        Refusal::Internal(e)
    }
}

/// Classes rIDM can stand behind, and whether they mean a second factor.
fn class_support(class: &str) -> Option<bool> {
    match class {
        ns::AC_REFEDS_MFA | ns::AC_MS_MULTIPLE_AUTHN => Some(true),
        ns::AC_PASSWORD_PROTECTED
        | ns::AC_UNSPECIFIED
        | "urn:oasis:names:tc:SAML:2.0:ac:classes:Password" => Some(false),
        _ => None,
    }
}

/// Check an `AuthnRequest` against the SP's registration.
pub async fn admit(
    state: &AppState,
    tenant: &TenantCtx,
    received: &Received,
) -> Result<Admitted, Refusal> {
    let page = |e: SamlError| Refusal::Page(StatusCode::BAD_REQUEST, e);
    if received.kind != Kind::Request {
        return Err(page(SamlError::malformed("expected a SAMLRequest")));
    }
    let doc = xml::parse(&received.xml).map_err(page)?;
    let req: AuthnRequest = protocol::parse_authn_request(&doc).map_err(page)?;
    let entry = saml_sps::find_by_entity_id(state, tenant.id(), &req.issuer)
        .await?
        .ok_or_else(|| {
            page(SamlError::malformed(
                "the issuer is not a registered service provider",
            ))
        })?;
    let sp = &entry.sp;
    let client =
        crate::services::clients::find_by_client_id(state, tenant.id(), &entry.client_public_id)
            .await?
            .filter(|c| c.is_active())
            .ok_or_else(|| {
                Refusal::Page(
                    StatusCode::FORBIDDEN,
                    SamlError::malformed("this service provider is disabled"),
                )
            })?;
    let signed = check_signature(sp, received, &doc).map_err(page)?;
    let ep = endpoints(state, &tenant.tenant);
    match &req.destination {
        Some(d) if *d != ep.sso_url => {
            return Err(page(SamlError::malformed(
                "Destination is not this IdP's SSO endpoint",
            )));
        }
        None if signed => {
            return Err(page(SamlError::malformed(
                "a signed request must name its Destination",
            )));
        }
        _ => {}
    }
    check_instant(req.issue_instant, Utc::now()).map_err(page)?;

    // The consumer URL is only ever one the SP registered.
    let acs_url = match (&req.acs_url, req.acs_index) {
        (Some(url), _) => sp
            .acs_urls
            .iter()
            .find(|u| *u == url)
            .cloned()
            .ok_or_else(|| {
                page(SamlError::malformed(
                    "AssertionConsumerServiceURL is not registered for this service provider",
                ))
            })?,
        (None, Some(i)) => sp.acs_urls.get(i as usize).cloned().ok_or_else(|| {
            page(SamlError::malformed(
                "AssertionConsumerServiceIndex is out of range",
            ))
        })?,
        (None, None) => sp.acs_urls[0].clone(),
    };
    if !first_sighting(state, tenant.id(), sp.client_id, &req.id).await? {
        return Err(page(SamlError::malformed("this request was already used")));
    }
    let recipient = Recipient {
        client_id: client.id,
        acs_url,
        in_response_to: Some(req.id.clone()),
        relay_state: received.relay_state.clone(),
    };
    if req
        .protocol_binding
        .as_deref()
        .is_some_and(|b| b != ns::BINDING_POST)
    {
        return Err(status_refusal(
            recipient,
            ns::status::REQUESTER,
            Some(ns::status::UNSUPPORTED_BINDING),
            "responses are sent with the HTTP-POST binding only",
        ));
    }
    let name_id_format = match req.name_id_format.as_deref() {
        None | Some(ns::nameid::UNSPECIFIED) => sp.name_id_format,
        Some(f) if NameIdFormat::from_urn(f) == Some(sp.name_id_format) => sp.name_id_format,
        Some(_) => {
            return Err(status_refusal(
                recipient,
                ns::status::REQUESTER,
                Some(ns::status::INVALID_NAMEID_POLICY),
                "the requested NameID format is not the one configured for this service provider",
            ));
        }
    };
    let (mut mfa, mut requested_classes) = (false, vec![]);
    if let Some(rac) = &req.requested_authn_context {
        let known: Vec<(&String, bool)> = rac
            .class_refs
            .iter()
            .filter_map(|c| class_support(c).map(|m| (c, m)))
            .collect();
        match rac.comparison.as_str() {
            // `exact`/`minimum`: one of the listed classes (the first rIDM
            // knows), so an MFA class there is a step-up.
            "exact" | "minimum" => {
                let Some((_, first_mfa)) = known.first() else {
                    return Err(status_refusal(
                        recipient,
                        ns::status::RESPONDER,
                        Some(ns::status::NO_AUTHN_CONTEXT),
                        "none of the requested authentication contexts is supported",
                    ));
                };
                mfa = *first_mfa;
            }
            // `better`: stronger than any listed; only MFA beats a password.
            "better" => {
                if known.iter().any(|(_, m)| *m) {
                    return Err(status_refusal(
                        recipient,
                        ns::status::RESPONDER,
                        Some(ns::status::NO_AUTHN_CONTEXT),
                        "nothing stronger than a second factor is offered",
                    ));
                }
                mfa = true;
            }
            // `maximum`: no stronger than listed; any sign-in will do.
            _ => {}
        }
        requested_classes = rac.class_refs.clone();
    }
    Ok(Admitted {
        client_public_id: client.client_id.clone(),
        recipient,
        context: SamlRequestContext {
            entity_id: sp.entity_id.clone(),
            request_id: Some(req.id),
            relay_state: received.relay_state.clone(),
            name_id_format,
            requested_classes,
        },
        force_authn: req.force_authn,
        is_passive: req.is_passive,
        mfa,
    })
}

/// IdP-initiated sign-in to the SP named by entity ID or client id.
pub async fn admit_unsolicited(
    state: &AppState,
    tenant: &TenantCtx,
    sp_ref: &str,
    relay_state: Option<String>,
) -> Result<Admitted, Refusal> {
    let refuse = |s: StatusCode, m: &str| Refusal::Page(s, SamlError::malformed(m));
    let entry = match saml_sps::find_by_entity_id(state, tenant.id(), sp_ref).await? {
        Some(e) => Some(e),
        None => {
            match crate::services::clients::find_by_client_id(state, tenant.id(), sp_ref).await? {
                Some(c) if c.client_type == crate::models::ClientType::Saml => {
                    saml_sps::find_by_client(state, tenant.id(), c.id)
                        .await?
                        .map(|sp| {
                            Arc::new(saml_sps::SpEntry {
                                sp: (*sp).clone(),
                                client_public_id: c.client_id.clone(),
                            })
                        })
                }
                _ => None,
            }
        }
    };
    let entry = entry.ok_or_else(|| refuse(StatusCode::NOT_FOUND, "no such service provider"))?;
    let sp = &entry.sp;
    if !sp.allow_idp_initiated {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "this service provider does not accept IdP-initiated sign-in",
        ));
    }
    let client =
        crate::services::clients::find_by_client_id(state, tenant.id(), &entry.client_public_id)
            .await?
            .filter(|c| c.is_active())
            .ok_or_else(|| refuse(StatusCode::FORBIDDEN, "this service provider is disabled"))?;
    let relay_state = relay_state.or_else(|| sp.default_relay_state.clone());
    if relay_state
        .as_ref()
        .is_some_and(|r| r.len() > binding::MAX_RELAY_STATE)
    {
        return Err(refuse(StatusCode::BAD_REQUEST, "RelayState is too long"));
    }
    Ok(Admitted {
        client_public_id: client.client_id.clone(),
        recipient: Recipient {
            client_id: client.id,
            acs_url: sp.acs_urls[0].clone(),
            in_response_to: None,
            relay_state: relay_state.clone(),
        },
        context: SamlRequestContext {
            entity_id: sp.entity_id.clone(),
            request_id: None,
            relay_state,
            name_id_format: sp.name_id_format,
            requested_classes: vec![],
        },
        force_authn: false,
        is_passive: false,
        mfa: false,
    })
}

/// Park a POST-binding request until the browser comes back with a GET
/// (the session cookie is `SameSite=Lax`, so a cross-site POST carries
/// none) and return where to send it.
pub async fn park(state: &AppState, tenant: &TenantCtx, admitted: &Admitted) -> AppResult<String> {
    let id = Uuid::new_v4();
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(
            pending_key(tenant.id(), id),
            serde_json::to_string(admitted)?,
            PENDING_TTL_SECS,
        )
        .await?;
    Ok(format!(
        "{}?continue={id}",
        endpoints(state, &tenant.tenant).sso_url
    ))
}

fn pending_key(tenant_id: Uuid, id: Uuid) -> String {
    format!("{}:t:{tenant_id}:saml:pending:{id}", cache_keys::PREFIX)
}

/// Take a parked request (once).
pub async fn unpark(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<Option<Admitted>> {
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = redis::cmd("GETDEL")
        .arg(pending_key(tenant_id, id))
        .query_async(&mut conn)
        .await?;
    Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
}

/// Answer an admission failure.
pub async fn refuse(state: &AppState, tenant: &TenantCtx, refusal: Refusal) -> Response {
    match refusal {
        Refusal::Page(status, err) => saml_page(status, &err),
        Refusal::Status(r) => {
            status_response(state, tenant, &r.recipient, r.top, r.second, &r.message).await
        }
        Refusal::Internal(e) => {
            tracing::error!(error = ?e, "SAML request failed");
            e.into_response()
        }
    }
}

/// Run an admitted request through the sign-in step machine.
pub async fn start(
    state: &AppState,
    tenant: &TenantCtx,
    headers: &HeaderMap,
    origin: geoip::Origin,
    admitted: Admitted,
) -> Response {
    let client = match crate::services::clients::find_by_client_id(
        state,
        tenant.id(),
        &admitted.client_public_id,
    )
    .await
    {
        Ok(Some(c)) if c.is_active() => c,
        Ok(_) => {
            return saml_page(
                StatusCode::FORBIDDEN,
                &SamlError::malformed("this service provider is disabled"),
            );
        }
        Err(e) => return e.into_response(),
    };
    if let Err(e) = ip_rules::require_client(state, tenant.id(), client.id, origin.ip).await {
        return error_page(e.status(), "access_denied", &e.to_string());
    }
    let recipient = admitted.recipient.clone();
    let mut prompt = vec![];
    if admitted.force_authn {
        prompt.push("login".to_string());
    }
    if admitted.is_passive {
        prompt.push("none".to_string());
    }
    let request = AuthRequest {
        client_id: client.id,
        client_public_id: client.client_id.clone(),
        redirect_uri: recipient.acs_url.clone(),
        response_mode: ResponseMode::FormPost,
        scopes: client.allowed_scopes.clone(),
        audiences: vec![],
        state: None,
        nonce: None,
        code_challenge: None,
        prompt,
        max_age: None,
        acr_values: if admitted.mfa {
            vec![flows::ACR_MFA.to_string()]
        } else {
            vec![]
        },
        login_hint: None,
        ui_locales: vec![],
        claims: None,
        skip_consent: !client.require_consent,
        device_code: None,
        organization: None,
        saml: Some(admitted.context),
    };
    match authorize::decide(
        state,
        tenant,
        headers,
        Validated { client, request },
        origin,
    )
    .await
    {
        Ok(res) => res,
        Err(Failure::Page(code, desc)) => error_page(StatusCode::BAD_REQUEST, code, &desc),
        Err(Failure::Redirect(e)) => {
            let (top, second) = match e.error {
                OAuthErrorCode::LoginRequired
                | OAuthErrorCode::ConsentRequired
                | OAuthErrorCode::InteractionRequired => {
                    (ns::status::RESPONDER, Some(ns::status::NO_PASSIVE))
                }
                OAuthErrorCode::AccessDenied => {
                    (ns::status::RESPONDER, Some(ns::status::REQUEST_DENIED))
                }
                _ => (ns::status::RESPONDER, None),
            };
            let message = e
                .error_description
                .clone()
                .unwrap_or_else(|| e.error.as_str().to_string());
            status_response(state, tenant, &recipient, top, second, &message).await
        }
        Err(Failure::Internal(e)) => {
            tracing::error!(error = ?e, "SAML sign-in failed");
            status_response(
                state,
                tenant,
                &recipient,
                ns::status::RESPONDER,
                None,
                "server error",
            )
            .await
        }
    }
}

/// A signed `Response` carrying only a status, posted to the SP.
async fn status_response(
    state: &AppState,
    tenant: &TenantCtx,
    recipient: &Recipient,
    top: &str,
    second: Option<&str>,
    message: &str,
) -> Response {
    let ep = endpoints(state, &tenant.tenant);
    let mut el = protocol::response(
        &ep.entity_id,
        &recipient.acs_url,
        recipient.in_response_to.as_deref(),
        Utc::now(),
        (top, second, Some(message)),
        None,
    );
    match saml_keys::signer(state, &tenant.tenant).await {
        Ok(signer) => {
            if let Err(e) = signer.sign_enveloped(&mut el, 1) {
                return AppError::Internal(e.to_string()).into_response();
            }
        }
        Err(e) => return e.into_response(),
    }
    let mut res = binding::to_post(
        &recipient.acs_url,
        Kind::Response,
        &el.to_document(),
        recipient.relay_state.as_deref(),
    );
    html_headers(&mut res);
    res
}

fn ticket_key(tenant_id: Uuid, id: Uuid) -> String {
    format!("{}:t:{tenant_id}:saml:ticket:{id}", cache_keys::PREFIX)
}

#[derive(Serialize, Deserialize)]
struct Ticket {
    recipient: Recipient,
    top: String,
    second: Option<String>,
    message: String,
}

/// The URL the login UI sends the browser to when the user cancels a SAML
/// sign-in or refuses consent: it posts `RequestDenied` to the SP.
pub async fn denial_url(state: &AppState, tenant: &Tenant, req: &AuthRequest) -> AppResult<String> {
    refusal_url(
        state,
        tenant,
        req,
        ns::status::REQUEST_DENIED,
        "the user denied the request",
    )
    .await
}

/// A one-time URL that posts a `Responder` failure with `second` (a
/// second-level status) and `message` to the SP of `req`.
pub async fn refusal_url(
    state: &AppState,
    tenant: &Tenant,
    req: &AuthRequest,
    second: &str,
    message: &str,
) -> AppResult<String> {
    let ctx = req
        .saml
        .as_ref()
        .ok_or_else(|| AppError::Internal("not a SAML request".into()))?;
    let id = Uuid::new_v4();
    let ticket = Ticket {
        recipient: Recipient {
            client_id: req.client_id,
            acs_url: req.redirect_uri.clone(),
            in_response_to: ctx.request_id.clone(),
            relay_state: ctx.relay_state.clone(),
        },
        top: ns::status::RESPONDER.into(),
        second: Some(second.into()),
        message: message.into(),
    };
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(
            ticket_key(tenant.id, id),
            serde_json::to_string(&ticket)?,
            TICKET_TTL_SECS,
        )
        .await?;
    Ok(format!(
        "{}/saml/respond/{id}",
        tokens::issuer(state, tenant)
    ))
}

/// Deliver a ticket from [`denial_url`] (once).
pub async fn redeem_ticket(state: &AppState, tenant: &TenantCtx, id: Uuid) -> Response {
    let raw: Option<String> = match state.redis.get().await {
        Ok(mut conn) => match redis::cmd("GETDEL")
            .arg(ticket_key(tenant.id(), id))
            .query_async(&mut conn)
            .await
        {
            Ok(v) => v,
            Err(e) => return AppError::from(e).into_response(),
        },
        Err(e) => return e.into_response(),
    };
    let Some(ticket) = raw.and_then(|r| serde_json::from_str::<Ticket>(&r).ok()) else {
        return saml_page(
            StatusCode::NOT_FOUND,
            &SamlError::malformed("this answer was already delivered or has expired"),
        );
    };
    status_response(
        state,
        tenant,
        &ticket.recipient,
        &ticket.top,
        ticket.second.as_deref(),
        &ticket.message,
    )
    .await
}

/// The `SessionIndex` of a session: opaque, and the same for every SP.
pub fn session_index(tenant: &Tenant, session_id: Uuid) -> String {
    let mut h = sha2::Sha256::new();
    h.update(b"saml-session-index|");
    h.update(session_id.as_bytes());
    h.update(&tenant.pairwise_salt);
    format!("_{}", hex::encode(&h.finalize()[..16]))
}

/// What an SP was told in a session, for logging it out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant {
    pub client_id: Uuid,
    pub name_id: String,
    pub name_id_format: String,
    pub sp_name_qualifier: Option<String>,
    pub session_index: String,
}

fn participants_key(tenant_id: Uuid, session_id: Uuid) -> String {
    format!(
        "{}:t:{tenant_id}:session:{session_id}:saml",
        cache_keys::PREFIX
    )
}

fn index_key(tenant_id: Uuid, index: &str) -> String {
    format!("{}:t:{tenant_id}:saml:sidx:{index}", cache_keys::PREFIX)
}

async fn record_participant(
    state: &AppState,
    session: &SsoSession,
    p: &Participant,
) -> AppResult<()> {
    let ttl = (session.expires_at - Utc::now()).num_seconds().max(60);
    let mut conn = state.redis.get().await?;
    let key = participants_key(session.tenant_id, session.id);
    let _: () = conn
        .hset(&key, p.client_id.to_string(), serde_json::to_string(p)?)
        .await?;
    let _: () = conn.expire(&key, ttl).await?;
    let _: () = conn
        .set_ex(
            index_key(session.tenant_id, &p.session_index),
            session.id.to_string(),
            ttl as u64,
        )
        .await?;
    Ok(())
}

/// The SAML SPs that took part in a session.
pub async fn participants(
    state: &AppState,
    tenant_id: Uuid,
    session_id: Uuid,
) -> AppResult<Vec<Participant>> {
    let mut conn = state.redis.get().await?;
    let raw: Vec<String> = conn.hvals(participants_key(tenant_id, session_id)).await?;
    Ok(raw
        .iter()
        .filter_map(|r| serde_json::from_str(r).ok())
        .collect())
}

async fn session_by_index(
    state: &AppState,
    tenant_id: Uuid,
    index: &str,
) -> AppResult<Option<Uuid>> {
    if index.len() > 128 {
        return Ok(None);
    }
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = conn.get(index_key(tenant_id, index)).await?;
    Ok(raw.and_then(|r| Uuid::parse_str(&r).ok()))
}

/// Claims as attribute values: strings as they are, numbers and booleans
/// written out, arrays one value each, objects as JSON.
fn values_of(v: &Value) -> Vec<String> {
    match v {
        Value::Null => vec![],
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a.iter().flat_map(values_of).collect(),
        Value::Object(_) => vec![v.to_string()],
        other => vec![other.to_string()],
    }
}

/// The attributes released to `sp` for `user`: the claims the client's
/// granted scopes, the profile schema and the claim mappers produce, named
/// as the SP's attribute list says (or after the claim when it has none).
async fn attributes(
    state: &AppState,
    tenant: &Tenant,
    client: &Client,
    sp: &SamlServiceProvider,
    user: &User,
    granted: &[String],
    org_id: Option<Uuid>,
) -> AppResult<Vec<protocol::Attribute>> {
    let role_list = roles::effective_roles(state, tenant.id, user.id, org_id).await?;
    let group_list = groups::groups_of_user(state, tenant.id, user.id, true).await?;
    let defs = scopes::list(state, tenant.id).await?;
    let mut claims: Map<String, Value> = scope_claims(user, granted, &defs);
    let schema = profile_schema::get(state, tenant.id).await?;
    profile_claims(user, &schema, Exposure::IdToken, &mut claims);
    let mappers = crate::oidc::token::effective_mappers_for(state, tenant.id, client).await?;
    let ctx = ClaimContext {
        tenant,
        user: Some(user),
        client_id: &client.client_id,
        scopes: granted,
        roles: &role_list,
        groups: &group_list,
    };
    apply_mappers(&mappers, &ctx, TokenKind::Id, &mut claims)?;

    let mapping = &sp.attributes.0;
    if mapping.is_empty() {
        return Ok(claims
            .iter()
            .map(|(k, v)| protocol::Attribute {
                name: k.clone(),
                name_format: AttributeNameFormat::Basic.urn(),
                friendly_name: None,
                values: values_of(v),
            })
            .filter(|a| !a.values.is_empty())
            .collect());
    }
    // `roles` and `groups` are there for the asking, as in access tokens.
    let builtin = |claim: &str| -> Option<Value> {
        match claim {
            "roles" => Some(Value::from(
                role_list.iter().map(|r| r.name.clone()).collect::<Vec<_>>(),
            )),
            "groups" => Some(Value::from(
                group_list
                    .iter()
                    .map(|g| g.name.clone())
                    .collect::<Vec<_>>(),
            )),
            _ => None,
        }
    };
    Ok(mapping
        .iter()
        .filter_map(|m| {
            let v = claims
                .get(&m.claim)
                .cloned()
                .or_else(|| builtin(&m.claim))?;
            let values = values_of(&v);
            (!values.is_empty()).then(|| protocol::Attribute {
                name: m.name.clone(),
                name_format: m.name_format.urn(),
                friendly_name: m.friendly_name.clone(),
                values,
            })
        })
        .collect())
}

/// The `AuthnContextClassRef` the assertion states.
fn authn_context(session: &SsoSession, requested: &[String]) -> &'static str {
    let mfa = session.acr.as_deref().is_some_and(flows::is_mfa_acr)
        || session.amr.iter().any(|m| m == "mfa");
    if mfa {
        if requested.iter().any(|c| c == ns::AC_MS_MULTIPLE_AUTHN)
            && !requested.iter().any(|c| c == ns::AC_REFEDS_MFA)
        {
            return ns::AC_MS_MULTIPLE_AUTHN;
        }
        return ns::AC_REFEDS_MFA;
    }
    if session.amr.iter().any(|m| m == "pwd") {
        ns::AC_PASSWORD_PROTECTED
    } else if session
        .amr
        .iter()
        .any(|m| m == crate::services::kerberos::AMR_KERBEROS)
    {
        ns::AC_KERBEROS
    } else {
        ns::AC_UNSPECIFIED
    }
}

/// Answer a SAML authorization request whose sign-in is complete: build,
/// sign (and encrypt) the assertion and post it to the SP. Called where an
/// OIDC request would get its code.
pub async fn respond(
    state: &AppState,
    tenant: &TenantCtx,
    client: &Client,
    req: &AuthRequest,
    session: &SsoSession,
) -> AppResult<Response> {
    let ctx = req
        .saml
        .as_ref()
        .ok_or_else(|| AppError::Internal("not a SAML request".into()))?;
    let recipient = Recipient {
        client_id: client.id,
        acs_url: req.redirect_uri.clone(),
        in_response_to: ctx.request_id.clone(),
        relay_state: ctx.relay_state.clone(),
    };
    // An assertion has no `act`: the SP could not tell the administrator
    // from the user, so impersonated sessions get none.
    if session.impersonator.is_some() {
        return Ok(status_response(
            state,
            tenant,
            &recipient,
            ns::status::RESPONDER,
            Some(ns::status::REQUEST_DENIED),
            "SAML sign-in is not available while impersonating a user",
        )
        .await);
    }
    let sp = saml_sps::find_by_client(state, tenant.id(), client.id)
        .await?
        .ok_or(AppError::NotFound("SAML service provider"))?;
    let user = users::get(state, tenant.id(), session.user_id).await?;

    let (name_id, spnq) = match ctx.name_id_format {
        NameIdFormat::Persistent => {
            let mut tc = tokens::TokenClient::public(client.client_id.clone());
            tc.subject_type = tokens::SubjectType::Pairwise;
            tc.sector_identifier = Some(sp.entity_id.clone());
            (
                tokens::subject_for(&tenant.tenant, &tc, &user),
                Some(sp.entity_id.clone()),
            )
        }
        NameIdFormat::Transient => (protocol::new_id(), Some(sp.entity_id.clone())),
        NameIdFormat::Email => match &user.email {
            Some(e) => (e.clone(), None),
            None => {
                return Ok(status_response(
                    state,
                    tenant,
                    &recipient,
                    ns::status::RESPONDER,
                    Some(ns::status::INVALID_NAMEID_POLICY),
                    "the user has no email address",
                )
                .await);
            }
        },
        NameIdFormat::Unspecified => (user.id.to_string(), None),
    };
    let session_index = session_index(&tenant.tenant, session.id);
    let attrs = attributes(
        state,
        &tenant.tenant,
        client,
        &sp,
        &user,
        &req.scopes,
        session.org_id,
    )
    .await?;
    let ep = endpoints(state, &tenant.tenant);
    let now = Utc::now();
    let mut assertion = protocol::assertion(&protocol::AssertionContent {
        idp_entity_id: &ep.entity_id,
        sp_entity_id: &sp.entity_id,
        acs_url: &recipient.acs_url,
        in_response_to: recipient.in_response_to.as_deref(),
        name_id: &name_id,
        name_id_format: ctx.name_id_format.urn(),
        sp_name_qualifier: spnq.as_deref(),
        session_index: &session_index,
        authn_instant: session.auth_time,
        authn_context: authn_context(session, &ctx.requested_classes),
        session_not_on_or_after: Some(session.expires_at),
        attributes: &attrs,
        now,
        lifetime: chrono::Duration::seconds(i64::from(sp.assertion_ttl_secs)),
    });
    let signer = saml_keys::signer(state, &tenant.tenant).await?;
    let internal = |e: SamlError| AppError::Internal(e.to_string());
    if sp.sign_assertion {
        signer.sign_enveloped(&mut assertion, 1).map_err(internal)?;
    }
    let body = if sp.encrypt_assertion {
        let cert = sp
            .encryption_certificate
            .as_deref()
            .ok_or_else(|| AppError::Internal("encryption certificate missing".into()))
            .and_then(|c| Certificate::parse(c).map_err(internal))?;
        let encrypted = xmlenc::encrypt(
            &assertion.to_string(),
            &cert,
            sp.data_encryption,
            sp.key_transport,
        )
        .map_err(internal)?;
        crate::saml::xml::El::new("saml:EncryptedAssertion").child(encrypted)
    } else {
        assertion
    };
    let mut response = protocol::response(
        &ep.entity_id,
        &recipient.acs_url,
        recipient.in_response_to.as_deref(),
        now,
        (ns::status::SUCCESS, None, None),
        Some(body),
    );
    if sp.sign_response {
        signer.sign_enveloped(&mut response, 1).map_err(internal)?;
    }

    record_participant(
        state,
        session,
        &Participant {
            client_id: client.id,
            name_id: name_id.clone(),
            name_id_format: ctx.name_id_format.urn().to_string(),
            sp_name_qualifier: spnq,
            session_index,
        },
    )
    .await?;
    sessions::add_client(state, session, &client.client_id).await?;
    state.events.publish(Event::new(
        Some(tenant.id()),
        Actor::User {
            id: session.user_id,
        },
        EventKind::AuthorizationGranted {
            user_id: session.user_id,
            client_id: client.id,
            scopes: req.scopes.clone(),
        },
    ));
    let mut res = binding::to_post(
        &recipient.acs_url,
        Kind::Response,
        &response.to_document(),
        recipient.relay_state.as_deref(),
    );
    html_headers(&mut res);
    Ok(res)
}

// ---------------------------------------------------------------------------
// Single Logout (front channel)
// ---------------------------------------------------------------------------

/// How a logout chain ends once every SP had its turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Finish {
    /// SP-initiated: a `LogoutResponse` to the SP that asked.
    Respond {
        client_id: Uuid,
        in_response_to: String,
        relay_state: Option<String>,
    },
    /// Started at rIDM: on to where that logout was going anyway.
    Redirect(String),
}

/// A browser being walked through the session's SAML SPs, one
/// `LogoutRequest` and `LogoutResponse` at a time.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogoutChain {
    id: Uuid,
    pending: Vec<Participant>,
    /// The SP asked last, and the ID of that `LogoutRequest`.
    current: Option<(Uuid, String)>,
    /// Some SP did not confirm.
    partial: bool,
    /// OIDC front-channel logout URLs, framed on the last page.
    frontchannel: Vec<String>,
    /// The upstream SAML IdP that brokered the ended session: told after
    /// the SPs, before the SP that asked is answered.
    #[serde(default)]
    upstream: Option<crate::services::saml_sp::UpstreamSession>,
    finish: Finish,
}

fn chain_key(tenant_id: Uuid, id: Uuid) -> String {
    format!("{}:t:{tenant_id}:saml:slo:{id}", cache_keys::PREFIX)
}

async fn save_chain(state: &AppState, tenant_id: Uuid, chain: &LogoutChain) -> AppResult<()> {
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(
            chain_key(tenant_id, chain.id),
            serde_json::to_string(chain)?,
            CHAIN_TTL_SECS,
        )
        .await?;
    Ok(())
}

async fn load_chain(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<Option<LogoutChain>> {
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = conn.get(chain_key(tenant_id, id)).await?;
    Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
}

async fn drop_chain(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<()> {
    let mut conn = state.redis.get().await?;
    let _: () = conn.del(chain_key(tenant_id, id)).await?;
    Ok(())
}

/// Where a logout that started at rIDM goes when the session had SAML SPs:
/// through each of them, then on to `target`. `target` itself when it had
/// none.
pub async fn logout_through(
    state: &AppState,
    tenant: &Tenant,
    participants: Vec<Participant>,
    target: String,
) -> AppResult<String> {
    if participants.is_empty() {
        return Ok(target);
    }
    let chain = LogoutChain {
        id: Uuid::new_v4(),
        pending: participants,
        current: None,
        partial: false,
        frontchannel: vec![],
        upstream: None,
        finish: Finish::Redirect(target),
    };
    save_chain(state, tenant.id, &chain).await?;
    Ok(format!(
        "{}/saml/slo/chain/{}",
        tokens::issuer(state, tenant),
        chain.id
    ))
}

/// Resume a chain started by [`logout_through`].
pub async fn continue_chain(state: &AppState, tenant: &TenantCtx, id: Uuid) -> Response {
    match load_chain(state, tenant.id(), id).await {
        Ok(Some(chain)) if chain.current.is_none() => step(state, tenant, chain).await,
        Ok(_) => saml_page(
            StatusCode::NOT_FOUND,
            &SamlError::malformed("this sign-out has finished or expired"),
        ),
        Err(e) => e.into_response(),
    }
}

/// Send the next SP its `LogoutRequest`, or finish.
async fn step(state: &AppState, tenant: &TenantCtx, mut chain: LogoutChain) -> Response {
    let ep = endpoints(state, &tenant.tenant);
    while let Some(p) = chain.pending.pop() {
        let sp = match saml_sps::find_by_client(state, tenant.id(), p.client_id).await {
            Ok(Some(sp)) => sp,
            Ok(None) => continue,
            Err(e) => return e.into_response(),
        };
        let Some(slo_url) = sp.slo_url.clone() else {
            continue;
        };
        let request = protocol::logout_request(
            &ep.entity_id,
            &slo_url,
            &NameId {
                value: p.name_id.clone(),
                format: Some(p.name_id_format.clone()),
                sp_name_qualifier: p.sp_name_qualifier.clone(),
            },
            Some(&p.session_index),
            Utc::now(),
        );
        let request_id = request.attribute("ID").unwrap_or_default().to_string();
        chain.current = Some((p.client_id, request_id));
        if let Err(e) = save_chain(state, tenant.id(), &chain).await {
            return e.into_response();
        }
        let relay = chain.id.to_string();
        return match deliver_to_sp(
            state,
            tenant,
            &sp,
            &slo_url,
            Kind::Request,
            request,
            Some(&relay),
        )
        .await
        {
            Ok(r) => r,
            Err(e) => e.into_response(),
        };
    }
    // Every SP had its turn; the upstream IdP next, then back here to
    // finish.
    if let Some(up) = chain.upstream.take() {
        if let Err(e) = save_chain(state, tenant.id(), &chain).await {
            return e.into_response();
        }
        let back = format!(
            "{}/saml/slo/chain/{}",
            tokens::issuer(state, &tenant.tenant),
            chain.id
        );
        return match crate::services::saml_sp::logout_upstream(
            state,
            &tenant.tenant,
            Some(up),
            back,
        )
        .await
        {
            Ok(to) => Redirect::to(&to).into_response(),
            Err(e) => e.into_response(),
        };
    }
    if let Err(e) = drop_chain(state, tenant.id(), chain.id).await {
        return e.into_response();
    }
    finish_chain(state, tenant, chain).await
}

/// Sign and send a message to an SP's logout service by its binding.
async fn deliver_to_sp(
    state: &AppState,
    tenant: &TenantCtx,
    sp: &SamlServiceProvider,
    url: &str,
    kind: Kind,
    mut el: crate::saml::xml::El,
    relay: Option<&str>,
) -> AppResult<Response> {
    let signer = saml_keys::signer(state, &tenant.tenant).await?;
    let internal = |e: SamlError| AppError::Internal(e.to_string());
    let mut res = match sp.slo_binding {
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
    html_headers(&mut res);
    Ok(res)
}

async fn finish_chain(state: &AppState, tenant: &TenantCtx, chain: LogoutChain) -> Response {
    let next = match chain.finish {
        Finish::Redirect(target) => Redirect::to(&target).into_response(),
        Finish::Respond {
            client_id,
            in_response_to,
            relay_state,
        } => {
            let sp = match saml_sps::find_by_client(state, tenant.id(), client_id).await {
                Ok(Some(sp)) => sp,
                Ok(None) => {
                    return saml_page(
                        StatusCode::OK,
                        &SamlError::malformed("signed out; the application is gone"),
                    );
                }
                Err(e) => return e.into_response(),
            };
            let Some(slo_url) = sp.slo_url.clone() else {
                return signed_out_page(state, tenant);
            };
            // Some SP did not confirm: `PartialLogout` under `Success` tells
            // the SP that asked (SAML Core §3.2.2.2).
            let second = chain.partial.then_some(ns::status::PARTIAL_LOGOUT);
            let ep = endpoints(state, &tenant.tenant);
            let el = protocol::logout_response(
                &ep.entity_id,
                &slo_url,
                &in_response_to,
                (ns::status::SUCCESS, second),
                Utc::now(),
            );
            match deliver_to_sp(
                state,
                tenant,
                &sp,
                &slo_url,
                Kind::Response,
                el,
                relay_state.as_deref(),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => e.into_response(),
            }
        }
    };
    with_frontchannel(next, &chain.frontchannel).await
}

/// The `<form>` of an auto-posting page (`binding::to_post`), whose own
/// `onload` submission is left behind with the rest of the page.
async fn form_of(page: Response) -> Option<String> {
    let body = axum::body::to_bytes(page.into_body(), 1024 * 1024)
        .await
        .ok()?;
    let html = std::str::from_utf8(&body).ok()?;
    let start = html.find("<form")?;
    let end = html[start..].find("</form>")? + start + "</form>".len();
    Some(
        html[start..end]
            .replace("<noscript>", "")
            .replace("</noscript>", ""),
    )
}

fn signed_out_page(state: &AppState, tenant: &TenantCtx) -> Response {
    let target = state.ui_page(
        &tenant.tenant,
        "logout",
        &[("tenant", tenant.slug()), ("done", "1")],
    );
    Redirect::to(&target).into_response()
}

/// Frame the OIDC front-channel logout URLs before `next` (a redirect or
/// an auto-posting form) runs: they get two seconds to load.
async fn with_frontchannel(next: Response, frontchannel: &[String]) -> Response {
    if frontchannel.is_empty() {
        return next;
    }
    let frames: String = frontchannel
        .iter()
        .map(|u| {
            format!(
                "<iframe src=\"{}\" style=\"display:none\"></iframe>",
                authorize::html_escape(u)
            )
        })
        .collect();
    // A redirect continues through a link the page follows after the
    // frames; an auto-posting form is embedded as it is, and submitted
    // after them.
    let (continue_html, script) = match next.headers().get(header::LOCATION) {
        Some(loc) => {
            let loc = authorize::html_escape(loc.to_str().unwrap_or_default());
            (
                format!("<a id=\"next\" href=\"{loc}\">Continue</a>"),
                "setTimeout(function(){location.href=document.getElementById('next').href},2000)",
            )
        }
        None => match form_of(next).await {
            Some(form) => (
                form,
                "setTimeout(function(){document.forms[0].submit()},2000)",
            ),
            None => (String::new(), ""),
        },
    };
    let mut origins: Vec<String> = frontchannel
        .iter()
        .filter_map(|u| url::Url::parse(u).ok())
        .map(|u| u.origin().ascii_serialization())
        .collect();
    origins.sort();
    origins.dedup();
    let html = format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Signing out</title></head>\
         <body>{frames}<p>Signing you out…</p>{continue_html}<script>{script}</script></body></html>"
    );
    let csp = format!(
        "default-src 'none'; frame-src {}; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
         frame-ancestors 'none'; base-uri 'none'; form-action *",
        origins.join(" ")
    );
    let mut res = (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        html,
    )
        .into_response();
    if let Ok(v) = HeaderValue::from_str(&csp) {
        res.headers_mut().insert(header::CONTENT_SECURITY_POLICY, v);
    }
    html_headers(&mut res);
    res
}

/// A message arriving at the SLO endpoint: an SP asking to end the session
/// (SP-initiated), or an SP answering one of rIDM's requests (a chain).
pub async fn slo(
    state: &AppState,
    tenant: &TenantCtx,
    headers: &HeaderMap,
    received: Received,
) -> Response {
    let page = |e: SamlError| saml_page(StatusCode::BAD_REQUEST, &e);
    let doc = match xml::parse(&received.xml) {
        Ok(d) => d,
        Err(e) => return page(e),
    };
    match received.kind {
        Kind::Request => logout_request(state, tenant, headers, &received, &doc).await,
        Kind::Response => logout_response(state, tenant, &received, &doc).await,
    }
}

async fn logout_request(
    state: &AppState,
    tenant: &TenantCtx,
    headers: &HeaderMap,
    received: &Received,
    doc: &roxmltree::Document<'_>,
) -> Response {
    let page = |e: SamlError| saml_page(StatusCode::BAD_REQUEST, &e);
    let req = match protocol::parse_logout_request(doc) {
        Ok(r) => r,
        Err(e) => return page(e),
    };
    let entry = match saml_sps::find_by_entity_id(state, tenant.id(), &req.issuer).await {
        Ok(Some(e)) => e,
        Ok(None) => {
            return page(SamlError::malformed(
                "the issuer is not a registered service provider",
            ));
        }
        Err(e) => return e.into_response(),
    };
    let sp = &entry.sp;
    let signed = match check_signature(sp, received, doc) {
        Ok(s) => s,
        Err(e) => return page(e),
    };
    let ep = endpoints(state, &tenant.tenant);
    match &req.destination {
        Some(d) if *d != ep.slo_url => {
            return page(SamlError::malformed(
                "Destination is not this IdP's logout endpoint",
            ));
        }
        None if signed => {
            return page(SamlError::malformed(
                "a signed request must name its Destination",
            ));
        }
        _ => {}
    }
    let now = Utc::now();
    if let Err(e) = check_instant(req.issue_instant, now) {
        return page(e);
    }
    if req.not_on_or_after.is_some_and(|t| t <= now - CLOCK_SKEW) {
        return page(SamlError::malformed("the request has expired"));
    }
    match first_sighting(state, tenant.id(), sp.client_id, &req.id).await {
        Ok(true) => {}
        Ok(false) => return page(SamlError::malformed("this request was already used")),
        Err(e) => return e.into_response(),
    }

    // The session: by SessionIndex (a cross-site POST carries no cookie),
    // else the browser's own; either way only if this SP was told this
    // NameID in it.
    let mut candidates = vec![];
    for idx in &req.session_indexes {
        match session_by_index(state, tenant.id(), idx).await {
            Ok(Some(sid)) => candidates.push(sid),
            Ok(None) => {}
            Err(e) => return e.into_response(),
        }
    }
    match sessions::session_id_from_headers(state, &tenant.tenant, headers) {
        Some(sid) if req.session_indexes.is_empty() => candidates.push(sid),
        _ => {}
    }
    let mut ended = None;
    for sid in candidates {
        let parts = match participants(state, tenant.id(), sid).await {
            Ok(p) => p,
            Err(e) => return e.into_response(),
        };
        if parts
            .iter()
            .any(|p| p.client_id == sp.client_id && p.name_id == req.name_id.value)
        {
            ended = Some((sid, parts));
            break;
        }
    }
    let mut pending = vec![];
    let mut frontchannel = vec![];
    let mut upstream = None;
    if let Some((sid, parts)) = ended {
        match crate::services::logout::end_session(state, &tenant.tenant, sid).await {
            Ok(outcome) => {
                frontchannel = outcome.frontchannel_logout_uris;
                upstream = outcome.saml_upstream;
            }
            Err(e) => return e.into_response(),
        }
        pending = parts
            .into_iter()
            .filter(|p| p.client_id != sp.client_id)
            .collect();
    }
    let chain = LogoutChain {
        id: Uuid::new_v4(),
        pending,
        current: None,
        partial: false,
        frontchannel,
        upstream,
        finish: Finish::Respond {
            client_id: sp.client_id,
            in_response_to: req.id,
            relay_state: received.relay_state.clone(),
        },
    };
    let mut res = step(state, tenant, chain).await;
    if let Ok(v) = HeaderValue::from_str(&sessions::clear_cookie_header(state, &tenant.tenant)) {
        res.headers_mut().append(header::SET_COOKIE, v);
    }
    res
}

async fn logout_response(
    state: &AppState,
    tenant: &TenantCtx,
    received: &Received,
    doc: &roxmltree::Document<'_>,
) -> Response {
    let page = |e: SamlError| saml_page(StatusCode::BAD_REQUEST, &e);
    let res = match protocol::parse_logout_response(doc) {
        Ok(r) => r,
        Err(e) => return page(e),
    };
    let Some(chain_id) = received
        .relay_state
        .as_deref()
        .and_then(|r| Uuid::parse_str(r).ok())
    else {
        return page(SamlError::malformed(
            "no sign-out is waiting for this answer",
        ));
    };
    let mut chain = match load_chain(state, tenant.id(), chain_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return page(SamlError::malformed(
                "this sign-out has finished or expired",
            ));
        }
        Err(e) => return e.into_response(),
    };
    let Some((client_id, request_id)) = chain.current.clone() else {
        return page(SamlError::malformed(
            "no sign-out is waiting for this answer",
        ));
    };
    let entry = match saml_sps::find_by_entity_id(state, tenant.id(), &res.issuer).await {
        Ok(Some(e)) if e.sp.client_id == client_id => e,
        Ok(_) => {
            return page(SamlError::malformed(
                "the answer is not from the service provider that was asked",
            ));
        }
        Err(e) => return e.into_response(),
    };
    if res.in_response_to.as_deref() != Some(request_id.as_str()) {
        return page(SamlError::malformed(
            "InResponseTo does not match the request",
        ));
    }
    if let Err(e) = check_signature(&entry.sp, received, doc) {
        return page(e);
    }
    if res.status != ns::status::SUCCESS {
        chain.partial = true;
    }
    chain.current = None;
    step(state, tenant, chain).await
}
