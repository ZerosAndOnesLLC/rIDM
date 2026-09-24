//! Kerberos realms as identity providers: desktop single sign-on over
//! HTTP Negotiate (SPNEGO).
//!
//! **Asking.** The login page posts to `/flows/{id}/kerberos`. Asked on
//! its own (`auto`), rIDM challenges (`401` with `WWW-Authenticate:
//! Negotiate`) only a browser on one of the tenant's trusted networks, and
//! only for a flow that does not demand a fresh sign-in; the user's click
//! on the provider's button always challenges. A browser holding a ticket
//! for rIDM's service answers with it; one that has none gives up quietly
//! and the login page shows the usual form. The trusted networks decide
//! when to ask, not who may sign in: a ticket is proof wherever it comes
//! from.
//!
//! **Proof.** The ticket must be for a provider's service principal and
//! decrypt under its keytab ([`crate::kerberos::Acceptor`]: validity,
//! allowed realms, the authenticator's client and clock), and its
//! authenticator must be new to the replay cache (Valkey, for twice the
//! allowed skew).
//!
//! **Who.** With a directory (an LDAP provider) the name is looked up in it
//! and the entry imported or refreshed as a password sign-in would do;
//! otherwise the principal's own link, then the local account named by it
//! (`match_username`), then a new account (`create_users`). The sign-in
//! then goes on like any first factor: MFA policy, risk, consent.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::kerberos::{self, Acceptor, Principal, spnego};
use crate::middleware::TenantCtx;
use crate::models::{
    IdentityProvider, IdpKind, KerberosNameForm, KerberosUpstream, LdapVendor, Tenant, User,
    UserStatus,
};
use crate::repos;
use crate::services::broker::{self, Identity};
use crate::services::flows::{self, AuthStep, RequestContext};
use crate::services::identity_providers;
use crate::services::ldap::{self, DirectoryMatch};
use crate::services::login_flows::{FlowStage, LoginFlow};
use crate::state::AppState;

/// The `amr` a Kerberos sign-in records.
pub const AMR_KERBEROS: &str = "kerberos";

const REALMS_TTL: Duration = Duration::from_secs(60);

/// What the login page needs to know of a tenant's Kerberos providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Offered {
    pub id: Uuid,
    pub alias: String,
    pub display_name: String,
    pub hidden: bool,
    pub trusted_networks: Vec<String>,
}

/// How long a node keeps a provider's parsed keytab. Any change to the
/// provider names a new entry (its `updated_at` is in the key).
const KEYTAB_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// A provider's keytab, decrypted and parsed once per node (not on every
/// Negotiate header); `None` when it has none.
async fn keytab(
    state: &AppState,
    tenant_id: Uuid,
    idp: &crate::models::IdentityProvider,
) -> AppResult<Option<Arc<Vec<kerberos::KeytabEntry>>>> {
    let key = keys::kerberos_keytab(tenant_id, idp.id, idp.updated_at.timestamp_micros());
    let material = state.cache.material();
    if let Some(parsed) = material.get::<Vec<kerberos::KeytabEntry>>(&key) {
        return Ok(Some(parsed));
    }
    let ticket = material.ticket(&key);
    let Some(b64) = identity_providers::client_secret(state, idp).await? else {
        return Ok(None);
    };
    let parsed = {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|e| AppError::Internal(format!("stored keytab: {e}")))?;
        Arc::new(
            kerberos::parse_keytab(&bytes)
                .map_err(|e| AppError::Internal(format!("stored keytab: {e}")))?,
        )
    };
    material.insert_fresh(key, parsed.clone(), KEYTAB_TTL, ticket);
    Ok(Some(parsed))
}

/// The tenant's enabled Kerberos providers, cached (most tenants have
/// none). Empty when this build cannot accept tickets.
pub async fn offered(state: &AppState, tenant_id: Uuid) -> AppResult<Vec<Offered>> {
    if !kerberos::crypto::AVAILABLE {
        return Ok(vec![]);
    }
    let db = state.db.clone();
    let cached: Option<Arc<Vec<Offered>>> = state
        .cache
        .get_or_load(
            &keys::kerberos_realms(tenant_id),
            REALMS_TTL,
            || async move {
                let mut tx = db::tenant_tx(&db, tenant_id).await?;
                let rows = repos::identity_providers::list(&mut *tx, tenant_id).await?;
                let settings = if rows.iter().any(|p| p.kind == IdpKind::Kerberos) {
                    repos::identity_providers::list_kerberos(&mut *tx, tenant_id).await?
                } else {
                    vec![]
                };
                tx.commit().await?;
                Ok(Some(
                    rows.iter()
                        .filter(|p| p.enabled && p.kind == IdpKind::Kerberos && p.client_secret_set)
                        .filter_map(|p| {
                            let k = settings.iter().find(|k| k.idp_id == p.id)?;
                            Some(Offered {
                                id: p.id,
                                alias: p.alias.clone(),
                                display_name: p.display_name.clone(),
                                hidden: p.hidden,
                                trusted_networks: k.trusted_networks.clone(),
                            })
                        })
                        .collect::<Vec<_>>(),
                ))
            },
        )
        .await?;
    Ok(cached.map(|v| v.as_ref().clone()).unwrap_or_default())
}

/// The login page's Kerberos button: the first provider that is not
/// hidden. `None` hides the button (automatic sign-in may still happen).
#[derive(Debug, Clone, Serialize)]
pub struct PublicKerberos {
    /// The button's label; no button when `None`.
    pub display_name: Option<String>,
}

pub async fn public(state: &AppState, tenant_id: Uuid) -> AppResult<Option<PublicKerberos>> {
    let realms = offered(state, tenant_id).await?;
    if realms.is_empty() {
        return Ok(None);
    }
    Ok(Some(PublicKerberos {
        display_name: realms
            .iter()
            .find(|r| !r.hidden)
            .map(|r| r.display_name.clone()),
    }))
}

fn on_trusted_network(realms: &[Offered], ip: Option<&str>) -> bool {
    let Some(ip) = ip.and_then(|i| i.parse::<std::net::IpAddr>().ok()) else {
        return false;
    };
    realms.iter().any(|r| {
        r.trusted_networks
            .iter()
            .filter_map(|n| n.parse::<ipnet::IpNet>().ok())
            .any(|n| n.contains(&ip))
    })
}

/// Should the login page's request be answered with a Negotiate challenge?
/// `NotFound` when the tenant has no usable Kerberos provider.
pub async fn challenge(
    state: &AppState,
    tenant_id: Uuid,
    flow: &LoginFlow,
    ip: Option<&str>,
    auto: bool,
) -> AppResult<bool> {
    let realms = offered(state, tenant_id).await?;
    if realms.is_empty() {
        return Err(AppError::NotFound("kerberos"));
    }
    if !auto {
        return Ok(true);
    }
    // A request that wants the user to authenticate again (`prompt=login`,
    // `max_age=0`), typically to switch accounts, is not answered by the
    // ticket the desktop holds anyway.
    let fresh_asked =
        flow.request.prompt.iter().any(|p| p == "login") || flow.request.max_age == Some(0);
    Ok(!fresh_asked && on_trusted_network(&realms, ip))
}

/// Why a Kerberos sign-in did not happen; the login page shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The browser offered NTLM: it had no ticket for this host.
    Ntlm,
    /// No Kerberos token (another mechanism, or none).
    Unsupported,
    /// The ticket was refused (wrong service or key, expired, clock, realm).
    Invalid,
    /// The authenticator was seen before.
    Replay,
    /// Nobody in rIDM is this principal.
    NoAccount,
    AccountDisabled,
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Self::Ntlm => "kerberos_ntlm",
            Self::Unsupported => "kerberos_unsupported",
            Self::Invalid => "kerberos_invalid",
            Self::Replay => "kerberos_replay",
            Self::NoAccount => "kerberos_no_account",
            Self::AccountDisabled => "account_disabled",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::Ntlm | Self::Unsupported => {
                "your computer did not offer a Kerberos ticket for this site"
            }
            Self::Invalid | Self::Replay => "your Kerberos ticket was not accepted",
            Self::NoAccount => "no account matches your Kerberos sign-in",
            Self::AccountDisabled => "your account is disabled",
        }
    }
}

/// What a Negotiate token led to.
pub enum Negotiation {
    /// Signed in (or refused by the risk policy): the flow's step, and the
    /// token to send back in `WWW-Authenticate` (mutual authentication).
    Done {
        step: AuthStep,
        answer: Option<Vec<u8>>,
    },
    Refused(Refusal),
}

/// A Kerberos provider with its settings.
struct Realm {
    idp: IdentityProvider,
    cfg: KerberosUpstream,
}

async fn realm_for(
    state: &AppState,
    tenant_id: Uuid,
    service: &Principal,
) -> AppResult<Option<Realm>> {
    for o in offered(state, tenant_id).await? {
        let idp = match identity_providers::get_cached(state, tenant_id, &o.id.to_string()).await {
            Ok(p) => p,
            Err(AppError::NotFound(_)) => continue,
            Err(e) => return Err(e),
        };
        let Some(cfg) = idp.kerberos.clone() else {
            continue;
        };
        let matches =
            Principal::parse(&cfg.service_principal).is_ok_and(|p| p.eq_ignore_case(service));
        if idp.enabled && matches {
            return Ok(Some(Realm { idp, cfg }));
        }
    }
    Ok(None)
}

fn metric(outcome: &'static str) {
    metrics::counter!("ridm_kerberos_negotiations_total", "outcome" => outcome).increment(1);
}

/// Sign in the login flow with the browser's Negotiate token.
pub async fn negotiate(
    state: &AppState,
    tenant: &TenantCtx,
    flow: LoginFlow,
    token: &[u8],
    ctx: RequestContext,
) -> AppResult<Negotiation> {
    if flow.stage != FlowStage::Authenticate {
        return Err(AppError::BadRequest(
            "flow is not at the authenticate step".into(),
        ));
    }
    let offer = match spnego::parse(token) {
        Ok(spnego::Negotiated::Kerberos(o)) => o,
        Ok(spnego::Negotiated::Ntlm) => {
            metric("ntlm");
            return Ok(Negotiation::Refused(Refusal::Ntlm));
        }
        Ok(spnego::Negotiated::Unsupported(why)) => {
            tracing::info!(reason = why, "Negotiate token without Kerberos");
            metric("unsupported");
            return Ok(Negotiation::Refused(Refusal::Unsupported));
        }
        Err(e) => {
            tracing::info!(error = %e, "malformed Negotiate token");
            metric("invalid");
            return Ok(Negotiation::Refused(Refusal::Invalid));
        }
    };
    let refused_ticket = |why: String| {
        tracing::warn!(reason = %why, "Kerberos ticket refused");
        metric("invalid");
        Ok(Negotiation::Refused(Refusal::Invalid))
    };
    let service = match kerberos::service_of(&offer.ap_req) {
        Ok(s) => s,
        Err(e) => return refused_ticket(e.to_string()),
    };
    let Some(realm) = realm_for(state, tenant.id(), &service).await? else {
        return refused_ticket(format!("no enabled provider accepts tickets for {service}"));
    };
    let Some(keys) = keytab(state, tenant.id(), &realm.idp).await? else {
        return refused_ticket(format!("provider `{}` has no keytab", realm.idp.alias));
    };
    let spn = Principal::parse(&realm.cfg.service_principal)
        .map_err(|e| AppError::Internal(format!("stored service principal: {e}")))?;
    let skew = i64::from(realm.cfg.max_skew_seconds.clamp(30, 900));
    let accepted = match (Acceptor {
        keys: &keys,
        service: &spn,
        realms: &realm.cfg.realms,
        max_skew: chrono::Duration::seconds(skew),
        now: Utc::now(),
    })
    .accept(&offer.ap_req)
    {
        Ok(a) => a,
        Err(e) => return refused_ticket(format!("provider `{}`: {e}", realm.idp.alias)),
    };
    // The replay cache: an authenticator is good once. It lives as long as
    // its time could still pass the skew check.
    let replay_key = keys::kerberos_replay(tenant.id(), &hex::encode(accepted.replay_key));
    let mut conn = state.redis.get().await?;
    let fresh: bool = redis::cmd("SET")
        .arg(&replay_key)
        .arg(1)
        .arg("NX")
        .arg("EX")
        .arg(2 * skew + 60)
        .query_async::<Option<String>>(&mut conn)
        .await?
        .is_some();
    drop(conn);
    if !fresh {
        tracing::warn!(provider = %realm.idp.alias, client = %accepted.client, "Kerberos authenticator replayed");
        metric("replay");
        return Ok(Negotiation::Refused(Refusal::Replay));
    }

    let user = match resolve(state, &tenant.tenant, &realm, &accepted.client).await? {
        Ok(u) => u,
        Err(r) => {
            let mut tx = db::tenant_tx(&state.db, tenant.id()).await?;
            repos::login_attempts::record(
                &mut *tx,
                tenant.id(),
                &accepted.client.to_string(),
                ctx.ip.as_deref(),
                false,
                Some(r.code()),
            )
            .await?;
            tx.commit().await?;
            metric(if r == Refusal::NoAccount {
                "no_account"
            } else {
                "disabled"
            });
            return Ok(Negotiation::Refused(r));
        }
    };
    let step = flows::complete_authentication(
        state,
        tenant,
        flow,
        &user,
        vec![AMR_KERBEROS.into()],
        ctx,
        false,
    )
    .await?;
    metric("success");
    state.events.publish(Event::new(
        Some(tenant.id()),
        Actor::User { id: user.id },
        EventKind::BrokeredLogin {
            user_id: user.id,
            idp_id: realm.idp.id,
            provider: realm.idp.alias.clone(),
        },
    ));
    Ok(Negotiation::Done {
        step,
        answer: spnego::answer(&offer, accepted.ap_rep.as_deref()),
    })
}

/// The directory attribute a name is looked up by, when the provider does
/// not name one.
pub fn default_ldap_attribute(vendor: LdapVendor, form: KerberosNameForm) -> &'static str {
    match (vendor, form) {
        (LdapVendor::ActiveDirectory, KerberosNameForm::LocalPart) => "sAMAccountName",
        (LdapVendor::ActiveDirectory, KerberosNameForm::Principal) => "userPrincipalName",
        (_, KerberosNameForm::LocalPart) => "uid",
        (_, KerberosNameForm::Principal) => "krbPrincipalName",
    }
}

fn usable(u: &User) -> bool {
    u.status == UserStatus::Active && !u.is_locked_now() && u.deleted_at.is_none()
}

/// The rIDM user a client principal is.
async fn resolve(
    state: &AppState,
    tenant: &Tenant,
    realm: &Realm,
    client: &Principal,
) -> AppResult<Result<User, Refusal>> {
    let name = match realm.cfg.name_form {
        KerberosNameForm::LocalPart => client.name(),
        KerberosNameForm::Principal => client.to_string(),
    };
    if let Some(dir_id) = realm.cfg.ldap_idp_id {
        let Some(dir) = ldap::load(state, tenant.id, dir_id).await? else {
            tracing::warn!(provider = %realm.idp.alias, "the Kerberos provider's directory is gone");
            return Ok(Err(Refusal::NoAccount));
        };
        let attribute =
            realm.cfg.ldap_attribute.clone().unwrap_or_else(|| {
                default_ldap_attribute(dir.cfg.vendor, realm.cfg.name_form).into()
            });
        return Ok(
            match ldap::sign_in_proven(state, tenant, &dir, &attribute, &name).await? {
                DirectoryMatch::User(u) if usable(&u) => Ok(*u),
                DirectoryMatch::User(_) | DirectoryMatch::Refused => Err(Refusal::AccountDisabled),
                DirectoryMatch::None => Err(Refusal::NoAccount),
            },
        );
    }

    let identity = Identity {
        subject: client.to_string(),
        email: None,
        email_verified: false,
        username: Some(name.clone()),
        claims: Default::default(),
    };
    let tid = tenant.id;
    let mut tx = db::tenant_tx(&state.db, tid).await?;
    let linked =
        repos::federated_identities::find(&mut *tx, tid, realm.idp.id, &identity.subject).await?;
    let by_name = match (&linked, realm.cfg.match_username) {
        (None, true) => match crate::services::users::normalize_username(&name) {
            Ok(n) => repos::users::find_by_username(&mut *tx, tid, &n).await?,
            Err(_) => None,
        },
        _ => None,
    };
    tx.commit().await?;
    if linked.is_some() {
        // Status, and a user who is gone, are the broker's business.
        return Ok(broker::resolve_user(state, tenant, &realm.idp, &identity)
            .await?
            .map_err(|_| Refusal::AccountDisabled));
    }
    if let Some(u) = by_name {
        if !usable(&u) {
            return Ok(Err(Refusal::AccountDisabled));
        }
        return Ok(
            match broker::link(state, tenant, &realm.idp, &u, &identity).await? {
                Ok(()) => Ok(u),
                Err(e) => {
                    tracing::info!(provider = %realm.idp.alias, reason = e.code(), "Kerberos principal not linked");
                    Err(Refusal::NoAccount)
                }
            },
        );
    }
    if realm.cfg.create_users {
        return Ok(broker::resolve_user(state, tenant, &realm.idp, &identity)
            .await?
            .map_err(|_| Refusal::NoAccount));
    }
    Ok(Err(Refusal::NoAccount))
}
