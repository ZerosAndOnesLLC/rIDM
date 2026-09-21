//! Tenant configuration as code: a deterministic JSON document of everything
//! an administrator configures (settings, schema, resource servers, scopes,
//! clients, roles, groups, claim mappers, message templates, webhooks, IP
//! rules), keyed by natural identifiers rather than ids, and an idempotent
//! apply that reports its plan first. Secrets are never exported; a client or
//! webhook created by an import gets a fresh secret, returned once in the
//! report. Users, sessions and provider credentials (SMTP, SMS, CAPTCHA) are
//! not configuration and stay out.

use std::collections::{BTreeMap, BTreeSet};

use ridm_core::events::Actor;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::{
    ClientStatus, GroupUpdate, IpRuleAction, IpRuleUpdate, MessageChannel, NewClaimMapper,
    NewClient, NewGroup, NewIpRule, NewPermission, NewResourceServer, NewRole, NewScope,
    NewWebhook, Principal, ProfileSchema, ResourceServerUpdate, RoleUpdate, STANDARD_SCOPES,
    ScopeUpdate, Tenant, TenantSettings, WebhookUpdate,
};
use crate::models::{
    IdentityProviderUpdate, IdpAuthMethod, IdpKind, IdpMappers, LinkPolicy, NewIdentityProvider,
};
use crate::services::admin_access::{self, Grant};
use crate::services::messaging::TemplateBody;
use crate::services::saml_sps::{self, SamlSpInput};
use crate::services::tenants::TenantUpdate;
use crate::services::{
    admin_console, claim_mappers, clients, groups, identity_providers, ip_rules,
    messaging as messaging_admin, profile_schema, resource_servers, roles, scopes, tenants,
    webhooks,
};
use crate::state::AppState;

pub const FORMAT: &str = "ridm.tenant/1";

// --- document ------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TenantConfig {
    pub format: String,
    pub tenant: TenantSection,
    #[serde(default)]
    pub profile_schema: ProfileSchema,
    #[serde(default)]
    pub resource_servers: Vec<ResourceServerDoc>,
    #[serde(default)]
    pub scopes: Vec<ScopeDoc>,
    #[serde(default)]
    pub clients: Vec<ClientDoc>,
    #[serde(default)]
    pub roles: Vec<RoleDoc>,
    #[serde(default)]
    pub groups: Vec<GroupDoc>,
    #[serde(default)]
    pub claim_mappers: Vec<MapperDoc>,
    #[serde(default)]
    pub message_templates: Vec<TemplateDoc>,
    #[serde(default)]
    pub webhooks: Vec<WebhookDoc>,
    #[serde(default)]
    pub ip_rules: Vec<IpRuleDoc>,
    /// Upstream providers without their client secrets (set those after an import).
    #[serde(default)]
    pub identity_providers: Vec<IdentityProviderDoc>,
    /// SAML service providers (`saml` clients), which `clients` leaves out.
    #[serde(default)]
    pub saml_service_providers: Vec<SamlSpDoc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TenantSection {
    /// Informational: an import applies to the tenant in the URL.
    pub slug: String,
    pub display_name: String,
    #[serde(default)]
    pub settings: TenantSettings,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceServerDoc {
    pub identifier: String,
    pub name: String,
    pub token_ttl_secs: Option<i32>,
    pub signing_alg: Option<String>,
    pub allow_offline_access: bool,
    pub permissions: Vec<PermissionDoc>,
}

impl Default for ResourceServerDoc {
    fn default() -> Self {
        Self {
            identifier: String::new(),
            name: String::new(),
            token_ttl_secs: None,
            signing_alg: None,
            allow_offline_access: true,
            permissions: vec![],
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PermissionDoc {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ScopeDoc {
    pub name: String,
    pub description: Option<String>,
    pub claims: Vec<String>,
    pub is_default: bool,
    /// Resource server identifier.
    pub resource_server: Option<String>,
}

/// A client's metadata document: every field `POST /clients` accepts, plus
/// `status` and whether it has a service account. Never a secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ClientDoc {
    pub client_id: String,
    #[serde(default = "default_status")]
    pub status: ClientStatus,
    #[serde(default)]
    pub service_account: bool,
    #[serde(flatten)]
    #[schema(value_type = Object)]
    pub metadata: serde_json::Map<String, Value>,
}

fn default_status() -> ClientStatus {
    ClientStatus::Active
}

/// A SAML service provider: its registration as `POST /saml/service-providers`
/// takes it, keyed by the public client id, plus `status`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SamlSpDoc {
    pub client_id: String,
    #[serde(default = "default_status")]
    pub status: ClientStatus,
    #[serde(flatten)]
    #[schema(value_type = Object)]
    pub settings: serde_json::Map<String, Value>,
}

/// A registration as a document: every field, `null`s dropped, without the
/// key.
fn saml_settings(input: &SamlSpInput) -> AppResult<serde_json::Map<String, Value>> {
    let mut v = serde_json::to_value(input)?;
    let map = v.as_object_mut().expect("input serializes to an object");
    map.remove("client_id");
    map.retain(|_, v| !v.is_null());
    Ok(map.clone())
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RoleDoc {
    pub name: String,
    /// Public `client_id` of the client the role belongs to; absent = realm role.
    pub client: Option<String>,
    pub description: Option<String>,
    /// Role references: `name` for realm roles, `client_id/name` for client roles.
    pub composites: Vec<String>,
    /// `resource server identifier#permission name`.
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct GroupDoc {
    /// Names from the root down; the last element is the group's own name.
    pub path: Vec<String>,
    pub description: Option<String>,
    pub attributes: Value,
    /// Role references (see `RoleDoc::composites`).
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct MapperDoc {
    pub name: String,
    pub client: Option<String>,
    pub config: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TemplateDoc {
    pub channel: MessageChannel,
    pub event: String,
    pub locale: String,
    #[serde(default)]
    pub subject: Option<String>,
    pub body_text: String,
    #[serde(default)]
    pub body_html: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct WebhookDoc {
    pub name: String,
    pub url: String,
    pub events: Vec<String>,
    pub enabled: bool,
    pub headers: Value,
    pub max_attempts: i32,
}

impl Default for WebhookDoc {
    fn default() -> Self {
        Self {
            name: String::new(),
            url: String::new(),
            events: vec![],
            enabled: true,
            headers: serde_json::json!({}),
            max_attempts: 8,
        }
    }
}

/// An upstream identity provider; the client secret is never part of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityProviderDoc {
    pub alias: String,
    pub kind: IdpKind,
    pub display_name: String,
    pub preset: Option<String>,
    pub enabled: bool,
    pub hidden: bool,
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub client_id: String,
    pub token_endpoint_auth_method: IdpAuthMethod,
    pub scopes: Vec<String>,
    pub pkce: bool,
    pub link_policy: LinkPolicy,
    pub trust_email: bool,
    pub mappers: IdpMappers,
    pub sort_order: i32,
}

impl Default for IdentityProviderDoc {
    fn default() -> Self {
        Self {
            alias: String::new(),
            kind: IdpKind::Oidc,
            display_name: String::new(),
            preset: None,
            enabled: true,
            hidden: false,
            issuer: None,
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
            client_id: String::new(),
            token_endpoint_auth_method: IdpAuthMethod::ClientSecretBasic,
            scopes: vec![],
            pkce: true,
            link_policy: LinkPolicy::VerifiedEmail,
            trust_email: false,
            mappers: IdpMappers::default(),
            sort_order: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct IpRuleDoc {
    pub cidr: String,
    pub action: IpRuleAction,
    pub client: Option<String>,
    pub description: Option<String>,
}

impl Default for IpRuleDoc {
    fn default() -> Self {
        Self {
            cidr: String::new(),
            action: IpRuleAction::Deny,
            client: None,
            description: None,
        }
    }
}

// --- export ----------------------------------------------------------------------

fn role_ref(name: &str, client: Option<&str>) -> String {
    match client {
        Some(c) => format!("{c}/{name}"),
        None => name.to_string(),
    }
}

/// Client metadata as a document: the stored columns minus identity,
/// secrets and status, with `null` optionals dropped so omitted and cleared
/// fields compare equal.
fn client_metadata(c: &crate::models::Client) -> AppResult<serde_json::Map<String, Value>> {
    let mut v = serde_json::to_value(c)?;
    let map = v.as_object_mut().expect("client serializes to an object");
    for k in [
        "id",
        "tenant_id",
        "client_id",
        "service_account_user_id",
        "status",
        "created_at",
        "updated_at",
    ] {
        map.remove(k);
    }
    map.retain(|_, v| !v.is_null());
    Ok(map.clone())
}

pub async fn export(state: &AppState, tenant: &Tenant) -> AppResult<TenantConfig> {
    let tid = tenant.id;

    // Lookups shared by several sections.
    let all_clients: BTreeMap<Uuid, String> = {
        let mut out = BTreeMap::new();
        let mut cursor = None;
        loop {
            let page = clients::list(state, tid, None, cursor.as_deref(), Some(500)).await?;
            for c in &page.items {
                out.insert(c.id, c.client_id.clone());
            }
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        out
    };
    let client_ref = |id: Option<Uuid>| id.and_then(|i| all_clients.get(&i).cloned());
    let rs_all = resource_servers::list(state, tid).await?;
    let rs_ident: BTreeMap<Uuid, String> = rs_all
        .iter()
        .map(|r| (r.id, r.identifier.clone()))
        .collect();
    let role_all = roles::list(state, tid, None).await?;
    let role_name: BTreeMap<Uuid, String> = role_all
        .iter()
        .map(|r| (r.id, role_ref(&r.name, client_ref(r.client_id).as_deref())))
        .collect();

    let mut resource_servers_out = vec![];
    for rs in rs_all.iter().filter(|r| !r.built_in) {
        let mut permissions: Vec<PermissionDoc> =
            resource_servers::list_permissions(state, tid, rs.id)
                .await?
                .into_iter()
                .map(|p| PermissionDoc {
                    name: p.name,
                    description: p.description,
                })
                .collect();
        permissions.sort_by(|a, b| a.name.cmp(&b.name));
        resource_servers_out.push(ResourceServerDoc {
            identifier: rs.identifier.clone(),
            name: rs.name.clone(),
            token_ttl_secs: rs.token_ttl_secs,
            signing_alg: rs.signing_alg.clone(),
            allow_offline_access: rs.allow_offline_access,
            permissions,
        });
    }
    resource_servers_out.sort_by(|a, b| a.identifier.cmp(&b.identifier));

    let mut scopes_out: Vec<ScopeDoc> = scopes::list(state, tid)
        .await?
        .iter()
        .map(|s| ScopeDoc {
            name: s.name.clone(),
            description: s.description.clone(),
            claims: s.claims.clone(),
            is_default: s.is_default,
            resource_server: s.resource_server_id.and_then(|i| rs_ident.get(&i).cloned()),
        })
        .collect();
    scopes_out.sort_by(|a, b| a.name.cmp(&b.name));

    let mut clients_out = vec![];
    let mut saml_out = vec![];
    for (id, public_id) in &all_clients {
        // The console's client is built in and follows `UI_URL`, not the document.
        if admin_console::is_builtin_client(public_id) {
            continue;
        }
        let c = clients::get(state, tid, *id).await?;
        if c.client_type == crate::models::ClientType::Saml {
            let sp = saml_sps::get(state, tid, c.id).await?;
            saml_out.push(SamlSpDoc {
                client_id: c.client_id.clone(),
                status: c.status,
                settings: saml_settings(&saml_sps::to_input(&sp.client, &sp.saml))?,
            });
            continue;
        }
        clients_out.push(ClientDoc {
            client_id: c.client_id.clone(),
            status: c.status,
            service_account: c.service_account_user_id.is_some(),
            metadata: client_metadata(&c)?,
        });
    }
    clients_out.sort_by(|a, b| a.client_id.cmp(&b.client_id));
    saml_out.sort_by(|a, b| a.client_id.cmp(&b.client_id));

    let mut roles_out = vec![];
    for r in role_all.iter().filter(|r| !r.built_in) {
        let mut composites: Vec<String> = roles::composites_of(state, tid, r.id)
            .await?
            .iter()
            .filter_map(|c| role_name.get(&c.id).cloned())
            .collect();
        composites.sort();
        let mut permissions: Vec<String> = resource_servers::permissions_of_role(state, tid, r.id)
            .await?
            .iter()
            .filter_map(|p| {
                rs_ident
                    .get(&p.resource_server_id)
                    .map(|rs| format!("{rs}#{}", p.name))
            })
            .collect();
        permissions.sort();
        roles_out.push(RoleDoc {
            name: r.name.clone(),
            client: client_ref(r.client_id),
            description: r.description.clone(),
            composites,
            permissions,
        });
    }
    roles_out.sort_by(|a, b| (&a.client, &a.name).cmp(&(&b.client, &b.name)));

    let group_all = groups::list(state, tid).await?;
    let by_id: BTreeMap<Uuid, &crate::models::Group> =
        group_all.iter().map(|g| (g.id, g)).collect();
    let path_of = |g: &crate::models::Group| -> Vec<String> {
        let mut path = vec![g.name.clone()];
        let mut cur = g.parent_id;
        let mut guard = 0;
        while let Some(p) = cur.and_then(|p| by_id.get(&p))
            && guard < 64
        {
            path.push(p.name.clone());
            cur = p.parent_id;
            guard += 1;
        }
        path.reverse();
        path
    };
    let mut groups_out = vec![];
    for g in &group_all {
        let mut role_refs: Vec<String> =
            roles::assignments_of(state, tid, Principal::Group { id: g.id })
                .await?
                .iter()
                .filter_map(|a| role_name.get(&a.role_id).cloned())
                .collect();
        role_refs.sort();
        groups_out.push(GroupDoc {
            path: path_of(g),
            description: g.description.clone(),
            attributes: g.attributes.clone(),
            roles: role_refs,
        });
    }
    groups_out.sort_by(|a, b| a.path.cmp(&b.path));

    let mut mappers_out: Vec<MapperDoc> = claim_mappers::list(state, tid, None)
        .await?
        .into_iter()
        .map(|m| MapperDoc {
            name: m.name,
            client: client_ref(m.client_id),
            config: m.config,
        })
        .collect();
    mappers_out.sort_by(|a, b| (&a.client, &a.name).cmp(&(&b.client, &b.name)));

    let mut templates_out: Vec<TemplateDoc> = messaging_admin::list_overrides(state, tid)
        .await?
        .into_iter()
        .map(|t| TemplateDoc {
            channel: t.channel,
            event: t.event,
            locale: t.locale,
            subject: t.subject,
            body_text: t.body_text,
            body_html: t.body_html,
        })
        .collect();
    templates_out.sort_by(|a, b| {
        (a.channel.as_str(), &a.event, &a.locale).cmp(&(b.channel.as_str(), &b.event, &b.locale))
    });

    let mut webhooks_out: Vec<WebhookDoc> = webhooks::list(state, tid)
        .await?
        .into_iter()
        .map(|w| WebhookDoc {
            name: w.name,
            url: w.url,
            events: w.events,
            enabled: w.enabled,
            headers: w.headers,
            max_attempts: w.max_attempts,
        })
        .collect();
    webhooks_out.sort_by(|a, b| a.name.cmp(&b.name));

    let mut ip_rules_out: Vec<IpRuleDoc> = ip_rules::list(state, tid, None)
        .await?
        .into_iter()
        .map(|r| IpRuleDoc {
            cidr: r.cidr,
            action: r.action,
            client: client_ref(r.client_id),
            description: r.description,
        })
        .collect();
    ip_rules_out.sort_by(|a, b| (&a.client, &a.cidr).cmp(&(&b.client, &b.cidr)));

    let mut idps_out: Vec<IdentityProviderDoc> = identity_providers::list(state, tid)
        .await?
        .into_iter()
        .map(|p| IdentityProviderDoc {
            alias: p.alias,
            kind: p.kind,
            display_name: p.display_name,
            preset: p.preset,
            enabled: p.enabled,
            hidden: p.hidden,
            issuer: p.issuer,
            authorization_endpoint: p.authorization_endpoint,
            token_endpoint: p.token_endpoint,
            userinfo_endpoint: p.userinfo_endpoint,
            jwks_uri: p.jwks_uri,
            client_id: p.client_id,
            token_endpoint_auth_method: p.token_endpoint_auth_method,
            scopes: p.scopes,
            pkce: p.pkce,
            link_policy: p.link_policy,
            trust_email: p.trust_email,
            mappers: p.mappers.0,
            sort_order: p.sort_order,
        })
        .collect();
    idps_out.sort_by(|a, b| a.alias.cmp(&b.alias));

    Ok(TenantConfig {
        format: FORMAT.to_string(),
        tenant: TenantSection {
            slug: tenant.slug.clone(),
            display_name: tenant.display_name.clone(),
            settings: tenant.settings.0.clone(),
        },
        profile_schema: (*profile_schema::get(state, tid).await?).clone(),
        resource_servers: resource_servers_out,
        scopes: scopes_out,
        clients: clients_out,
        roles: roles_out,
        groups: groups_out,
        claim_mappers: mappers_out,
        message_templates: templates_out,
        webhooks: webhooks_out,
        ip_rules: ip_rules_out,
        identity_providers: idps_out,
        saml_service_providers: saml_out,
    })
}

// --- plan ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Create,
    Update,
    Delete,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct FieldChange {
    pub field: String,
    pub from: Value,
    pub to: Value,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct Change {
    pub resource: &'static str,
    pub key: String,
    pub op: Op,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FieldChange>,
}

#[derive(Debug, Default, Serialize, utoipa::ToSchema)]
pub struct Summary {
    pub create: usize,
    pub update: usize,
    pub delete: usize,
    pub unchanged: usize,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Plan {
    pub prune: bool,
    pub changes: Vec<Change>,
    pub summary: Summary,
}

fn field_changes(current: &Value, desired: &Value) -> Vec<FieldChange> {
    let (Some(a), Some(b)) = (current.as_object(), desired.as_object()) else {
        return vec![FieldChange {
            field: String::new(),
            from: current.clone(),
            to: desired.clone(),
        }];
    };
    let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    keys.into_iter()
        .filter_map(|k| {
            let from = a.get(k).cloned().unwrap_or(Value::Null);
            let to = b.get(k).cloned().unwrap_or(Value::Null);
            (from != to).then(|| FieldChange {
                field: k.clone(),
                from,
                to,
            })
        })
        .collect()
}

/// Compare two keyed collections and record creates, updates and (with
/// `prune`) deletes. `key` must be unique within each side.
fn diff_collection<T: Serialize>(
    plan: &mut Plan,
    resource: &'static str,
    current: &[T],
    desired: &[T],
    key: impl Fn(&T) -> String,
    deletable: impl Fn(&T) -> bool,
) -> AppResult<()> {
    let cur: BTreeMap<String, &T> = current.iter().map(|x| (key(x), x)).collect();
    let mut seen = BTreeSet::new();
    for d in desired {
        let k = key(d);
        if !seen.insert(k.clone()) {
            return Err(AppError::BadRequest(format!(
                "{resource}: `{k}` appears more than once"
            )));
        }
        let to = serde_json::to_value(d)?;
        match cur.get(&k) {
            None => plan.changes.push(Change {
                resource,
                key: k,
                op: Op::Create,
                fields: vec![],
            }),
            Some(c) => {
                let from = serde_json::to_value(c)?;
                if from == to {
                    plan.summary.unchanged += 1;
                } else {
                    plan.changes.push(Change {
                        resource,
                        key: k,
                        op: Op::Update,
                        fields: field_changes(&from, &to),
                    });
                }
            }
        }
    }
    if plan.prune {
        for (k, c) in &cur {
            if !seen.contains(k) && deletable(c) {
                plan.changes.push(Change {
                    resource,
                    key: k.clone(),
                    op: Op::Delete,
                    fields: vec![],
                });
            }
        }
    }
    Ok(())
}

fn scalar_change<T: Serialize>(
    plan: &mut Plan,
    resource: &'static str,
    key: &str,
    current: &T,
    desired: &T,
) -> AppResult<()> {
    let from = serde_json::to_value(current)?;
    let to = serde_json::to_value(desired)?;
    if from == to {
        plan.summary.unchanged += 1;
    } else {
        plan.changes.push(Change {
            resource,
            key: key.to_string(),
            op: Op::Update,
            fields: field_changes(&from, &to),
        });
    }
    Ok(())
}

/// Bring the desired document into the same shape an export would produce,
/// so that omitted defaults and cosmetic differences do not read as changes.
fn normalize(tenant_id: Uuid, mut doc: TenantConfig) -> AppResult<TenantConfig> {
    if doc.format != FORMAT {
        return Err(AppError::BadRequest(format!(
            "unsupported format `{}` (expected {FORMAT})",
            doc.format
        )));
    }
    for c in &mut doc.clients {
        if admin_console::is_builtin_client(&c.client_id) {
            return Err(AppError::BadRequest(format!(
                "clients: `{}` is built in and is not part of the document",
                c.client_id
            )));
        }
        let mut input = Value::Object(c.metadata.clone());
        input["client_id"] = Value::String(c.client_id.clone());
        let new_client: NewClient = serde_json::from_value(input)
            .map_err(|e| AppError::BadRequest(format!("clients: `{}`: {e}", c.client_id)))?;
        let (resolved, _) = clients::resolve(tenant_id, new_client)?;
        c.metadata = client_metadata(&resolved)?;
    }
    for sp in &mut doc.saml_service_providers {
        let mut input = Value::Object(sp.settings.clone());
        input["client_id"] = Value::String(sp.client_id.clone());
        let input: SamlSpInput = serde_json::from_value(input).map_err(|e| {
            AppError::BadRequest(format!("saml_service_providers: `{}`: {e}", sp.client_id))
        })?;
        let (client, saml) =
            saml_sps::resolve(tenant_id, Uuid::nil(), None, input).map_err(|e| {
                AppError::BadRequest(format!("saml_service_providers: `{}`: {e}", sp.client_id))
            })?;
        sp.settings = saml_settings(&saml_sps::to_input(&client, &saml))?;
    }
    for r in &mut doc.ip_rules {
        r.cidr = ip_rules::normalize_cidr(&r.cidr)?;
    }
    for r in &mut doc.roles {
        r.composites.sort();
        r.composites.dedup();
        r.permissions.sort();
        r.permissions.dedup();
    }
    for g in &mut doc.groups {
        g.roles.sort();
        g.roles.dedup();
        if g.attributes.is_null() {
            g.attributes = serde_json::json!({});
        }
    }
    for rs in &mut doc.resource_servers {
        rs.permissions.sort_by(|a, b| a.name.cmp(&b.name));
    }
    for w in &mut doc.webhooks {
        if w.headers.is_null() {
            w.headers = serde_json::json!({});
        }
    }
    for p in &mut doc.identity_providers {
        p.alias = p.alias.trim().to_lowercase();
    }
    Ok(doc)
}

pub async fn plan(
    state: &AppState,
    tenant: &Tenant,
    desired: TenantConfig,
    prune: bool,
) -> AppResult<Plan> {
    let desired = normalize(tenant.id, desired)?;
    let current = export(state, tenant).await?;
    let mut plan = Plan {
        prune,
        changes: vec![],
        summary: Summary::default(),
    };
    scalar_change(
        &mut plan,
        "tenant",
        &tenant.slug,
        &(&current.tenant.display_name, &current.tenant.settings),
        &(&desired.tenant.display_name, &desired.tenant.settings),
    )?;
    scalar_change(
        &mut plan,
        "profile_schema",
        "profile_schema",
        &current.profile_schema,
        &desired.profile_schema,
    )?;
    diff_collection(
        &mut plan,
        "resource_server",
        &current.resource_servers,
        &desired.resource_servers,
        |r| r.identifier.clone(),
        |_| true,
    )?;
    diff_collection(
        &mut plan,
        "scope",
        &current.scopes,
        &desired.scopes,
        |s| s.name.clone(),
        |s| !STANDARD_SCOPES.contains(&s.name.as_str()),
    )?;
    diff_collection(
        &mut plan,
        "client",
        &current.clients,
        &desired.clients,
        |c| c.client_id.clone(),
        |c| !admin_console::is_builtin_client(&c.client_id),
    )?;
    diff_collection(
        &mut plan,
        "saml_service_provider",
        &current.saml_service_providers,
        &desired.saml_service_providers,
        |c| c.client_id.clone(),
        |_| true,
    )?;
    diff_collection(
        &mut plan,
        "role",
        &current.roles,
        &desired.roles,
        |r| role_ref(&r.name, r.client.as_deref()),
        |_| true,
    )?;
    diff_collection(
        &mut plan,
        "group",
        &current.groups,
        &desired.groups,
        |g| g.path.join("/"),
        |_| true,
    )?;
    diff_collection(
        &mut plan,
        "claim_mapper",
        &current.claim_mappers,
        &desired.claim_mappers,
        |m| role_ref(&m.name, m.client.as_deref()),
        |_| true,
    )?;
    diff_collection(
        &mut plan,
        "message_template",
        &current.message_templates,
        &desired.message_templates,
        |t| format!("{}/{}/{}", t.channel.as_str(), t.event, t.locale),
        |_| true,
    )?;
    diff_collection(
        &mut plan,
        "webhook",
        &current.webhooks,
        &desired.webhooks,
        |w| w.name.clone(),
        |_| true,
    )?;
    diff_collection(
        &mut plan,
        "ip_rule",
        &current.ip_rules,
        &desired.ip_rules,
        |r| role_ref(&r.cidr, r.client.as_deref()),
        |_| true,
    )?;
    diff_collection(
        &mut plan,
        "identity_provider",
        &current.identity_providers,
        &desired.identity_providers,
        |p| p.alias.clone(),
        |_| true,
    )?;
    for c in &plan.changes {
        match c.op {
            Op::Create => plan.summary.create += 1,
            Op::Update => plan.summary.update += 1,
            Op::Delete => plan.summary.delete += 1,
        }
    }
    Ok(plan)
}

// --- apply ----------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, utoipa::ToSchema)]
pub struct Secrets {
    /// Secrets of clients this import created (public `client_id` → secret).
    pub clients: BTreeMap<String, String>,
    /// Signing secrets of webhooks this import created (name → secret).
    pub webhooks: BTreeMap<String, String>,
    /// Identity providers this import created: their client secrets are
    /// never exported and must be set by hand.
    #[serde(default)]
    pub identity_providers: Vec<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApplyError {
    pub resource: &'static str,
    pub key: String,
    pub error: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApplyReport {
    pub dry_run: bool,
    #[serde(flatten)]
    pub plan: Plan,
    pub applied: usize,
    pub errors: Vec<ApplyError>,
    #[serde(skip_serializing_if = "secrets_empty")]
    pub secrets: Secrets,
}

fn secrets_empty(s: &Secrets) -> bool {
    s.clients.is_empty() && s.webhooks.is_empty() && s.identity_providers.is_empty()
}

/// The importer's no-escalation rule
/// ([`crate::middleware::AdminCtx::require_can_grant`]).
pub type CanGrant<'a> = &'a (dyn Fn(&[String]) -> AppResult<()> + Sync);

struct Ctx<'a> {
    state: &'a AppState,
    tenant: &'a Tenant,
    actor: Actor,
    can_grant: CanGrant<'a>,
    report: ApplyReport,
}

impl Ctx<'_> {
    fn note(&mut self, resource: &'static str, key: &str, r: AppResult<()>) {
        match r {
            Ok(()) => self.report.applied += 1,
            Err(e) => self.report.errors.push(ApplyError {
                resource,
                key: key.to_string(),
                error: e.to_string(),
            }),
        }
    }

    fn wants(&self, resource: &str, key: &str, op: Op) -> bool {
        self.report
            .plan
            .changes
            .iter()
            .any(|c| c.resource == resource && c.key == key && c.op == op)
    }

    fn deletes(&self, resource: &str) -> Vec<String> {
        self.report
            .plan
            .changes
            .iter()
            .filter(|c| c.resource == resource && c.op == Op::Delete)
            .map(|c| c.key.clone())
            .collect()
    }

    async fn client_id_of(&self, public: &str) -> AppResult<Uuid> {
        clients::find_by_client_id(self.state, self.tenant.id, public)
            .await?
            .map(|c| c.id)
            .ok_or_else(|| AppError::BadRequest(format!("unknown client `{public}`")))
    }

    async fn client_opt(&self, public: Option<&str>) -> AppResult<Option<Uuid>> {
        match public {
            Some(p) => Ok(Some(self.client_id_of(p).await?)),
            None => Ok(None),
        }
    }

    async fn role_id_of(&self, reference: &str) -> AppResult<Uuid> {
        let (client, name) = match reference.split_once('/') {
            Some((c, n)) => (Some(c), n),
            None => (None, reference),
        };
        let client_id = self.client_opt(client).await?;
        let mut tx = crate::db::tenant_tx(&self.state.db, self.tenant.id).await?;
        let r =
            crate::repos::roles::find_by_name(&mut *tx, self.tenant.id, client_id, name).await?;
        tx.commit().await?;
        r.map(|r| r.id)
            .ok_or_else(|| AppError::BadRequest(format!("unknown role `{reference}`")))
    }

    /// Refuse, before anything changes, to hand out admin permissions the
    /// importer does not hold: the same check the admin routes make for a
    /// composite, a group's role or a built-in permission grant.
    async fn check_grants(&self, grants: &[Grant], permissions: &[Uuid]) -> AppResult<()> {
        let mut names = vec![];
        for g in grants {
            names.extend(admin_access::permissions_of_grant(self.state, self.tenant.id, *g).await?);
        }
        for id in permissions {
            let p = resource_servers::get_permission(self.state, self.tenant.id, *id).await?;
            let rs =
                resource_servers::get(self.state, self.tenant.id, p.resource_server_id).await?;
            if rs.built_in {
                names.push(p.name);
            }
        }
        (self.can_grant)(&names)
    }

    /// Admin permissions a role reference carries once the document is
    /// imported: a role the document defines by its own permissions and
    /// composites (followed through the document), any other by what it
    /// holds now.
    async fn admin_permissions_of_role(
        &self,
        doc: &TenantConfig,
        built_in: &BTreeSet<String>,
        reference: &str,
    ) -> AppResult<BTreeSet<String>> {
        let mut out = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut todo = vec![reference.to_string()];
        while let Some(r) = todo.pop() {
            if !seen.insert(r.clone()) {
                continue;
            }
            match doc
                .roles
                .iter()
                .find(|d| role_ref(&d.name, d.client.as_deref()) == r)
            {
                Some(def) => {
                    out.extend(
                        def.permissions
                            .iter()
                            .filter_map(|p| built_in_permission(built_in, p)),
                    );
                    todo.extend(def.composites.iter().cloned());
                }
                None => {
                    if let Ok(id) = self.role_id_of(&r).await {
                        out.extend(
                            admin_access::permissions_of_grant(
                                self.state,
                                self.tenant.id,
                                Grant::Role(id),
                            )
                            .await?,
                        );
                    }
                }
            }
        }
        Ok(out)
    }

    async fn permission_id_of(&self, reference: &str) -> AppResult<Uuid> {
        let (rs, name) = reference.split_once('#').ok_or_else(|| {
            AppError::BadRequest(format!(
                "permission `{reference}` must be `resource-server#permission`"
            ))
        })?;
        let servers = resource_servers::list(self.state, self.tenant.id).await?;
        let server = servers
            .iter()
            .find(|s| s.identifier == rs)
            .ok_or_else(|| AppError::BadRequest(format!("unknown resource server `{rs}`")))?;
        resource_servers::list_permissions(self.state, self.tenant.id, server.id)
            .await?
            .into_iter()
            .find(|p| p.name == name)
            .map(|p| p.id)
            .ok_or_else(|| AppError::BadRequest(format!("unknown permission `{reference}`")))
    }
}

/// The plan, plus what [`apply`] would refuse under the importer's
/// no-escalation rule, found without changing anything: every role or group
/// the plan creates or updates whose new composites, permissions or roles
/// would hand out admin permissions `can_grant` refuses is listed in
/// `errors`, as `apply` would list it. A role the same document defines
/// counts with the permissions it will have once imported.
pub async fn dry_run(
    state: &AppState,
    tenant: &Tenant,
    actor: Actor,
    desired: TenantConfig,
    prune: bool,
    can_grant: CanGrant<'_>,
) -> AppResult<ApplyReport> {
    let desired = normalize(tenant.id, desired)?;
    let plan = plan(state, tenant, desired.clone(), prune).await?;
    let mut ctx = Ctx {
        state,
        tenant,
        actor,
        can_grant,
        report: ApplyReport {
            dry_run: true,
            plan,
            applied: 0,
            errors: vec![],
            secrets: Secrets::default(),
        },
    };
    let built_in: BTreeSet<String> = resource_servers::list(state, tenant.id)
        .await?
        .into_iter()
        .filter(|rs| rs.built_in)
        .map(|rs| rs.identifier)
        .collect();
    let mut refused = vec![];
    for role in &desired.roles {
        let key = role_ref(&role.name, role.client.as_deref());
        if !ctx.wants("role", &key, Op::Create) && !ctx.wants("role", &key, Op::Update) {
            continue;
        }
        let existing = ctx.role_id_of(&key).await.ok();
        let (current_comp, current_perm): (BTreeSet<Uuid>, BTreeSet<Uuid>) = match existing {
            Some(id) => (
                roles::composites_of(state, tenant.id, id)
                    .await?
                    .into_iter()
                    .map(|r| r.id)
                    .collect(),
                resource_servers::permissions_of_role(state, tenant.id, id)
                    .await?
                    .into_iter()
                    .map(|p| p.id)
                    .collect(),
            ),
            None => Default::default(),
        };
        let mut names = BTreeSet::new();
        for c in &role.composites {
            let held = match ctx.role_id_of(c).await {
                Ok(id) => current_comp.contains(&id),
                Err(_) => false,
            };
            if !held {
                names.extend(
                    ctx.admin_permissions_of_role(&desired, &built_in, c)
                        .await?,
                );
            }
        }
        for p in &role.permissions {
            let held = match ctx.permission_id_of(p).await {
                Ok(id) => current_perm.contains(&id),
                Err(_) => false,
            };
            if !held && let Some(name) = built_in_permission(&built_in, p) {
                names.insert(name);
            }
        }
        if let Err(e) = (ctx.can_grant)(&names.into_iter().collect::<Vec<_>>()) {
            refused.push(("role", key, e));
        }
    }
    let all_groups = groups::list(state, tenant.id).await?;
    for g in &desired.groups {
        let key = g.path.join("/");
        if !ctx.wants("group", &key, Op::Create) && !ctx.wants("group", &key, Op::Update) {
            continue;
        }
        let mut parent: Option<Uuid> = None;
        let mut existing = None;
        for name in &g.path {
            existing = all_groups
                .iter()
                .find(|x| x.parent_id == parent && &x.name == name)
                .map(|x| x.id);
            parent = existing;
            if parent.is_none() {
                break;
            }
        }
        let current: BTreeSet<Uuid> = match existing {
            Some(id) => roles::assignments_of(state, tenant.id, Principal::Group { id })
                .await?
                .into_iter()
                .map(|a| a.role_id)
                .collect(),
            None => BTreeSet::new(),
        };
        let mut names = BTreeSet::new();
        for r in &g.roles {
            let held = match ctx.role_id_of(r).await {
                Ok(id) => current.contains(&id),
                Err(_) => false,
            };
            if !held {
                names.extend(
                    ctx.admin_permissions_of_role(&desired, &built_in, r)
                        .await?,
                );
            }
        }
        if let Err(e) = (ctx.can_grant)(&names.into_iter().collect::<Vec<_>>()) {
            refused.push(("group", key, e));
        }
    }
    for (resource, key, e) in refused {
        ctx.report.errors.push(ApplyError {
            resource,
            key,
            error: e.to_string(),
        });
    }
    Ok(ctx.report)
}

/// The permission name of a `resource-server#permission` reference when the
/// resource server is built in (an admin permission), else `None`.
fn built_in_permission(built_in: &BTreeSet<String>, reference: &str) -> Option<String> {
    let (rs, name) = reference.split_once('#')?;
    built_in.contains(rs).then(|| name.to_string())
}

/// Apply the plan. Changes are applied in dependency order and deletions
/// (with `prune`) in reverse; each change is independent, so one failure
/// does not stop the rest. Running the same document twice is a no-op. A role
/// or group whose new composites, permissions or roles would grant admin
/// permissions the importer lacks (`can_grant` refuses them) is reported as an
/// error and left unchanged.
pub async fn apply(
    state: &AppState,
    tenant: &Tenant,
    actor: Actor,
    desired: TenantConfig,
    prune: bool,
    can_grant: CanGrant<'_>,
) -> AppResult<ApplyReport> {
    let desired = normalize(tenant.id, desired)?;
    let plan = plan(state, tenant, desired.clone(), prune).await?;
    let tid = tenant.id;
    let mut ctx = Ctx {
        state,
        tenant,
        actor,
        can_grant,
        report: ApplyReport {
            dry_run: false,
            plan,
            applied: 0,
            errors: vec![],
            secrets: Secrets::default(),
        },
    };

    // Tenant and schema.
    if ctx.wants("tenant", &tenant.slug, Op::Update) {
        let r = tenants::update(
            state,
            ctx.actor.clone(),
            tid,
            TenantUpdate {
                display_name: Some(desired.tenant.display_name.clone()),
                status: None,
                settings: Some(desired.tenant.settings.clone()),
            },
        )
        .await
        .map(|_| ());
        ctx.note("tenant", &tenant.slug, r);
    }
    if ctx.wants("profile_schema", "profile_schema", Op::Update) {
        let r = profile_schema::set(
            state,
            tid,
            ctx.actor.clone(),
            desired.profile_schema.clone(),
        )
        .await
        .map(|_| ());
        ctx.note("profile_schema", "profile_schema", r);
    }

    // Resource servers and their permissions.
    for rs in &desired.resource_servers {
        let key = rs.identifier.clone();
        if ctx.wants("resource_server", &key, Op::Create) {
            let r = resource_servers::create(
                state,
                tid,
                ctx.actor.clone(),
                NewResourceServer {
                    identifier: rs.identifier.clone(),
                    name: rs.name.clone(),
                    token_ttl_secs: rs.token_ttl_secs,
                    signing_alg: rs.signing_alg.clone(),
                    allow_offline_access: Some(rs.allow_offline_access),
                },
            )
            .await
            .map(|_| ());
            ctx.note("resource_server", &key, r);
        } else if !ctx.wants("resource_server", &key, Op::Update) {
            continue;
        }
        let r = async {
            let current = resource_servers::list(state, tid)
                .await?
                .into_iter()
                .find(|s| s.identifier == rs.identifier)
                .ok_or(AppError::NotFound("resource server"))?;
            resource_servers::update(
                state,
                tid,
                ctx.actor.clone(),
                current.id,
                ResourceServerUpdate {
                    name: Some(rs.name.clone()),
                    token_ttl_secs: Some(rs.token_ttl_secs),
                    signing_alg: Some(rs.signing_alg.clone()),
                    allow_offline_access: Some(rs.allow_offline_access),
                },
            )
            .await?;
            let existing = resource_servers::list_permissions(state, tid, current.id).await?;
            for p in &rs.permissions {
                if !existing.iter().any(|e| e.name == p.name) {
                    resource_servers::create_permission(
                        state,
                        tid,
                        ctx.actor.clone(),
                        current.id,
                        NewPermission {
                            name: p.name.clone(),
                            description: p.description.clone(),
                        },
                    )
                    .await?;
                }
            }
            for e in existing {
                if !rs.permissions.iter().any(|p| p.name == e.name) {
                    resource_servers::delete_permission(
                        state,
                        tid,
                        ctx.actor.clone(),
                        current.id,
                        e.id,
                    )
                    .await?;
                }
            }
            Ok(())
        }
        .await;
        if ctx.wants("resource_server", &key, Op::Update) {
            ctx.note("resource_server", &key, r);
        } else if let Err(e) = r {
            ctx.report.errors.push(ApplyError {
                resource: "resource_server",
                key,
                error: e.to_string(),
            });
        }
    }

    // Scopes.
    for s in &desired.scopes {
        let key = s.name.clone();
        let create = ctx.wants("scope", &key, Op::Create);
        let update = ctx.wants("scope", &key, Op::Update);
        if !create && !update {
            continue;
        }
        let r = async {
            let rs_id = match &s.resource_server {
                Some(ident) => Some(
                    resource_servers::list(state, tid)
                        .await?
                        .into_iter()
                        .find(|r| &r.identifier == ident)
                        .map(|r| r.id)
                        .ok_or_else(|| {
                            AppError::BadRequest(format!("unknown resource server `{ident}`"))
                        })?,
                ),
                None => None,
            };
            if create {
                scopes::create(
                    state,
                    tid,
                    ctx.actor.clone(),
                    NewScope {
                        name: s.name.clone(),
                        description: s.description.clone(),
                        claims: s.claims.clone(),
                        resource_server_id: rs_id,
                        is_default: s.is_default,
                    },
                )
                .await?;
            } else {
                let current = scopes::list(state, tid)
                    .await?
                    .iter()
                    .find(|x| x.name == s.name)
                    .cloned()
                    .ok_or(AppError::NotFound("scope"))?;
                scopes::update(
                    state,
                    tid,
                    ctx.actor.clone(),
                    current.id,
                    ScopeUpdate {
                        description: Some(s.description.clone()),
                        claims: Some(s.claims.clone()),
                        is_default: Some(s.is_default),
                        resource_server_id: Some(rs_id),
                    },
                )
                .await?;
            }
            Ok(())
        }
        .await;
        ctx.note("scope", &key, r);
    }

    // Clients.
    for c in &desired.clients {
        let key = c.client_id.clone();
        let create = ctx.wants("client", &key, Op::Create);
        let update = ctx.wants("client", &key, Op::Update);
        if !create && !update {
            continue;
        }
        let mut input = Value::Object(c.metadata.clone());
        input["client_id"] = Value::String(c.client_id.clone());
        let r = async {
            let new_client: NewClient =
                serde_json::from_value(input).map_err(|e| AppError::BadRequest(e.to_string()))?;
            let id = if create {
                let created = clients::create(state, tid, ctx.actor.clone(), new_client).await?;
                if let Some(secret) = created.client_secret {
                    ctx.report
                        .secrets
                        .clients
                        .insert(c.client_id.clone(), secret.to_string());
                }
                created.client.id
            } else {
                let id = ctx.client_id_of(&c.client_id).await?;
                let (_, secret) =
                    clients::update_metadata(state, tid, ctx.actor.clone(), id, new_client).await?;
                if let Some(secret) = secret {
                    ctx.report
                        .secrets
                        .clients
                        .insert(c.client_id.clone(), secret.to_string());
                }
                id
            };
            let current = clients::get(state, tid, id).await?;
            if current.status != c.status {
                clients::set_status(state, tid, ctx.actor.clone(), id, c.status).await?;
            }
            match (c.service_account, current.service_account_user_id.is_some()) {
                (true, false) => {
                    clients::enable_service_account(state, tid, ctx.actor.clone(), id).await?;
                }
                (false, true) => {
                    clients::disable_service_account(state, tid, ctx.actor.clone(), id).await?;
                }
                _ => {}
            }
            Ok(())
        }
        .await;
        ctx.note("client", &key, r);
    }

    // SAML service providers (after clients: client ids are one namespace).
    for sp in &desired.saml_service_providers {
        let key = sp.client_id.clone();
        let create = ctx.wants("saml_service_provider", &key, Op::Create);
        let update = ctx.wants("saml_service_provider", &key, Op::Update);
        if !create && !update {
            continue;
        }
        let mut input = Value::Object(sp.settings.clone());
        input["client_id"] = Value::String(key.clone());
        let r = async {
            let input: SamlSpInput =
                serde_json::from_value(input).map_err(|e| AppError::BadRequest(e.to_string()))?;
            let view = if create {
                saml_sps::create(state, tid, ctx.actor.clone(), input).await?
            } else {
                let id = ctx.client_id_of(&key).await?;
                saml_sps::replace(state, tid, ctx.actor.clone(), id, input).await?
            };
            if view.client.status != sp.status {
                clients::set_status(state, tid, ctx.actor.clone(), view.client.id, sp.status)
                    .await?;
            }
            Ok(())
        }
        .await;
        ctx.note("saml_service_provider", &key, r);
    }

    // Roles: rows first (composites may reference each other), then links.
    for role in &desired.roles {
        let key = role_ref(&role.name, role.client.as_deref());
        if !ctx.wants("role", &key, Op::Create) {
            continue;
        }
        let r = async {
            let client_id = ctx.client_opt(role.client.as_deref()).await?;
            roles::create(
                state,
                tid,
                ctx.actor.clone(),
                NewRole {
                    name: role.name.clone(),
                    client_id,
                    description: role.description.clone(),
                },
            )
            .await
            .map(|_| ())
        }
        .await;
        if let Err(e) = r {
            ctx.report.errors.push(ApplyError {
                resource: "role",
                key: key.clone(),
                error: e.to_string(),
            });
        }
    }
    for role in &desired.roles {
        let key = role_ref(&role.name, role.client.as_deref());
        let create = ctx.wants("role", &key, Op::Create);
        let update = ctx.wants("role", &key, Op::Update);
        if !create && !update {
            continue;
        }
        let r = async {
            let id = ctx.role_id_of(&key).await?;
            if update {
                roles::update(
                    state,
                    tid,
                    ctx.actor.clone(),
                    id,
                    RoleUpdate {
                        name: None,
                        description: Some(role.description.clone()),
                    },
                )
                .await?;
            }
            let current_comp: BTreeSet<Uuid> = roles::composites_of(state, tid, id)
                .await?
                .into_iter()
                .map(|r| r.id)
                .collect();
            let mut desired_comp = BTreeSet::new();
            for c in &role.composites {
                desired_comp.insert(ctx.role_id_of(c).await?);
            }
            let current_perm: BTreeSet<Uuid> =
                resource_servers::permissions_of_role(state, tid, id)
                    .await?
                    .into_iter()
                    .map(|p| p.id)
                    .collect();
            let mut desired_perm = BTreeSet::new();
            for p in &role.permissions {
                desired_perm.insert(ctx.permission_id_of(p).await?);
            }
            let new_comp: Vec<Grant> = desired_comp
                .difference(&current_comp)
                .map(|id| Grant::Role(*id))
                .collect();
            let new_perm: Vec<Uuid> = desired_perm.difference(&current_perm).copied().collect();
            ctx.check_grants(&new_comp, &new_perm).await?;
            for add in desired_comp.difference(&current_comp) {
                roles::add_composite(state, tid, ctx.actor.clone(), id, *add).await?;
            }
            for rm in current_comp.difference(&desired_comp) {
                roles::remove_composite(state, tid, ctx.actor.clone(), id, *rm).await?;
            }
            for add in desired_perm.difference(&current_perm) {
                resource_servers::grant(state, tid, ctx.actor.clone(), id, *add).await?;
            }
            for rm in current_perm.difference(&desired_perm) {
                resource_servers::revoke(state, tid, ctx.actor.clone(), id, *rm).await?;
            }
            Ok(())
        }
        .await;
        ctx.note("role", &key, r);
    }

    // Groups: parents before children.
    let mut group_docs: Vec<&GroupDoc> = desired.groups.iter().collect();
    group_docs.sort_by_key(|g| g.path.len());
    for g in group_docs {
        let key = g.path.join("/");
        let create = ctx.wants("group", &key, Op::Create);
        let update = ctx.wants("group", &key, Op::Update);
        if !create && !update {
            continue;
        }
        let r = async {
            let all = groups::list(state, tid).await?;
            let find = |path: &[String]| -> Option<Uuid> {
                let mut parent: Option<Uuid> = None;
                for name in path {
                    let g = all
                        .iter()
                        .find(|x| x.parent_id == parent && &x.name == name)?;
                    parent = Some(g.id);
                }
                parent
            };
            let (own, parents) = g
                .path
                .split_last()
                .ok_or_else(|| AppError::BadRequest("group path must not be empty".into()))?;
            let parent_id = if parents.is_empty() {
                None
            } else {
                Some(find(parents).ok_or_else(|| {
                    AppError::BadRequest(format!("parent group `{}` missing", parents.join("/")))
                })?)
            };
            let id = match find(&g.path) {
                Some(id) => {
                    groups::update(
                        state,
                        tid,
                        ctx.actor.clone(),
                        id,
                        GroupUpdate {
                            name: None,
                            parent_id: None,
                            description: Some(g.description.clone()),
                            attributes: Some(g.attributes.clone()),
                        },
                    )
                    .await?;
                    id
                }
                None => {
                    groups::create(
                        state,
                        tid,
                        ctx.actor.clone(),
                        NewGroup {
                            name: own.clone(),
                            parent_id,
                            description: g.description.clone(),
                            attributes: Some(g.attributes.clone()),
                        },
                    )
                    .await?
                    .id
                }
            };
            let current: BTreeSet<Uuid> =
                roles::assignments_of(state, tid, Principal::Group { id })
                    .await?
                    .into_iter()
                    .map(|a| a.role_id)
                    .collect();
            let mut wanted = BTreeSet::new();
            for r in &g.roles {
                wanted.insert(ctx.role_id_of(r).await?);
            }
            let new_roles: Vec<Grant> = wanted
                .difference(&current)
                .map(|id| Grant::Role(*id))
                .collect();
            ctx.check_grants(&new_roles, &[]).await?;
            for add in wanted.difference(&current) {
                roles::assign(state, tid, ctx.actor.clone(), *add, Principal::Group { id }).await?;
            }
            for rm in current.difference(&wanted) {
                roles::unassign(state, tid, ctx.actor.clone(), *rm, Principal::Group { id })
                    .await?;
            }
            Ok(())
        }
        .await;
        ctx.note("group", &key, r);
    }

    // Claim mappers.
    for m in &desired.claim_mappers {
        let key = role_ref(&m.name, m.client.as_deref());
        let create = ctx.wants("claim_mapper", &key, Op::Create);
        let update = ctx.wants("claim_mapper", &key, Op::Update);
        if !create && !update {
            continue;
        }
        let r = async {
            let client_id = ctx.client_opt(m.client.as_deref()).await?;
            let existing = claim_mappers::list(state, tid, Some(client_id))
                .await?
                .into_iter()
                .find(|x| x.name == m.name);
            match existing {
                Some(x) => {
                    claim_mappers::update(
                        state,
                        tid,
                        ctx.actor.clone(),
                        x.id,
                        crate::models::ClaimMapperUpdate {
                            name: None,
                            config: Some(m.config.clone()),
                        },
                    )
                    .await?;
                }
                None => {
                    claim_mappers::create(
                        state,
                        tid,
                        ctx.actor.clone(),
                        NewClaimMapper {
                            name: m.name.clone(),
                            client_id,
                            config: m.config.clone(),
                        },
                    )
                    .await?;
                }
            }
            Ok(())
        }
        .await;
        ctx.note("claim_mapper", &key, r);
    }

    // Message templates.
    for t in &desired.message_templates {
        let key = format!("{}/{}/{}", t.channel.as_str(), t.event, t.locale);
        if !ctx.wants("message_template", &key, Op::Create)
            && !ctx.wants("message_template", &key, Op::Update)
        {
            continue;
        }
        let r = messaging_admin::put_template(
            state,
            tid,
            t.channel,
            &t.event,
            &t.locale,
            TemplateBody {
                subject: t.subject.clone(),
                body_text: t.body_text.clone(),
                body_html: t.body_html.clone(),
            },
        )
        .await
        .map(|_| ());
        ctx.note("message_template", &key, r);
    }

    // Webhooks.
    for w in &desired.webhooks {
        let key = w.name.clone();
        let create = ctx.wants("webhook", &key, Op::Create);
        let update = ctx.wants("webhook", &key, Op::Update);
        if !create && !update {
            continue;
        }
        let r = async {
            let existing = webhooks::list(state, tid)
                .await?
                .into_iter()
                .find(|x| x.name == w.name);
            match existing {
                Some(x) => {
                    webhooks::update(
                        state,
                        tid,
                        ctx.actor.clone(),
                        x.id,
                        WebhookUpdate {
                            name: None,
                            url: Some(w.url.clone()),
                            events: Some(w.events.clone()),
                            enabled: Some(w.enabled),
                            headers: Some(w.headers.clone()),
                            max_attempts: Some(w.max_attempts),
                        },
                    )
                    .await?;
                }
                None => {
                    let created = webhooks::create(
                        state,
                        tid,
                        ctx.actor.clone(),
                        NewWebhook {
                            name: w.name.clone(),
                            url: w.url.clone(),
                            events: w.events.clone(),
                            enabled: Some(w.enabled),
                            headers: Some(w.headers.clone()),
                            max_attempts: Some(w.max_attempts),
                        },
                    )
                    .await?;
                    ctx.report
                        .secrets
                        .webhooks
                        .insert(w.name.clone(), created.secret);
                }
            }
            Ok(())
        }
        .await;
        ctx.note("webhook", &key, r);
    }

    // IP rules.
    for rule in &desired.ip_rules {
        let key = role_ref(&rule.cidr, rule.client.as_deref());
        let create = ctx.wants("ip_rule", &key, Op::Create);
        let update = ctx.wants("ip_rule", &key, Op::Update);
        if !create && !update {
            continue;
        }
        let r = async {
            let client_id = ctx.client_opt(rule.client.as_deref()).await?;
            let existing = ip_rules::list(state, tid, Some(client_id))
                .await?
                .into_iter()
                .find(|x| x.cidr == rule.cidr);
            match existing {
                Some(x) => {
                    ip_rules::update(
                        state,
                        tid,
                        ctx.actor.clone(),
                        x.id,
                        IpRuleUpdate {
                            action: Some(rule.action),
                            cidr: None,
                            description: Some(rule.description.clone()),
                        },
                    )
                    .await?;
                }
                None => {
                    ip_rules::create(
                        state,
                        tid,
                        ctx.actor.clone(),
                        NewIpRule {
                            client_id,
                            action: Some(rule.action),
                            cidr: rule.cidr.clone(),
                            description: rule.description.clone(),
                        },
                    )
                    .await?;
                }
            }
            Ok(())
        }
        .await;
        ctx.note("ip_rule", &key, r);
    }

    // Identity providers (secrets are kept, or missing on a fresh row).
    for p in &desired.identity_providers {
        let key = p.alias.clone();
        let create = ctx.wants("identity_provider", &key, Op::Create);
        let update = ctx.wants("identity_provider", &key, Op::Update);
        if !create && !update {
            continue;
        }
        let r = async {
            let existing = identity_providers::get(state, tid, &p.alias).await;
            match existing {
                Ok(_) => {
                    identity_providers::update(
                        state,
                        tid,
                        ctx.actor.clone(),
                        &p.alias,
                        IdentityProviderUpdate {
                            alias: None,
                            kind: Some(p.kind),
                            display_name: Some(p.display_name.clone()),
                            enabled: Some(p.enabled),
                            hidden: Some(p.hidden),
                            issuer: Some(p.issuer.clone()),
                            authorization_endpoint: Some(p.authorization_endpoint.clone()),
                            token_endpoint: Some(p.token_endpoint.clone()),
                            userinfo_endpoint: Some(p.userinfo_endpoint.clone()),
                            jwks_uri: Some(p.jwks_uri.clone()),
                            client_id: Some(p.client_id.clone()),
                            client_secret: None,
                            token_endpoint_auth_method: Some(p.token_endpoint_auth_method),
                            scopes: Some(p.scopes.clone()),
                            pkce: Some(p.pkce),
                            link_policy: Some(p.link_policy),
                            trust_email: Some(p.trust_email),
                            mappers: Some(p.mappers.clone()),
                            sort_order: Some(p.sort_order),
                        },
                    )
                    .await?;
                }
                Err(AppError::NotFound(_)) => {
                    identity_providers::create(
                        state,
                        tid,
                        ctx.actor.clone(),
                        NewIdentityProvider {
                            alias: p.alias.clone(),
                            kind: Some(p.kind),
                            display_name: Some(p.display_name.clone()),
                            preset: p.preset.clone(),
                            enabled: Some(p.enabled),
                            hidden: Some(p.hidden),
                            issuer: p.issuer.clone(),
                            authorization_endpoint: p.authorization_endpoint.clone(),
                            token_endpoint: p.token_endpoint.clone(),
                            userinfo_endpoint: p.userinfo_endpoint.clone(),
                            jwks_uri: p.jwks_uri.clone(),
                            client_id: p.client_id.clone(),
                            client_secret: None,
                            token_endpoint_auth_method: Some(p.token_endpoint_auth_method),
                            scopes: Some(p.scopes.clone()),
                            pkce: Some(p.pkce),
                            link_policy: Some(p.link_policy),
                            trust_email: Some(p.trust_email),
                            mappers: Some(p.mappers.clone()),
                            sort_order: Some(p.sort_order),
                        },
                    )
                    .await?;
                    ctx.report.secrets.identity_providers.push(p.alias.clone());
                }
                Err(e) => return Err(e),
            }
            Ok(())
        }
        .await;
        ctx.note("identity_provider", &key, r);
    }

    // Deletions, in reverse dependency order.
    if prune {
        for key in ctx.deletes("identity_provider") {
            let r = identity_providers::delete(state, tid, ctx.actor.clone(), &key).await;
            ctx.note("identity_provider", &key, r);
        }
        for key in ctx.deletes("ip_rule") {
            let r = async {
                let (client, cidr) = match key.split_once('/') {
                    // `client/cidr` vs a bare cidr (which itself contains `/`):
                    // client ids never contain `/`, cidrs always do, so split on
                    // the first `/` only when what precedes it is not an address.
                    Some((c, rest)) if c.parse::<std::net::IpAddr>().is_err() => (Some(c), rest),
                    _ => (None, key.as_str()),
                };
                let client_id = ctx.client_opt(client).await?;
                let rule = ip_rules::list(state, tid, Some(client_id))
                    .await?
                    .into_iter()
                    .find(|x| x.cidr == cidr)
                    .ok_or(AppError::NotFound("ip rule"))?;
                ip_rules::delete(state, tid, ctx.actor.clone(), rule.id).await
            }
            .await;
            ctx.note("ip_rule", &key, r);
        }
        for key in ctx.deletes("webhook") {
            let r = async {
                let w = webhooks::list(state, tid)
                    .await?
                    .into_iter()
                    .find(|x| x.name == key)
                    .ok_or(AppError::NotFound("webhook"))?;
                webhooks::delete(state, tid, ctx.actor.clone(), w.id).await
            }
            .await;
            ctx.note("webhook", &key, r);
        }
        for key in ctx.deletes("message_template") {
            let r = async {
                let mut parts = key.splitn(3, '/');
                let (channel, event, locale) = (
                    parts.next().unwrap_or_default(),
                    parts.next().unwrap_or_default(),
                    parts.next().unwrap_or_default(),
                );
                let channel = match channel {
                    "email" => MessageChannel::Email,
                    _ => MessageChannel::Sms,
                };
                messaging_admin::delete_template(state, tid, channel, event, locale).await
            }
            .await;
            ctx.note("message_template", &key, r);
        }
        for key in ctx.deletes("claim_mapper") {
            let r = async {
                let (client, name) = match key.split_once('/') {
                    Some((c, n)) => (Some(c), n),
                    None => (None, key.as_str()),
                };
                let client_id = ctx.client_opt(client).await?;
                let m = claim_mappers::list(state, tid, Some(client_id))
                    .await?
                    .into_iter()
                    .find(|x| x.name == name)
                    .ok_or(AppError::NotFound("claim mapper"))?;
                claim_mappers::delete(state, tid, ctx.actor.clone(), m.id).await
            }
            .await;
            ctx.note("claim_mapper", &key, r);
        }
        let mut group_keys = ctx.deletes("group");
        group_keys.sort_by_key(|k| std::cmp::Reverse(k.matches('/').count()));
        for key in group_keys {
            let r = async {
                let all = groups::list(state, tid).await?;
                let mut parent: Option<Uuid> = None;
                let mut found = None;
                for name in key.split('/') {
                    let g = all
                        .iter()
                        .find(|x| x.parent_id == parent && x.name == name)
                        .ok_or(AppError::NotFound("group"))?;
                    parent = Some(g.id);
                    found = Some(g.id);
                }
                groups::delete(
                    state,
                    tid,
                    ctx.actor.clone(),
                    found.ok_or(AppError::NotFound("group"))?,
                )
                .await
            }
            .await;
            ctx.note("group", &key, r);
        }
        for key in ctx.deletes("role") {
            let r = async {
                let id = ctx.role_id_of(&key).await?;
                roles::delete(state, tid, ctx.actor.clone(), id).await
            }
            .await;
            ctx.note("role", &key, r);
        }
        for key in ctx.deletes("client") {
            let r = async {
                let id = ctx.client_id_of(&key).await?;
                clients::delete(state, tid, ctx.actor.clone(), id).await
            }
            .await;
            ctx.note("client", &key, r);
        }
        for key in ctx.deletes("saml_service_provider") {
            let r = async {
                let id = ctx.client_id_of(&key).await?;
                clients::delete(state, tid, ctx.actor.clone(), id).await
            }
            .await;
            ctx.note("saml_service_provider", &key, r);
        }
        for key in ctx.deletes("scope") {
            let r = async {
                let s = scopes::list(state, tid)
                    .await?
                    .iter()
                    .find(|x| x.name == key)
                    .cloned()
                    .ok_or(AppError::NotFound("scope"))?;
                scopes::delete(state, tid, ctx.actor.clone(), s.id).await
            }
            .await;
            ctx.note("scope", &key, r);
        }
        for key in ctx.deletes("resource_server") {
            let r = async {
                let rs = resource_servers::list(state, tid)
                    .await?
                    .into_iter()
                    .find(|x| x.identifier == key)
                    .ok_or(AppError::NotFound("resource server"))?;
                resource_servers::delete(state, tid, ctx.actor.clone(), rs.id).await
            }
            .await;
            ctx.note("resource_server", &key, r);
        }
    }
    Ok(ctx.report)
}
