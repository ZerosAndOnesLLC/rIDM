//! Admin permission model.
//!
//! The admin API is guarded by permissions named `ridm:<resource>:<action>`.
//! They belong to a built-in resource server, [`ADMIN_AUDIENCE`], that every
//! tenant has, and are granted to roles through ordinary permission
//! assignments. Six built-in roles ([`BUILT_IN_ROLES`]) are seeded per tenant.
//!
//! Where a role lives decides its reach: roles in `master` act on every tenant
//! (global administrators); roles in any other tenant act on that tenant only.
//!
//! How a role is *granted* decides its reach within a tenant. An assignment
//! carrying an `org_id` (`role_assignments.org_id`) applies only to sessions
//! acting in that organization, and only on the admin routes of that one
//! organization — see [`crate::middleware::AdminCtx::require_org`].
//! [`ORG_ADMIN_ROLE`] is the role meant to be granted that way.
//!
//! The catalogue here mirrors migration `20260915124323_admin_permission_model`;
//! a contract test keeps the two identical. Custom roles may also be granted
//! wildcard permissions (`ridm:users:*`, `ridm:*`), see [`matches`].

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::repos;
use crate::services::roles;
use crate::state::AppState;

/// Identifier (audience) of the built-in admin resource server. Access tokens
/// presented to the admin API must carry it in `aud`, and clients must list it
/// in `allowed_audiences` to obtain such tokens.
pub const ADMIN_AUDIENCE: &str = "urn:ridm:admin";

pub const OWNER_ROLE: &str = "ridm:owner";
pub const ADMIN_ROLE: &str = "ridm:admin";
pub const USER_MANAGER_ROLE: &str = "ridm:user-manager";
pub const CLIENT_MANAGER_ROLE: &str = "ridm:client-manager";
pub const ORG_ADMIN_ROLE: &str = "ridm:org-admin";
pub const VIEWER_ROLE: &str = "ridm:viewer";

const PERMISSIONS_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub struct PermissionDef {
    pub name: &'static str,
    pub description: &'static str,
}

macro_rules! perm {
    ($name:literal, $desc:literal) => {
        PermissionDef {
            name: $name,
            description: $desc,
        }
    };
}

/// Every admin permission, in catalogue order.
pub const CATALOGUE: &[PermissionDef] = &[
    perm!(
        "ridm:tenants:read",
        "View tenant settings, branding, feature flags and IP rules"
    ),
    perm!(
        "ridm:tenants:write",
        "Change tenant settings, branding, feature flags and IP rules"
    ),
    perm!(
        "ridm:tenants:create",
        "Create tenants (global administrators only)"
    ),
    perm!("ridm:tenants:delete", "Delete tenants"),
    perm!("ridm:tenants:export", "Export tenant configuration"),
    perm!("ridm:tenants:import", "Import tenant configuration"),
    perm!(
        "ridm:users:read",
        "View users, their sessions, credentials, devices, tokens and consents"
    ),
    perm!(
        "ridm:users:write",
        "Create, change, disable and delete users; manage their sessions, credentials, devices, tokens, consents, roles and groups"
    ),
    perm!(
        "ridm:users:impersonate",
        "Sign in as a user to see what they see (impersonation), where the tenant allows it"
    ),
    perm!("ridm:invitations:read", "View invitations"),
    perm!(
        "ridm:invitations:write",
        "Create, resend and revoke invitations; bulk import users"
    ),
    perm!("ridm:groups:read", "View groups and their members"),
    perm!(
        "ridm:groups:write",
        "Create, change and delete groups; manage membership"
    ),
    perm!(
        "ridm:orgs:read",
        "View organizations, their members and domains"
    ),
    perm!(
        "ridm:orgs:write",
        "Create, change and delete organizations; manage membership, domains and org-scoped role grants"
    ),
    perm!("ridm:roles:read", "View roles, composites and assignments"),
    perm!(
        "ridm:roles:write",
        "Create, change and delete roles and composites"
    ),
    perm!("ridm:clients:read", "View OAuth clients"),
    perm!(
        "ridm:clients:write",
        "Create, change and delete OAuth clients; generate and rotate secrets"
    ),
    perm!("ridm:scopes:read", "View scopes"),
    perm!("ridm:scopes:write", "Create, change and delete scopes"),
    perm!("ridm:mappers:read", "View claim mappers"),
    perm!(
        "ridm:mappers:write",
        "Create, change and delete claim mappers"
    ),
    perm!(
        "ridm:resource-servers:read",
        "View resource servers and their permissions"
    ),
    perm!(
        "ridm:resource-servers:write",
        "Create, change and delete resource servers and permissions; grant permissions to roles"
    ),
    perm!("ridm:idps:read", "View identity providers"),
    perm!(
        "ridm:idps:write",
        "Create, change and delete identity providers"
    ),
    perm!(
        "ridm:keys:read",
        "View signing keys and master-key rotation status"
    ),
    perm!("ridm:keys:write", "Rotate and revoke signing keys"),
    perm!(
        "ridm:messaging:read",
        "View messaging settings and templates"
    ),
    perm!(
        "ridm:messaging:write",
        "Change messaging settings and templates; send test messages"
    ),
    perm!("ridm:audit:read", "View and export the audit log"),
    perm!("ridm:webhooks:read", "View webhooks and their deliveries"),
    perm!(
        "ridm:webhooks:write",
        "Create, change and delete webhooks; redeliver events"
    ),
    perm!("ridm:scim:read", "View SCIM provisioning tokens"),
    perm!(
        "ridm:scim:write",
        "Create and revoke SCIM provisioning tokens"
    ),
];

/// Which catalogue entries a built-in role receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grants {
    All,
    AllExcept(&'static [&'static str]),
    Only(&'static [&'static str]),
    /// Every `*:read` permission.
    ReadOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltInRole {
    pub name: &'static str,
    pub description: &'static str,
    pub grants: Grants,
}

impl BuiltInRole {
    /// Catalogue permissions granted to this role, in catalogue order.
    pub fn permissions(&self) -> Vec<&'static str> {
        CATALOGUE
            .iter()
            .map(|p| p.name)
            .filter(|name| match self.grants {
                Grants::All => true,
                Grants::AllExcept(excluded) => !excluded.contains(name),
                Grants::Only(included) => included.contains(name),
                Grants::ReadOnly => name.ends_with(":read"),
            })
            .collect()
    }
}

pub const BUILT_IN_ROLES: &[BuiltInRole] = &[
    BuiltInRole {
        name: OWNER_ROLE,
        description: "Owner: every admin permission, including tenant lifecycle",
        grants: Grants::All,
    },
    BuiltInRole {
        name: ADMIN_ROLE,
        description: "Administrator: everything except creating, deleting and importing tenants",
        // Impersonation stays with owners unless a custom role is given it.
        grants: Grants::AllExcept(&[
            "ridm:tenants:create",
            "ridm:tenants:delete",
            "ridm:tenants:import",
            "ridm:users:impersonate",
        ]),
    },
    BuiltInRole {
        name: USER_MANAGER_ROLE,
        description: "User manager: users, invitations and groups",
        grants: Grants::Only(&[
            "ridm:tenants:read",
            "ridm:users:read",
            "ridm:users:write",
            "ridm:invitations:read",
            "ridm:invitations:write",
            "ridm:groups:read",
            "ridm:groups:write",
            "ridm:orgs:read",
            "ridm:orgs:write",
            "ridm:roles:read",
            "ridm:audit:read",
            "ridm:scim:read",
            "ridm:scim:write",
        ]),
    },
    BuiltInRole {
        name: CLIENT_MANAGER_ROLE,
        description: "Client manager: clients, scopes, claim mappers and resource servers",
        grants: Grants::Only(&[
            "ridm:tenants:read",
            "ridm:clients:read",
            "ridm:clients:write",
            "ridm:scopes:read",
            "ridm:scopes:write",
            "ridm:mappers:read",
            "ridm:mappers:write",
            "ridm:resource-servers:read",
            "ridm:resource-servers:write",
            "ridm:roles:read",
            "ridm:audit:read",
        ]),
    },
    BuiltInRole {
        name: ORG_ADMIN_ROLE,
        description: "Organization administrator: the members, roles, domains and invitations of the organizations it is granted in",
        grants: Grants::Only(&[
            "ridm:orgs:read",
            "ridm:orgs:write",
            "ridm:invitations:read",
            "ridm:invitations:write",
            "ridm:roles:read",
        ]),
    },
    BuiltInRole {
        name: VIEWER_ROLE,
        description: "Viewer: read-only access to everything",
        grants: Grants::ReadOnly,
    },
];

pub fn built_in_role(name: &str) -> Option<&'static BuiltInRole> {
    BUILT_IN_ROLES.iter().find(|r| r.name == name)
}

pub fn is_known(permission: &str) -> bool {
    CATALOGUE.iter().any(|p| p.name == permission)
}

/// Does a granted permission satisfy a required one?
///
/// Exact names match; a granted name whose last segment is `*` matches every
/// required name sharing the preceding segments (`ridm:users:*` covers
/// `ridm:users:read`, `ridm:*` covers everything under `ridm:`). Wildcards are
/// only meaningful on the granted side; a required name is always concrete.
pub fn matches(granted: &str, required: &str) -> bool {
    if required.contains('*') {
        return false;
    }
    if granted == required {
        return true;
    }
    match granted.strip_suffix(":*") {
        Some(prefix) => required
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.len() > 1 && rest.starts_with(':') && !rest.contains('*')),
        None => false,
    }
}

/// The permissions a principal holds, normalised (sorted, deduplicated).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSet {
    names: Vec<String>,
}

impl PermissionSet {
    pub fn new(names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let mut names: Vec<String> = names.into_iter().map(Into::into).collect();
        names.sort_unstable();
        names.dedup();
        Self { names }
    }

    pub fn names(&self) -> &[String] {
        &self.names
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Is `required` satisfied by any held permission (including wildcards)?
    pub fn allows(&self, required: &str) -> bool {
        self.names.iter().any(|g| matches(g, required))
    }

    /// Does this set satisfy every permission in `required`? Used to stop an
    /// administrator from granting more than they hold themselves.
    pub fn covers<'a>(&self, required: impl IntoIterator<Item = &'a str>) -> bool {
        required.into_iter().all(|r| self.allows(r))
    }
}

/// Admin permissions of a user in `tenant_id`: every permission of the
/// built-in admin resource server reachable through the user's effective
/// roles. Cached under the tenant's roles version token, so any role, group,
/// assignment or grant change invalidates it at once.
///
/// `scope` decides which grants count; see [`OrgScope`].
pub async fn permissions_of_user(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    scope: OrgScope,
) -> AppResult<Arc<PermissionSet>> {
    let version = roles::access_version(state, tenant_id, user_id).await?;
    let key = keys::admin_permissions(tenant_id, &version, user_id, scope.cache_suffix());
    let db = state.db.clone();
    let state_for_roles = state.clone();
    let set = state
        .cache
        .get_or_load(&key, PERMISSIONS_TTL, || async move {
            let effective = match scope {
                OrgScope::TenantWide => {
                    roles::effective_roles(&state_for_roles, tenant_id, user_id, None).await?
                }
                OrgScope::In(org) => {
                    roles::effective_roles(&state_for_roles, tenant_id, user_id, Some(org)).await?
                }
                OrgScope::Anywhere => {
                    roles::effective_roles_anywhere(&state_for_roles, tenant_id, user_id).await?
                }
            };
            if effective.is_empty() {
                return Ok(Some(PermissionSet::default()));
            }
            let role_ids: Vec<Uuid> = effective.iter().map(|r| r.id).collect();
            let mut tx = db::tenant_tx(&db, tenant_id).await?;
            let rs =
                repos::resource_servers::find_by_identifier(&mut *tx, tenant_id, ADMIN_AUDIENCE)
                    .await?
                    .ok_or_else(|| {
                        AppError::Internal(format!(
                            "tenant {tenant_id} has no `{ADMIN_AUDIENCE}` resource server"
                        ))
                    })?;
            let names = repos::resource_servers::permissions_for_roles(
                &mut *tx, tenant_id, rs.id, &role_ids,
            )
            .await?;
            tx.commit().await?;
            Ok(Some(PermissionSet::new(names)))
        })
        .await?;
    Ok(set.unwrap_or_default())
}

/// Which role grants count when resolving a user's admin permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgScope {
    /// Unscoped grants only: what a tenant-wide check may rely on. An
    /// org-scoped grant can never satisfy one.
    TenantWide,
    /// Unscoped grants plus those scoped to this organization — the reach of
    /// a session acting in it, consulted only by
    /// [`crate::middleware::AdminCtx::require_org`].
    In(Uuid),
    /// Unscoped grants plus those scoped to any organization: "is this user an
    /// administrator at all?", asked before a session has chosen one.
    Anywhere,
}

impl OrgScope {
    fn cache_suffix(self) -> Option<String> {
        match self {
            Self::TenantWide => None,
            Self::In(org) => Some(org.to_string()),
            Self::Anywhere => Some("any".into()),
        }
    }
}

/// Something an administrator is about to hand to a principal.
#[derive(Debug, Clone, Copy)]
pub enum Grant {
    Role(Uuid),
    /// Membership: every role of the group and its ancestors.
    Group(Uuid),
}

/// Admin permissions a grant carries (composites expanded), for
/// [`crate::middleware::AdminCtx::require_can_grant`].
pub async fn permissions_of_grant(
    state: &AppState,
    tenant_id: Uuid,
    grant: Grant,
) -> AppResult<Vec<String>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let direct: Vec<Uuid> = match grant {
        Grant::Role(id) => vec![id],
        Grant::Group(id) => {
            repos::roles::role_ids_of_group_lineage(&mut *tx, tenant_id, id).await?
        }
    };
    if direct.is_empty() {
        return Ok(vec![]);
    }
    let all = repos::roles::expand_composites(&mut *tx, tenant_id, &direct).await?;
    let Some(rs) =
        repos::resource_servers::find_by_identifier(&mut *tx, tenant_id, ADMIN_AUDIENCE).await?
    else {
        return Ok(vec![]);
    };
    let names =
        repos::resource_servers::permissions_for_roles(&mut *tx, tenant_id, rs.id, &all).await?;
    tx.commit().await?;
    Ok(names)
}

/// Admin permissions carried by each of `role_ids` (composites expanded), for
/// a role picker that must not offer what the caller cannot grant.
pub async fn permissions_per_role(
    state: &AppState,
    tenant_id: Uuid,
    role_ids: &[Uuid],
) -> AppResult<std::collections::HashMap<Uuid, Vec<String>>> {
    let mut out: std::collections::HashMap<Uuid, Vec<String>> = std::collections::HashMap::new();
    if role_ids.is_empty() {
        return Ok(out);
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let Some(rs) =
        repos::resource_servers::find_by_identifier(&mut *tx, tenant_id, ADMIN_AUDIENCE).await?
    else {
        return Ok(out);
    };
    let rows =
        repos::resource_servers::permissions_per_role(&mut *tx, tenant_id, rs.id, role_ids).await?;
    tx.commit().await?;
    for (role_id, name) in rows {
        out.entry(role_id).or_default().push(name);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_wildcard_matching() {
        assert!(matches("ridm:users:read", "ridm:users:read"));
        assert!(!matches("ridm:users:read", "ridm:users:write"));
        assert!(matches("ridm:users:*", "ridm:users:read"));
        assert!(!matches("ridm:users:*", "ridm:usersx:read"));
        assert!(!matches("ridm:users:*", "ridm:users"));
        assert!(!matches("ridm:users:*", "ridm:users:"));
        assert!(matches("ridm:*", "ridm:users:read"));
        assert!(matches("ridm:*", "ridm:tenants:delete"));
        assert!(!matches("ridm:*", "other:users:read"));
        // Wildcards on the required side never match.
        assert!(!matches("ridm:users:read", "ridm:users:*"));
        assert!(!matches("ridm:*", "ridm:*"));
    }

    #[test]
    fn permission_set_normalises_and_covers() {
        let set = PermissionSet::new(["ridm:users:write", "ridm:users:read", "ridm:users:read"]);
        assert_eq!(set.names(), ["ridm:users:read", "ridm:users:write"]);
        assert!(set.allows("ridm:users:read"));
        assert!(!set.allows("ridm:clients:read"));
        assert!(set.covers(["ridm:users:read", "ridm:users:write"]));
        assert!(!set.covers(["ridm:users:read", "ridm:clients:read"]));
        let all = PermissionSet::new(["ridm:*"]);
        assert!(all.covers(CATALOGUE.iter().map(|p| p.name)));
    }

    #[test]
    fn catalogue_is_well_formed() {
        let mut names: Vec<&str> = CATALOGUE.iter().map(|p| p.name).collect();
        let n = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), n, "duplicate permission names");
        for p in CATALOGUE {
            let parts: Vec<&str> = p.name.split(':').collect();
            assert_eq!(parts.len(), 3, "{}", p.name);
            assert_eq!(parts[0], "ridm");
            assert!(!p.name.contains('*'));
            assert!(!p.description.is_empty());
        }
    }

    #[test]
    fn built_in_roles_have_expected_reach() {
        let owner = built_in_role(OWNER_ROLE).unwrap().permissions();
        assert_eq!(owner.len(), CATALOGUE.len());
        let admin = built_in_role(ADMIN_ROLE).unwrap().permissions();
        assert_eq!(admin.len(), CATALOGUE.len() - 4);
        assert!(!admin.contains(&"ridm:tenants:delete"));
        // Impersonation stays with owners.
        assert!(!admin.contains(&"ridm:users:impersonate"));
        let viewer = built_in_role(VIEWER_ROLE).unwrap().permissions();
        assert!(viewer.iter().all(|p| p.ends_with(":read")));
        assert!(viewer.contains(&"ridm:audit:read"));
        let um = built_in_role(USER_MANAGER_ROLE).unwrap().permissions();
        assert!(um.contains(&"ridm:users:write") && !um.contains(&"ridm:clients:read"));
        let cm = built_in_role(CLIENT_MANAGER_ROLE).unwrap().permissions();
        assert!(cm.contains(&"ridm:clients:write") && !cm.contains(&"ridm:users:read"));
        // Every name a built-in role lists exists in the catalogue.
        for role in BUILT_IN_ROLES {
            if let Grants::Only(list) | Grants::AllExcept(list) = role.grants {
                for name in list {
                    assert!(is_known(name), "{name} is not in the catalogue");
                }
            }
        }
    }
}
