//! LDAP / Active Directory directories as identity providers.
//!
//! **Sign-in.** A directory user keeps no local password: the password step
//! (through [`crate::services::password::verify_and_upgrade`]) finds the
//! user's entry by its uuid attribute and binds as it with the password
//! typed, so a password changed or an account disabled in the directory
//! counts at once. An identifier no local account has is looked up in the
//! tenant's enabled directories ([`sign_in_unknown`]): a single matching
//! entry that the password binds as is imported through the provider's
//! link policy, like a brokered first sign-in. Every successful bind
//! refreshes the user's email, username, mapped attributes and groups.
//!
//! **Sync.** A leader-locked job ([`sync_due`]) runs each directory's
//! incremental sync (entries modified since the last one, by
//! `modifyTimestamp` or AD's `whenChanged`) on its interval, and a full one
//! on its own: the full pass also disables users whose entries are gone or
//! disabled in AD, and enables them again when they come back. A full pass
//! that reads no entries at all disables nobody (a wrong base DN must not
//! lock everyone out). Directory groups become rIDM groups the directory
//! owns; their memberships are kept for directory users only.
//!
//! **Write-back.** A `read_only` directory refuses password, email and
//! mapped-attribute changes to its users (the directory is where they
//! change). A `writable` one takes them: rIDM writes the directory first,
//! as the service account (Password Modify on OpenLDAP and most servers,
//! `unicodePwd` on AD), then stores what it keeps itself.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use chrono::Utc;
use ldap3::{Mod, Scope};
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::ldap::{self as proto, Conn, ConnectOptions, Entry, LdapFailure};
use crate::models::{
    GroupUpdate, IdentityProvider, IdpKind, LdapEditMode, LdapMembership, LdapScope, LdapSyncStats,
    LdapUpstream, LdapVendor, NewGroup, PasswordPolicy, Tenant, User, UserStatus, UserUpdate,
};
use crate::repos;
use crate::services::broker::{self, Identity};
use crate::services::password::SetPasswordOptions;
use crate::services::{groups, identity_providers, tenants, users};
use crate::state::AppState;

/// Entries per page of a sync search.
const PAGE_SIZE: i32 = 500;
/// How long a sync may hold its per-directory lock.
const SYNC_LOCK: Duration = Duration::from_secs(3600);
/// Directory groups a single user's sign-in looks at.
const USER_GROUPS_LIMIT: i32 = 1000;

/// An `ldap` identity provider with its directory settings.
#[derive(Debug, Clone)]
pub struct Directory {
    pub idp: IdentityProvider,
    pub cfg: LdapUpstream,
}

impl Directory {
    fn from_idp(idp: IdentityProvider) -> Option<Directory> {
        if idp.kind != IdpKind::Ldap {
            return None;
        }
        let cfg = idp.ldap.clone()?;
        Some(Directory { idp, cfg })
    }

    fn options(&self) -> ConnectOptions {
        ConnectOptions {
            url: self.cfg.url.clone(),
            starttls: self.cfg.starttls,
            ca_certificate: self.cfg.ca_certificate.clone(),
            timeout: Duration::from_secs(self.cfg.timeout_secs.clamp(1, 60) as u64),
        }
    }

    fn scope(&self) -> Scope {
        match self.cfg.search_scope {
            LdapScope::Subtree => Scope::Subtree,
            LdapScope::One => Scope::OneLevel,
        }
    }

    fn is_ad(&self) -> bool {
        self.cfg.vendor == LdapVendor::ActiveDirectory
    }

    /// The attribute the email comes from (the mapper, `mail` by default).
    fn email_attribute(&self) -> &str {
        self.idp.mappers.0.email.as_deref().unwrap_or("mail")
    }

    fn username_mapper(&self) -> &str {
        self.idp
            .mappers
            .0
            .username
            .as_deref()
            .unwrap_or(&self.cfg.username_attribute)
    }

    /// Every attribute a user search asks for.
    fn user_attributes(&self) -> Vec<String> {
        let mut out: Vec<String> = vec![];
        let mut add = |a: &str| {
            if !a.is_empty() && !out.iter().any(|o| o.eq_ignore_ascii_case(a)) {
                out.push(a.to_string());
            }
        };
        add(&self.cfg.uuid_attribute);
        add(&self.cfg.username_attribute);
        for a in &self.cfg.login_attributes {
            add(a);
        }
        add(self.email_attribute());
        add(self.username_mapper());
        for a in self.idp.mappers.0.attributes.values() {
            add(a);
        }
        add(self.cfg.vendor.modified_attribute());
        if self.is_ad() {
            add("userAccountControl");
        }
        out
    }

    fn user_filter(&self, extra: Option<String>) -> String {
        let mut parts = vec![self.cfg.user_object_filter.clone()];
        parts.extend(extra);
        proto::and(&parts)
    }

    /// The filter finding an entry by its stable identifier.
    fn subject_filter(&self, subject: &str) -> String {
        let attr = &self.cfg.uuid_attribute;
        if attr.eq_ignore_ascii_case("objectGUID")
            && let Some(bytes) = proto::guid_bytes(subject)
        {
            return proto::eq_bytes(attr, &bytes);
        }
        proto::eq(attr, subject)
    }

    /// What the entry says about the person, for the broker's resolution
    /// and the mappers.
    fn identity(&self, entry: &Entry) -> Option<Identity> {
        let subject = entry.uuid(&self.cfg.uuid_attribute)?;
        let attrs = self.user_attributes();
        let claims = entry.claims(attrs.iter().map(String::as_str));
        let mut identity = broker::identity_from_claims(&self.idp, claims, Some(subject))?;
        // Directories vouch for nothing: an address counts as verified only
        // when the provider trusts the directory's (`trust_email`).
        identity.email_verified = false;
        Some(identity)
    }

    fn disabled(&self, entry: &Entry) -> bool {
        self.is_ad() && entry.ad_disabled()
    }
}

fn unavailable(dir: &Directory, e: LdapFailure) -> AppError {
    AppError::Unavailable(format!("directory `{}`: {e}", dir.idp.alias))
}

/// Load a directory by provider id; `None` when it is gone or not LDAP.
pub async fn load(state: &AppState, tenant_id: Uuid, idp_id: Uuid) -> AppResult<Option<Directory>> {
    match identity_providers::get(state, tenant_id, &idp_id.to_string()).await {
        Ok(idp) => Ok(Directory::from_idp(idp)),
        Err(AppError::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// A directory as the admin API hands it over.
pub fn directory(idp: IdentityProvider) -> AppResult<Directory> {
    Directory::from_idp(idp)
        .ok_or_else(|| AppError::BadRequest("not an LDAP identity provider".into()))
}

/// Connect and bind as the service account (or stay anonymous without one).
async fn connect(state: &AppState, dir: &Directory) -> AppResult<Conn> {
    let mut conn = Conn::open(&dir.options())
        .await
        .map_err(|e| unavailable(dir, e))?;
    service_bind(state, dir, &mut conn).await?;
    Ok(conn)
}

async fn service_bind(state: &AppState, dir: &Directory, conn: &mut Conn) -> AppResult<()> {
    let Some(bind_dn) = &dir.cfg.bind_dn else {
        return Ok(());
    };
    let password = identity_providers::client_secret(state, &dir.idp)
        .await?
        .unwrap_or_else(|| Zeroizing::new(String::new()));
    let ok = conn
        .bind(bind_dn, &password)
        .await
        .map_err(|e| unavailable(dir, e))?;
    if !ok {
        return Err(AppError::Unavailable(format!(
            "directory `{}`: the service account's bind was refused",
            dir.idp.alias
        )));
    }
    Ok(())
}

/// The one entry with this subject, if the directory still has it.
async fn find_by_subject(
    dir: &Directory,
    conn: &mut Conn,
    subject: &str,
) -> AppResult<Option<Entry>> {
    let found = conn
        .search(
            &dir.cfg.users_dn,
            dir.scope(),
            &dir.user_filter(Some(dir.subject_filter(subject))),
            &dir.user_attributes(),
            2,
        )
        .await
        .map_err(|e| unavailable(dir, e))?;
    Ok(match <[Entry; 1]>::try_from(found) {
        Ok([one]) => Some(one),
        Err(_) => None,
    })
}

/// The directory a user is linked to, with the entry's subject.
pub async fn directory_of_user(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Option<(Directory, String)>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let link = repos::ldap::directory_of_user(&mut *tx, tenant_id, user_id).await?;
    tx.commit().await?;
    let Some((idp_id, subject)) = link else {
        return Ok(None);
    };
    Ok(load(state, tenant_id, idp_id).await?.map(|d| (d, subject)))
}

// ---------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------

/// Check a directory user's password by binding as their entry. `None`
/// when the user is not linked to a directory (the local hash decides).
/// A disabled directory, an entry that is gone or disabled in AD, and a
/// wrong password are all `Some(false)`; an unreachable directory is an
/// error, never a local fallback.
pub async fn verify_password(
    state: &AppState,
    tenant_id: Uuid,
    user: &User,
    password: &str,
) -> AppResult<Option<bool>> {
    let Some((dir, subject)) = directory_of_user(state, tenant_id, user.id).await? else {
        return Ok(None);
    };
    if !dir.idp.enabled || password.is_empty() {
        return Ok(Some(false));
    }
    let mut conn = connect(state, &dir).await?;
    let Some(entry) = find_by_subject(&dir, &mut conn, &subject).await? else {
        conn.close().await;
        return Ok(Some(false));
    };
    let ok = conn
        .bind(&entry.dn, password)
        .await
        .map_err(|e| unavailable(&dir, e))?;
    if !ok || dir.disabled(&entry) {
        conn.close().await;
        return Ok(Some(false));
    }
    let tenant = tenants::get(state, tenant_id).await?;
    let groups = user_groups_after_bind(state, &dir, &mut conn, &entry).await;
    conn.close().await;
    refresh(state, &tenant, &dir, user, &entry, true).await?;
    apply_user_groups(state, tenant_id, &dir, user.id, groups).await?;
    Ok(Some(true))
}

/// Sign in an identifier no local account has: find a single entry that it
/// names in one of the tenant's directories, bind as it, and import it
/// through the provider's link policy. `Ok(None)` when no directory knows
/// it or the password is wrong.
pub async fn sign_in_unknown(
    state: &AppState,
    tenant: &Tenant,
    identifier: &str,
    password: &str,
) -> AppResult<Option<User>> {
    if password.is_empty() || identifier.is_empty() || identifier.len() > 256 {
        return Ok(None);
    }
    let mut outage = None;
    for idp_id in identity_providers::directories(state, tenant.id).await? {
        let Some(dir) = load(state, tenant.id, idp_id).await? else {
            continue;
        };
        if !dir.idp.enabled {
            continue;
        }
        match sign_in_at(state, tenant, &dir, identifier, password).await {
            Ok(Found::No) => {}
            Ok(Found::Refused) => return Ok(None),
            Ok(Found::User(u)) => return Ok(Some(*u)),
            Err(e @ AppError::Unavailable(_)) => {
                tracing::warn!(provider = %dir.idp.alias, error = %e, "directory unavailable at sign-in");
                outage = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    match outage {
        Some(e) => Err(e),
        None => Ok(None),
    }
}

enum Found {
    /// The directory has no such entry.
    No,
    /// It has one, and the sign-in failed (wrong password, ambiguous,
    /// disabled, refused by the link policy): no other directory is asked.
    Refused,
    User(Box<User>),
}

async fn sign_in_at(
    state: &AppState,
    tenant: &Tenant,
    dir: &Directory,
    identifier: &str,
    password: &str,
) -> AppResult<Found> {
    let mut conn = connect(state, dir).await?;
    let by_login: Vec<String> = dir
        .cfg
        .login_attributes
        .iter()
        .map(|a| proto::eq(a, identifier))
        .collect();
    let found = conn
        .search(
            &dir.cfg.users_dn,
            dir.scope(),
            &dir.user_filter(Some(proto::or(&by_login))),
            &dir.user_attributes(),
            2,
        )
        .await
        .map_err(|e| unavailable(dir, e))?;
    let entry = match <[Entry; 1]>::try_from(found) {
        Ok([one]) => one,
        Err(v) if v.is_empty() => {
            conn.close().await;
            return Ok(Found::No);
        }
        Err(_) => {
            tracing::warn!(provider = %dir.idp.alias, "a sign-in identifier matches several directory entries; refused");
            conn.close().await;
            return Ok(Found::Refused);
        }
    };
    let ok = conn
        .bind(&entry.dn, password)
        .await
        .map_err(|e| unavailable(dir, e))?;
    if !ok || dir.disabled(&entry) {
        conn.close().await;
        return Ok(Found::Refused);
    }
    let Some(identity) = dir.identity(&entry) else {
        tracing::warn!(provider = %dir.idp.alias, dn = %entry.dn, "directory entry has no usable uuid attribute");
        conn.close().await;
        return Ok(Found::Refused);
    };
    let groups = user_groups_after_bind(state, dir, &mut conn, &entry).await;
    conn.close().await;
    let user = match broker::resolve_user(state, tenant, &dir.idp, &identity).await? {
        Ok(u) => u,
        Err(e) => {
            tracing::info!(provider = %dir.idp.alias, reason = e.code(), "directory user not imported");
            return Ok(Found::Refused);
        }
    };
    let user = refresh(state, tenant, dir, &user, &entry, true).await?;
    apply_user_groups(state, tenant.id, dir, user.id, groups).await?;
    Ok(Found::User(Box::new(user)))
}

/// What a directory says about a name another mechanism already proved.
pub enum DirectoryMatch {
    /// No entry has it.
    None,
    /// An entry has it, and it may not sign in (several entries match, it
    /// is disabled in AD, or the link policy refused to import it).
    Refused,
    User(Box<User>),
}

/// Sign in the directory user whose `attribute` is `value`, with no bind as
/// them: another mechanism (a Kerberos ticket) proved who they are. The
/// entry is imported or refreshed, groups included, as a password sign-in
/// would. An unreachable directory is an error.
pub async fn sign_in_proven(
    state: &AppState,
    tenant: &Tenant,
    dir: &Directory,
    attribute: &str,
    value: &str,
) -> AppResult<DirectoryMatch> {
    if !dir.idp.enabled || value.is_empty() || value.len() > 512 {
        return Ok(DirectoryMatch::Refused);
    }
    let mut conn = connect(state, dir).await?;
    let found = conn
        .search(
            &dir.cfg.users_dn,
            dir.scope(),
            &dir.user_filter(Some(proto::eq(attribute, value))),
            &dir.user_attributes(),
            2,
        )
        .await
        .map_err(|e| unavailable(dir, e))?;
    let entry = match <[Entry; 1]>::try_from(found) {
        Ok([one]) => one,
        Err(v) if v.is_empty() => {
            conn.close().await;
            return Ok(DirectoryMatch::None);
        }
        Err(_) => {
            tracing::warn!(provider = %dir.idp.alias, %attribute, "a proven name matches several directory entries; refused");
            conn.close().await;
            return Ok(DirectoryMatch::Refused);
        }
    };
    if dir.disabled(&entry) {
        conn.close().await;
        return Ok(DirectoryMatch::Refused);
    }
    let Some(identity) = dir.identity(&entry) else {
        tracing::warn!(provider = %dir.idp.alias, dn = %entry.dn, "directory entry has no usable uuid attribute");
        conn.close().await;
        return Ok(DirectoryMatch::Refused);
    };
    let groups = user_groups_after_bind(state, dir, &mut conn, &entry).await;
    conn.close().await;
    let user = match broker::resolve_user(state, tenant, &dir.idp, &identity).await? {
        Ok(u) => u,
        Err(e) => {
            tracing::info!(provider = %dir.idp.alias, reason = e.code(), "directory user not imported");
            return Ok(DirectoryMatch::Refused);
        }
    };
    let user = refresh(state, tenant, dir, &user, &entry, true).await?;
    apply_user_groups(state, tenant.id, dir, user.id, groups).await?;
    Ok(DirectoryMatch::User(Box::new(user)))
}

/// Bring a linked user up to date with their entry: the link's DN and
/// names, no local password, email, username and mapped attributes.
/// Returns the user as stored afterwards.
async fn refresh(
    state: &AppState,
    tenant: &Tenant,
    dir: &Directory,
    user: &User,
    entry: &Entry,
    login: bool,
) -> AppResult<User> {
    let Some(identity) = dir.identity(entry) else {
        return Ok(user.clone());
    };
    let tid = tenant.id;
    let mut tx = db::tenant_tx(&state.db, tid).await?;
    repos::ldap::update_link(
        &mut *tx,
        tid,
        repos::ldap::LinkUpdate {
            idp_id: dir.idp.id,
            external_subject: &identity.subject,
            dn: &entry.dn,
            username: identity.username.as_deref(),
            email: identity.email.as_deref(),
            login,
        },
    )
    .await?;
    repos::ldap::clear_password(&mut *tx, tid, user.id).await?;
    tx.commit().await?;

    let mut patch = UserUpdate::default();
    if identity.email.is_some() && identity.email != user.email {
        patch.email = Some(identity.email.clone());
        patch.email_verified = Some(dir.idp.trust_email);
    }
    let username = identity
        .username
        .as_deref()
        .and_then(|u| users::normalize_username(u).ok());
    if let Some(u) = &username
        && *u != user.username
    {
        patch.username = Some(u.clone());
    }
    let mut current = user.clone();
    if !patch.is_empty() {
        match users::update(state, tid, Actor::System, user.id, patch.clone()).await {
            Ok(u) => current = u,
            Err(AppError::Conflict(_)) if patch.username.is_some() => {
                // Another account holds the name: keep the old one.
                tracing::info!(provider = %dir.idp.alias, user = %user.id, "directory username taken locally; kept the old one");
                patch.username = None;
                if !patch.is_empty() {
                    current = users::update(state, tid, Actor::System, user.id, patch)
                        .await
                        .or_else(|e| match e {
                            AppError::Conflict(_) | AppError::Validation(_) => Ok(current.clone()),
                            other => Err(other),
                        })?;
                }
            }
            Err(AppError::Conflict(_) | AppError::Validation(_)) => {
                tracing::info!(provider = %dir.idp.alias, user = %user.id, "directory email refused locally; kept the old one");
            }
            Err(e) => return Err(e),
        }
    }
    broker::apply_mappers(state, tid, &dir.idp, &current, &identity).await?;
    Ok(current)
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

/// The directory groups of the entry just bound as, read as the service
/// account (the user may not see them). `None` when group sync is off or
/// the lookup failed (the sign-in goes on; the next sync catches up).
async fn user_groups_after_bind(
    state: &AppState,
    dir: &Directory,
    conn: &mut Conn,
    entry: &Entry,
) -> Option<Vec<Entry>> {
    let groups_dn = dir.cfg.groups_dn.as_ref()?;
    let value = match dir.cfg.group_membership {
        LdapMembership::Dn => entry.dn.clone(),
        LdapMembership::Username => entry.first(&dir.cfg.username_attribute)?.to_string(),
    };
    let lookup = async {
        service_bind(state, dir, conn).await?;
        conn.search(
            groups_dn,
            Scope::Subtree,
            &proto::and(&[
                dir.cfg.group_object_filter.clone(),
                proto::eq(&dir.cfg.group_member_attribute, &value),
            ]),
            &group_attributes(dir, false),
            USER_GROUPS_LIMIT,
        )
        .await
        .map_err(|e| unavailable(dir, e))
    };
    match lookup.await {
        Ok(g) => Some(g),
        Err(e) => {
            tracing::warn!(provider = %dir.idp.alias, error = %e, "directory group lookup failed at sign-in");
            None
        }
    }
}

fn group_attributes(dir: &Directory, with_members: bool) -> Vec<String> {
    let mut out = vec![
        dir.cfg.uuid_attribute.clone(),
        dir.cfg.group_name_attribute.clone(),
    ];
    if with_members {
        out.push(dir.cfg.group_member_attribute.clone());
    }
    out
}

/// Put a user in exactly the directory-owned groups `groups` names (the
/// ones they are no longer in are left); `None` changes nothing.
async fn apply_user_groups(
    state: &AppState,
    tenant_id: Uuid,
    dir: &Directory,
    user_id: Uuid,
    groups: Option<Vec<Entry>>,
) -> AppResult<()> {
    let Some(groups) = groups else {
        return Ok(());
    };
    let mut links = group_link_map(state, tenant_id, dir).await?;
    let mut stats = LdapSyncStats::default();
    let mut desired = HashSet::new();
    for g in &groups {
        if let Some(id) = ensure_group(state, tenant_id, dir, &mut links, g, &mut stats).await? {
            desired.insert(id);
        }
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let current: HashSet<Uuid> =
        repos::ldap::owned_groups_of_user(&mut *tx, tenant_id, dir.idp.id, user_id)
            .await?
            .into_iter()
            .collect();
    let mut changes = vec![];
    for g in desired.difference(&current) {
        if repos::groups::add_member(&mut *tx, tenant_id, *g, user_id).await? {
            changes.push(EventKind::GroupMemberAdded {
                group_id: *g,
                user_id,
            });
        }
    }
    for g in current.difference(&desired) {
        if repos::groups::remove_member(&mut *tx, tenant_id, *g, user_id).await? {
            changes.push(EventKind::GroupMemberRemoved {
                group_id: *g,
                user_id,
            });
        }
    }
    tx.commit().await?;
    publish_memberships(state, tenant_id, changes).await
}

async fn publish_memberships(
    state: &AppState,
    tenant_id: Uuid,
    changes: Vec<EventKind>,
) -> AppResult<()> {
    if changes.is_empty() {
        return Ok(());
    }
    crate::services::roles::bump_roles_version(state, tenant_id).await?;
    for kind in changes {
        state
            .events
            .publish(Event::new(Some(tenant_id), Actor::System, kind));
    }
    Ok(())
}

async fn group_link_map(
    state: &AppState,
    tenant_id: Uuid,
    dir: &Directory,
) -> AppResult<HashMap<String, repos::ldap::GroupLink>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let links = repos::ldap::group_links(&mut *tx, tenant_id, dir.idp.id).await?;
    tx.commit().await?;
    Ok(links
        .into_iter()
        .map(|l| (l.external_id.clone(), l))
        .collect())
}

/// The rIDM group a directory group maps to, created (or renamed) as
/// needed. A group an administrator made with the same name is never
/// taken over: the synced one is named `{name} ({alias})` instead.
async fn ensure_group(
    state: &AppState,
    tenant_id: Uuid,
    dir: &Directory,
    links: &mut HashMap<String, repos::ldap::GroupLink>,
    entry: &Entry,
    stats: &mut LdapSyncStats,
) -> AppResult<Option<Uuid>> {
    let Some(external_id) = entry.uuid(&dir.cfg.uuid_attribute) else {
        return Ok(None);
    };
    let Some(name) = entry
        .first(&dir.cfg.group_name_attribute)
        .map(str::trim)
        .filter(|n| !n.is_empty() && n.len() <= 200)
        .map(str::to_string)
    else {
        return Ok(None);
    };
    if let Some(link) = links.get_mut(&external_id) {
        let group_id = link.group_id;
        let group = match groups::get(state, tenant_id, group_id).await {
            Ok(g) => g,
            Err(AppError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        let fallback = format!("{name} ({})", dir.idp.alias);
        if group.name != name && group.name != fallback {
            for candidate in [&name, &fallback] {
                match groups::update(
                    state,
                    tenant_id,
                    Actor::System,
                    group_id,
                    GroupUpdate {
                        name: Some(candidate.clone()),
                        ..Default::default()
                    },
                )
                .await
                {
                    Ok(_) => {
                        stats.groups_updated += 1;
                        break;
                    }
                    Err(AppError::Conflict(_)) => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        if !link.external_dn.eq_ignore_ascii_case(&entry.dn) {
            let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
            repos::ldap::set_group_link_dn(
                &mut *tx,
                tenant_id,
                dir.idp.id,
                &external_id,
                &entry.dn,
            )
            .await?;
            tx.commit().await?;
            link.external_dn = entry.dn.clone();
        }
        return Ok(Some(group_id));
    }
    let mut created = None;
    for candidate in [name.clone(), format!("{name} ({})", dir.idp.alias)] {
        match groups::create(
            state,
            tenant_id,
            Actor::System,
            NewGroup {
                name: candidate,
                parent_id: dir.cfg.group_parent_id,
                description: Some(format!("Synced from {}", dir.idp.display_name)),
                attributes: None,
            },
        )
        .await
        {
            Ok(g) => {
                created = Some(g);
                break;
            }
            Err(AppError::Conflict(_)) => continue,
            Err(e) => return Err(e),
        }
    }
    let Some(group) = created else {
        tracing::info!(provider = %dir.idp.alias, group = %name, "directory group not synced: its names are taken");
        return Ok(None);
    };
    let link = repos::ldap::GroupLink {
        external_id: external_id.clone(),
        group_id: group.id,
        external_dn: entry.dn.clone(),
    };
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    repos::ldap::insert_group_link(&mut *tx, tenant_id, dir.idp.id, &link).await?;
    tx.commit().await?;
    links.insert(external_id, link);
    stats.groups_created += 1;
    Ok(Some(group.id))
}

/// Every value of a group's member attribute. Active Directory hands out a
/// large one in ranges (`member;range=0-1499`); the rest is fetched.
async fn all_members(dir: &Directory, conn: &mut Conn, entry: &Entry) -> AppResult<Vec<String>> {
    let attr = dir.cfg.group_member_attribute.to_ascii_lowercase();
    let mut values = entry.values(&attr).to_vec();
    let range_prefix = format!("{attr};range=");
    let mut current = entry.clone();
    for _ in 0..1000 {
        let Some((key, range)) = current.attrs.keys().find_map(|k| {
            k.strip_prefix(&range_prefix)
                .map(|r| (k.clone(), r.to_string()))
        }) else {
            break;
        };
        values.extend(current.attrs.get(&key).cloned().unwrap_or_default());
        let Some((_, end)) = range.split_once('-') else {
            break;
        };
        let Ok(end) = end.parse::<u64>() else {
            break; // `*`: the last range
        };
        let next = conn
            .search(
                &entry.dn,
                Scope::Base,
                "(objectClass=*)",
                &[format!(
                    "{};range={}-*",
                    dir.cfg.group_member_attribute,
                    end + 1
                )],
                1,
            )
            .await
            .map_err(|e| unavailable(dir, e))?;
        match next.into_iter().next() {
            Some(e) => current = e,
            None => break,
        }
    }
    Ok(values)
}

/// The linked users a group's member values name.
async fn member_users(
    state: &AppState,
    tenant_id: Uuid,
    dir: &Directory,
    members: &[String],
) -> AppResult<HashSet<Uuid>> {
    let mut out = HashSet::new();
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    for chunk in members.chunks(1000) {
        let ids = match dir.cfg.group_membership {
            LdapMembership::Dn => {
                repos::ldap::users_by_dns(&mut *tx, tenant_id, dir.idp.id, chunk).await?
            }
            LdapMembership::Username => {
                repos::ldap::users_by_usernames(&mut *tx, tenant_id, dir.idp.id, chunk).await?
            }
        };
        out.extend(ids);
    }
    tx.commit().await?;
    Ok(out)
}

/// Sync every directory group: create and rename the owned groups, set
/// their directory members, and (with at least one group read) delete the
/// owned groups the directory no longer has.
async fn sync_groups(
    state: &AppState,
    tenant_id: Uuid,
    dir: &Directory,
    conn: &mut Conn,
    stats: &mut LdapSyncStats,
) -> AppResult<()> {
    let Some(groups_dn) = dir.cfg.groups_dn.clone() else {
        return Ok(());
    };
    let mut links = group_link_map(state, tenant_id, dir).await?;
    let mut search = conn
        .search_paged(
            &groups_dn,
            Scope::Subtree,
            &dir.cfg.group_object_filter,
            group_attributes(dir, true),
            PAGE_SIZE,
        )
        .await
        .map_err(|e| unavailable(dir, e))?;
    let mut entries = vec![];
    while let Some(entry) = search.next().await.map_err(|e| unavailable(dir, e))? {
        entries.push(entry);
    }
    let mut seen = HashSet::new();
    let mut changes = vec![];
    for entry in &entries {
        let Some(group_id) = ensure_group(state, tenant_id, dir, &mut links, entry, stats).await?
        else {
            continue;
        };
        if let Some(ext) = entry.uuid(&dir.cfg.uuid_attribute) {
            seen.insert(ext);
        }
        let members = all_members(dir, conn, entry).await?;
        let desired = member_users(state, tenant_id, dir, &members).await?;
        let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
        let current: HashSet<Uuid> =
            repos::ldap::directory_members(&mut *tx, tenant_id, dir.idp.id, group_id)
                .await?
                .into_iter()
                .collect();
        for u in desired.difference(&current) {
            if repos::groups::add_member(&mut *tx, tenant_id, group_id, *u).await? {
                stats.memberships_added += 1;
                changes.push(EventKind::GroupMemberAdded {
                    group_id,
                    user_id: *u,
                });
            }
        }
        for u in current.difference(&desired) {
            if repos::groups::remove_member(&mut *tx, tenant_id, group_id, *u).await? {
                stats.memberships_removed += 1;
                changes.push(EventKind::GroupMemberRemoved {
                    group_id,
                    user_id: *u,
                });
            }
        }
        tx.commit().await?;
    }
    publish_memberships(state, tenant_id, changes).await?;
    if !entries.is_empty() {
        for (ext, link) in links {
            if seen.contains(&ext) {
                continue;
            }
            match groups::delete(state, tenant_id, Actor::System, link.group_id).await {
                Ok(()) | Err(AppError::NotFound(_)) => stats.groups_deleted += 1,
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

/// Run every directory sync that is due (the job's pass). Returns how many
/// ran; one directory failing is recorded on it and does not stop the rest.
pub async fn sync_due(state: &AppState) -> AppResult<usize> {
    let mut cursor = (Uuid::nil(), Uuid::nil());
    let mut done = 0;
    loop {
        let mut tx = db::bypass_tx(&state.db).await?;
        let page = repos::ldap::due_sync(&mut *tx, cursor, 100).await?;
        tx.commit().await?;
        let Some(last) = page.last().copied() else {
            break;
        };
        cursor = last;
        for (tenant_id, idp_id) in page {
            match sync(state, tenant_id, idp_id, false).await {
                Ok(_) => done += 1,
                Err(AppError::Conflict(_)) => {}
                Err(e) => {
                    tracing::warn!(%tenant_id, %idp_id, error = %e, "directory sync failed")
                }
            }
        }
    }
    Ok(done)
}

/// Sync one directory now: incremental, or full when `full` is asked for,
/// when none has run yet or when the last full one is older than the
/// directory's full interval. One sync per directory at a time (a second
/// is a conflict). The outcome is recorded on the directory.
pub async fn sync(
    state: &AppState,
    tenant_id: Uuid,
    idp_id: Uuid,
    full: bool,
) -> AppResult<LdapSyncStats> {
    let Some(dir) = load(state, tenant_id, idp_id).await? else {
        return Err(AppError::NotFound("identity provider"));
    };
    let Some(lock) =
        crate::jobs::leader::try_acquire(&state.redis, &format!("ldap_sync:{idp_id}"), SYNC_LOCK)
            .await?
    else {
        return Err(AppError::Conflict(
            "a sync of this directory is already running".into(),
        ));
    };
    let started = std::time::Instant::now();
    let result = run_sync(state, tenant_id, &dir, full).await;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    match &result {
        Ok((stats, cursor)) => {
            repos::ldap::record_sync(&mut *tx, tenant_id, idp_id, Ok((stats, cursor.as_deref())))
                .await?
        }
        Err(e) => {
            repos::ldap::record_sync(&mut *tx, tenant_id, idp_id, Err(&e.to_string())).await?
        }
    }
    tx.commit().await?;
    lock.release().await?;
    let outcome = if result.is_ok() { "success" } else { "failure" };
    metrics::counter!("ridm_ldap_syncs_total", "outcome" => outcome).increment(1);
    metrics::histogram!("ridm_ldap_sync_seconds").record(started.elapsed().as_secs_f64());
    let (stats, _) = result?;
    state.events.publish(Event::new(
        Some(tenant_id),
        Actor::System,
        EventKind::DirectorySynced {
            idp_id,
            provider: dir.idp.alias.clone(),
            full: stats.full,
            created: stats.created,
            updated: stats.updated,
            disabled: stats.disabled,
            enabled: stats.enabled,
        },
    ));
    Ok(stats)
}

async fn run_sync(
    state: &AppState,
    tenant_id: Uuid,
    dir: &Directory,
    force_full: bool,
) -> AppResult<(LdapSyncStats, Option<String>)> {
    let tenant = tenants::get(state, tenant_id).await?;
    let full_due = dir.cfg.last_full_sync_at.is_none_or(|t| {
        t < Utc::now() - chrono::Duration::hours(i64::from(dir.cfg.full_sync_interval_hours))
    });
    let full = force_full || full_due || dir.cfg.sync_cursor.is_none();
    let modified = dir.cfg.vendor.modified_attribute();
    let filter = match (&dir.cfg.sync_cursor, full) {
        (Some(cursor), false) => dir.user_filter(Some(proto::ge(modified, cursor))),
        _ => dir.user_filter(None),
    };
    let mut stats = LdapSyncStats {
        full,
        ..Default::default()
    };
    let mut cursor = dir.cfg.sync_cursor.clone();
    let mut seen: HashSet<String> = HashSet::new();
    let mut conn = connect(state, dir).await?;
    let mut search = conn
        .search_paged(
            &dir.cfg.users_dn,
            dir.scope(),
            &filter,
            dir.user_attributes(),
            PAGE_SIZE,
        )
        .await
        .map_err(|e| unavailable(dir, e))?;
    while let Some(entry) = search.next().await.map_err(|e| unavailable(dir, e))? {
        stats.read += 1;
        if let Some(t) = entry.first(modified)
            && let Some(key) = proto::generalized_time_key(t)
            && cursor
                .as_deref()
                .and_then(proto::generalized_time_key)
                .is_none_or(|c| key > c)
        {
            cursor = Some(t.to_string());
        }
        if let Some(subject) = sync_entry(state, &tenant, dir, &entry, &mut stats).await? {
            seen.insert(subject);
        }
    }
    if full {
        if stats.read > 0 {
            disable_missing(state, tenant_id, dir, &seen, &mut stats).await?;
        } else {
            tracing::warn!(provider = %dir.idp.alias, "a full directory sync read no entries; nobody was disabled");
        }
    }
    sync_groups(state, tenant_id, dir, &mut conn, &mut stats).await?;
    conn.close().await;
    Ok((stats, cursor))
}

/// Create, update, disable or enable the user of one entry. Returns the
/// entry's subject when it has one.
async fn sync_entry(
    state: &AppState,
    tenant: &Tenant,
    dir: &Directory,
    entry: &Entry,
    stats: &mut LdapSyncStats,
) -> AppResult<Option<String>> {
    let Some(identity) = dir.identity(entry) else {
        stats.skipped += 1;
        tracing::debug!(provider = %dir.idp.alias, dn = %entry.dn, "directory entry without a usable uuid attribute skipped");
        return Ok(None);
    };
    let subject = identity.subject.clone();
    let disabled_upstream = dir.disabled(entry);
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    let link = repos::ldap::link_state(&mut *tx, tenant.id, dir.idp.id, &subject).await?;
    let linked_user = match link {
        Some((user_id, _)) => repos::users::find_by_id(&mut *tx, tenant.id, user_id)
            .await?
            .filter(|u| u.deleted_at.is_none()),
        None => None,
    };
    tx.commit().await?;
    match (link, linked_user) {
        (Some((_, flagged)), Some(user)) => {
            let after = refresh(state, tenant, dir, &user, entry, false).await?;
            if after.email != user.email
                || after.username != user.username
                || after.attributes != user.attributes
            {
                stats.updated += 1;
            }
            if disabled_upstream && user.status == UserStatus::Active {
                set_status(state, tenant.id, dir, user.id, false).await?;
                stats.disabled += 1;
            } else if !disabled_upstream && user.status == UserStatus::Disabled && flagged {
                set_status(state, tenant.id, dir, user.id, true).await?;
                stats.enabled += 1;
            }
        }
        _ if disabled_upstream => {
            // Nobody is created for an account disabled in the directory.
        }
        _ => match broker::resolve_user(state, tenant, &dir.idp, &identity).await {
            Ok(Ok(user)) => {
                refresh(state, tenant, dir, &user, entry, false).await?;
                stats.created += 1;
            }
            Ok(Err(e)) => {
                stats.skipped += 1;
                tracing::info!(provider = %dir.idp.alias, dn = %entry.dn, reason = e.code(), "directory entry not imported");
            }
            Err(AppError::Validation(errors)) => {
                stats.skipped += 1;
                tracing::info!(provider = %dir.idp.alias, dn = %entry.dn, ?errors, "directory entry not imported");
            }
            Err(e) => return Err(e),
        },
    }
    Ok(Some(subject))
}

/// Disable (or enable again) a directory user, remembering that the
/// directory is the reason.
async fn set_status(
    state: &AppState,
    tenant_id: Uuid,
    dir: &Directory,
    user_id: Uuid,
    enabled: bool,
) -> AppResult<()> {
    users::update(
        state,
        tenant_id,
        Actor::System,
        user_id,
        UserUpdate {
            status: Some(if enabled {
                UserStatus::Active
            } else {
                UserStatus::Disabled
            }),
            ..Default::default()
        },
    )
    .await?;
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    repos::ldap::set_disabled_by_directory(&mut *tx, tenant_id, dir.idp.id, user_id, !enabled)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// A full pass: disable the linked users whose entries it did not read.
async fn disable_missing(
    state: &AppState,
    tenant_id: Uuid,
    dir: &Directory,
    seen: &HashSet<String>,
    stats: &mut LdapSyncStats,
) -> AppResult<()> {
    let mut after = String::new();
    loop {
        let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
        let page = repos::ldap::links_page(&mut *tx, tenant_id, dir.idp.id, &after, 1000).await?;
        tx.commit().await?;
        let Some(last) = page.last() else {
            break;
        };
        after = last.1.clone();
        for (user_id, subject, _) in page {
            if seen.contains(&subject) {
                continue;
            }
            let user = match users::get(state, tenant_id, user_id).await {
                Ok(u) => u,
                Err(AppError::NotFound(_)) => continue,
                Err(e) => return Err(e),
            };
            if user.status == UserStatus::Active {
                set_status(state, tenant_id, dir, user_id, false).await?;
                stats.disabled += 1;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Write-back
// ---------------------------------------------------------------------------

fn managed_elsewhere(dir: &Directory, what: &str) -> AppError {
    AppError::BadRequest(format!(
        "this account's {what} is managed by {}: change it there",
        dir.idp.display_name
    ))
}

fn refused(dir: &Directory, e: LdapFailure) -> AppError {
    match e {
        // constraintViolation (19), a password policy refusal; also
        // unwillingToPerform (53), AD's answer to a too-simple password.
        LdapFailure::Refused { rc: 19 | 53, text } => {
            AppError::Validation(vec![crate::error::FieldError {
                field: "password".into(),
                message: if text.is_empty() {
                    "the directory refused this password".into()
                } else {
                    format!("the directory refused this password ({text})")
                },
            }])
        }
        other => unavailable(dir, other),
    }
}

/// Set a directory user's password (a change, a reset, a temporary one).
/// `Ok(false)` when the user is not a directory user. A read-only
/// directory refuses; a writable one gets the password (after the tenant's
/// policy, which the directory may add to) and rIDM keeps no hash.
pub async fn set_password(
    state: &AppState,
    tenant_id: Uuid,
    policy: &PasswordPolicy,
    actor: &Actor,
    user_id: Uuid,
    password: &Zeroizing<String>,
    opts: SetPasswordOptions,
) -> AppResult<bool> {
    let Some((dir, subject)) = directory_of_user(state, tenant_id, user_id).await? else {
        return Ok(false);
    };
    if dir.cfg.edit_mode != LdapEditMode::Writable {
        return Err(managed_elsewhere(&dir, "password"));
    }
    let user = users::get(state, tenant_id, user_id).await?;
    if !opts.skip_policy {
        let problems = crate::services::password::check_policy(policy, password, Some(&user));
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
            crate::services::password::check_breached(state, tenant_id, password).await?;
        }
    }
    let mut conn = connect(state, &dir).await?;
    let Some(entry) = find_by_subject(&dir, &mut conn, &subject).await? else {
        conn.close().await;
        return Err(AppError::BadRequest(format!(
            "the account is no longer in {}",
            dir.idp.display_name
        )));
    };
    let written = if dir.is_ad() {
        conn.set_ad_password(&entry.dn, password).await
    } else {
        conn.password_modify(&entry.dn, password).await
    };
    conn.close().await;
    written.map_err(|e| refused(&dir, e))?;
    if opts.must_change != user.must_change_password {
        users::update(
            state,
            tenant_id,
            Actor::System,
            user_id,
            UserUpdate {
                must_change_password: Some(opts.must_change),
                ..Default::default()
            },
        )
        .await?;
    }
    state.events.publish(Event::new(
        Some(tenant_id),
        actor.clone(),
        EventKind::PasswordChanged {
            user_id,
            by_user: opts.by_user,
        },
    ));
    if opts.notify {
        crate::services::notifications::password_changed(state, tenant_id, user_id).await;
    }
    Ok(true)
}

/// A mapped attribute's value as directory values (`null` clears it).
fn directory_values(v: &Value) -> HashSet<Vec<u8>> {
    let one = |v: &Value| match v {
        Value::String(s) => Some(s.as_bytes().to_vec()),
        Value::Number(n) => Some(n.to_string().into_bytes()),
        Value::Bool(b) => Some(if *b {
            b"TRUE".to_vec()
        } else {
            b"FALSE".to_vec()
        }),
        _ => None,
    };
    match v {
        Value::Array(items) => items.iter().filter_map(one).collect(),
        other => one(other).into_iter().collect(),
    }
}

/// The directory changes a profile patch makes: `Err` for a new username
/// (it always comes from the directory), and for any change at all when
/// the directory is read-only.
fn planned_mods(dir: &Directory, user: &User, patch: &UserUpdate) -> AppResult<Vec<Mod<Vec<u8>>>> {
    if let Some(u) = &patch.username
        && *u != user.username
    {
        return Err(managed_elsewhere(dir, "username"));
    }
    let mut mods: Vec<Mod<Vec<u8>>> = vec![];
    if let Some(email) = &patch.email
        && *email != user.email
    {
        let values = email
            .as_ref()
            .map(|e| HashSet::from([e.as_bytes().to_vec()]))
            .unwrap_or_default();
        mods.push(Mod::Replace(
            dir.email_attribute().as_bytes().to_vec(),
            values,
        ));
    }
    if let Some(Value::Object(new)) = &patch.attributes {
        for (attr, ldap_attr) in &dir.idp.mappers.0.attributes {
            let old = user.attributes.get(attr).unwrap_or(&Value::Null);
            let new = new.get(attr).unwrap_or(&Value::Null);
            if old != new {
                mods.push(Mod::Replace(
                    ldap_attr.as_bytes().to_vec(),
                    directory_values(new),
                ));
            }
        }
    }
    if !mods.is_empty() && dir.cfg.edit_mode != LdapEditMode::Writable {
        return Err(managed_elsewhere(dir, "profile"));
    }
    Ok(mods)
}

/// Would the directory refuse this change? Checked before a change that
/// is confirmed later (a new email address waits for its code), so a
/// read-only directory says no before anything is sent. Writes nothing.
pub async fn check_profile_change(
    state: &AppState,
    tenant_id: Uuid,
    user: &User,
    patch: &UserUpdate,
) -> AppResult<()> {
    if user.password_hash.is_some() {
        return Ok(());
    }
    if let Some((dir, _)) = directory_of_user(state, tenant_id, user.id).await? {
        planned_mods(&dir, user, patch)?;
    }
    Ok(())
}

/// Before a directory user's profile changes (by anyone but rIDM's own
/// sync): a read-only directory refuses a new username, email or mapped
/// attribute; a writable one gets the email and mapped attributes first.
/// The username always comes from the directory.
pub async fn write_profile(
    state: &AppState,
    tenant_id: Uuid,
    user: &User,
    patch: &UserUpdate,
) -> AppResult<()> {
    let Some((dir, subject)) = directory_of_user(state, tenant_id, user.id).await? else {
        return Ok(());
    };
    let mods = planned_mods(&dir, user, patch)?;
    if mods.is_empty() {
        return Ok(());
    }
    let mut conn = connect(state, &dir).await?;
    let Some(entry) = find_by_subject(&dir, &mut conn, &subject).await? else {
        conn.close().await;
        return Err(AppError::BadRequest(format!(
            "the account is no longer in {}",
            dir.idp.display_name
        )));
    };
    let written = conn.modify(&entry.dn, mods).await;
    conn.close().await;
    written.map_err(|e| match e {
        LdapFailure::Refused { rc, text } => AppError::BadRequest(format!(
            "{} refused the change (result {rc}: {text})",
            dir.idp.display_name
        )),
        other => unavailable(&dir, other),
    })
}

// ---------------------------------------------------------------------------
// Connection test (admin API)
// ---------------------------------------------------------------------------

/// A few directory users as a test sees them.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct TestUser {
    pub dn: String,
    pub subject: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
}

/// What a connection test found.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct TestReport {
    /// The connection (and TLS) was established.
    pub connected: bool,
    /// The service account's bind succeeded (true without a bind DN).
    pub bound: bool,
    /// Up to five users under the base.
    pub users: Vec<TestUser>,
    /// Up to five group names, when group sync is on.
    pub groups: Vec<String>,
    /// What went wrong, when something did.
    pub error: Option<String>,
}

/// Connect, bind as the service account and read a few users and groups.
pub async fn test(state: &AppState, dir: &Directory) -> AppResult<TestReport> {
    let mut report = TestReport {
        connected: false,
        bound: false,
        users: vec![],
        groups: vec![],
        error: None,
    };
    let mut conn = match Conn::open(&dir.options()).await {
        Ok(c) => c,
        Err(e) => {
            report.error = Some(e.to_string());
            return Ok(report);
        }
    };
    report.connected = true;
    if let Err(e) = service_bind(state, dir, &mut conn).await {
        report.error = Some(e.to_string());
        conn.close().await;
        return Ok(report);
    }
    report.bound = true;
    match conn
        .search(
            &dir.cfg.users_dn,
            dir.scope(),
            &dir.user_filter(None),
            &dir.user_attributes(),
            5,
        )
        .await
    {
        Ok(entries) => {
            report.users = entries
                .iter()
                .map(|e| {
                    let identity = dir.identity(e);
                    TestUser {
                        dn: e.dn.clone(),
                        subject: e.uuid(&dir.cfg.uuid_attribute),
                        username: identity.as_ref().and_then(|i| i.username.clone()),
                        email: identity.and_then(|i| i.email),
                    }
                })
                .collect();
        }
        Err(e) => report.error = Some(e.to_string()),
    }
    if report.error.is_none()
        && let Some(groups_dn) = &dir.cfg.groups_dn
    {
        match conn
            .search(
                groups_dn,
                Scope::Subtree,
                &dir.cfg.group_object_filter,
                &group_attributes(dir, false),
                5,
            )
            .await
        {
            Ok(entries) => {
                report.groups = entries
                    .iter()
                    .filter_map(|e| e.first(&dir.cfg.group_name_attribute).map(str::to_string))
                    .collect();
            }
            Err(e) => report.error = Some(e.to_string()),
        }
    }
    conn.close().await;
    Ok(report)
}
