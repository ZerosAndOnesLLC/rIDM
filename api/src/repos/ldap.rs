//! LDAP directory sync state: status, the directory side of linked
//! identities, and the groups a directory owns.

use sqlx::PgExecutor;
use sqlx::types::Json;
use uuid::Uuid;

use crate::models::LdapSyncStats;

/// Record a sync attempt: its stats and cursor on success, its error
/// otherwise. `last_full_sync_at` moves only on a successful full pass.
pub async fn record_sync<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    idp_id: Uuid,
    outcome: Result<(&LdapSyncStats, Option<&str>), &str>,
) -> Result<(), sqlx::Error> {
    match outcome {
        Ok((stats, cursor)) => {
            sqlx::query(
                "UPDATE ldap_identity_providers SET last_sync_at = now(), \
                 last_full_sync_at = CASE WHEN $3 THEN now() ELSE last_full_sync_at END, \
                 last_sync_error = NULL, last_sync_stats = $4, \
                 sync_cursor = COALESCE($5, sync_cursor) \
                 WHERE tenant_id = $1 AND idp_id = $2",
            )
            .bind(tenant_id)
            .bind(idp_id)
            .bind(stats.full)
            .bind(Json(stats))
            .bind(cursor)
            .execute(exec)
            .await?;
        }
        Err(error) => {
            sqlx::query(
                "UPDATE ldap_identity_providers SET last_sync_at = now(), \
                 last_sync_error = left($3, 1000) WHERE tenant_id = $1 AND idp_id = $2",
            )
            .bind(tenant_id)
            .bind(idp_id)
            .bind(error)
            .execute(exec)
            .await?;
        }
    }
    Ok(())
}

/// Enabled directories whose periodic sync is due, across tenants, after
/// the keyset cursor. Needs a transaction that bypasses row level security.
pub async fn due_sync<'e>(
    exec: impl PgExecutor<'e>,
    after: (Uuid, Uuid),
    limit: i64,
) -> Result<Vec<(Uuid, Uuid)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT l.tenant_id, l.idp_id FROM ldap_identity_providers l \
         JOIN identity_providers i ON i.tenant_id = l.tenant_id AND i.id = l.idp_id \
         WHERE l.sync_interval_minutes > 0 AND i.enabled \
           AND (l.last_sync_at IS NULL \
                OR l.last_sync_at < now() - make_interval(mins => l.sync_interval_minutes)) \
           AND (l.tenant_id, l.idp_id) > ($1, $2) \
         ORDER BY l.tenant_id, l.idp_id LIMIT $3",
    )
    .bind(after.0)
    .bind(after.1)
    .bind(limit)
    .fetch_all(exec)
    .await
}

/// The directory a user is linked to, if any: `(idp_id, external_subject)`.
/// A user linked to several directories signs in against the first.
pub async fn directory_of_user<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<Option<(Uuid, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT f.idp_id, f.external_subject FROM federated_identities f \
         JOIN identity_providers i ON i.tenant_id = f.tenant_id AND i.id = f.idp_id \
         WHERE f.tenant_id = $1 AND f.user_id = $2 AND i.kind = 'ldap' \
         ORDER BY i.sort_order, i.alias LIMIT 1",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_optional(exec)
    .await
}

/// What the directory says about a linked identity now.
pub struct LinkUpdate<'a> {
    pub idp_id: Uuid,
    pub external_subject: &'a str,
    pub dn: &'a str,
    pub username: Option<&'a str>,
    pub email: Option<&'a str>,
    /// A sign-in (not a sync): `last_login_at` moves.
    pub login: bool,
}

pub async fn update_link<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    u: LinkUpdate<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE federated_identities SET external_dn = $4, external_username = $5, \
         external_email = $6, last_login_at = CASE WHEN $7 THEN now() ELSE last_login_at END \
         WHERE tenant_id = $1 AND idp_id = $2 AND external_subject = $3",
    )
    .bind(tenant_id)
    .bind(u.idp_id)
    .bind(u.external_subject)
    .bind(u.dn)
    .bind(u.username)
    .bind(u.email)
    .bind(u.login)
    .execute(exec)
    .await?;
    Ok(())
}

/// Mark (or clear) that the directory is why a user is disabled.
pub async fn set_disabled_by_directory<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    idp_id: Uuid,
    user_id: Uuid,
    disabled: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE federated_identities SET disabled_by_directory = $4 \
         WHERE tenant_id = $1 AND idp_id = $2 AND user_id = $3",
    )
    .bind(tenant_id)
    .bind(idp_id)
    .bind(user_id)
    .bind(disabled)
    .execute(exec)
    .await?;
    Ok(())
}

/// A page of the identities linked to a directory, after `after` (by
/// subject): `(user_id, external_subject, disabled_by_directory)`.
pub async fn links_page<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    idp_id: Uuid,
    after: &str,
    limit: i64,
) -> Result<Vec<(Uuid, String, bool)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT user_id, external_subject, disabled_by_directory FROM federated_identities \
         WHERE tenant_id = $1 AND idp_id = $2 AND external_subject > $3 \
         ORDER BY external_subject LIMIT $4",
    )
    .bind(tenant_id)
    .bind(idp_id)
    .bind(after)
    .bind(limit)
    .fetch_all(exec)
    .await
}

/// The users linked to a directory whose entries have these DNs
/// (compared case-insensitively, as LDAP does).
pub async fn users_by_dns<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    idp_id: Uuid,
    dns: &[String],
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT user_id FROM federated_identities \
         WHERE tenant_id = $1 AND idp_id = $2 AND external_dn IS NOT NULL \
           AND lower(external_dn) = ANY($3)",
    )
    .bind(tenant_id)
    .bind(idp_id)
    .bind(dns.iter().map(|d| d.to_lowercase()).collect::<Vec<_>>())
    .fetch_all(exec)
    .await
}

/// The users linked to a directory under these directory usernames.
pub async fn users_by_usernames<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    idp_id: Uuid,
    usernames: &[String],
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT user_id FROM federated_identities \
         WHERE tenant_id = $1 AND idp_id = $2 AND external_username = ANY($3)",
    )
    .bind(tenant_id)
    .bind(idp_id)
    .bind(usernames)
    .fetch_all(exec)
    .await
}

/// A group a directory owns.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GroupLink {
    pub external_id: String,
    pub group_id: Uuid,
    pub external_dn: String,
}

pub async fn group_links<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    idp_id: Uuid,
) -> Result<Vec<GroupLink>, sqlx::Error> {
    sqlx::query_as(
        "SELECT external_id, group_id, external_dn FROM ldap_group_links \
         WHERE tenant_id = $1 AND idp_id = $2 ORDER BY external_id LIMIT 100000",
    )
    .bind(tenant_id)
    .bind(idp_id)
    .fetch_all(exec)
    .await
}

pub async fn insert_group_link<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    idp_id: Uuid,
    link: &GroupLink,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO ldap_group_links (tenant_id, idp_id, external_id, group_id, external_dn) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (tenant_id, idp_id, external_id) \
         DO UPDATE SET group_id = EXCLUDED.group_id, external_dn = EXCLUDED.external_dn",
    )
    .bind(tenant_id)
    .bind(idp_id)
    .bind(&link.external_id)
    .bind(link.group_id)
    .bind(&link.external_dn)
    .execute(exec)
    .await?;
    Ok(())
}

pub async fn set_group_link_dn<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    idp_id: Uuid,
    external_id: &str,
    dn: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE ldap_group_links SET external_dn = $4 \
         WHERE tenant_id = $1 AND idp_id = $2 AND external_id = $3",
    )
    .bind(tenant_id)
    .bind(idp_id)
    .bind(external_id)
    .bind(dn)
    .execute(exec)
    .await?;
    Ok(())
}

/// The members of a group who are linked to this directory: the only
/// members its sync adds or removes.
pub async fn directory_members<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    idp_id: Uuid,
    group_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT gm.user_id FROM group_members gm \
         JOIN federated_identities f ON f.tenant_id = gm.tenant_id AND f.user_id = gm.user_id \
              AND f.idp_id = $3 \
         WHERE gm.tenant_id = $1 AND gm.group_id = $2",
    )
    .bind(tenant_id)
    .bind(group_id)
    .bind(idp_id)
    .fetch_all(exec)
    .await
}

/// The directory-owned groups a user is a member of.
pub async fn owned_groups_of_user<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    idp_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT l.group_id FROM ldap_group_links l \
         JOIN group_members gm ON gm.tenant_id = l.tenant_id AND gm.group_id = l.group_id \
         WHERE l.tenant_id = $1 AND l.idp_id = $2 AND gm.user_id = $3",
    )
    .bind(tenant_id)
    .bind(idp_id)
    .bind(user_id)
    .fetch_all(exec)
    .await
}

/// Directory users have no local password: linking one clears it.
pub async fn clear_password<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE users SET password_hash = NULL, password_algo = NULL, password_expires_at = NULL, \
         updated_at = now() WHERE tenant_id = $1 AND id = $2 AND password_hash IS NOT NULL",
    )
    .bind(tenant_id)
    .bind(user_id)
    .execute(exec)
    .await?;
    Ok(())
}

/// The user a directory entry is linked to and whether the directory is
/// why they are disabled.
pub async fn link_state<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    idp_id: Uuid,
    external_subject: &str,
) -> Result<Option<(Uuid, bool)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT user_id, disabled_by_directory FROM federated_identities \
         WHERE tenant_id = $1 AND idp_id = $2 AND external_subject = $3",
    )
    .bind(tenant_id)
    .bind(idp_id)
    .bind(external_subject)
    .fetch_optional(exec)
    .await
}
