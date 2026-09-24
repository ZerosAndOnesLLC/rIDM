//! Direct members of a group or an organization (run inside a tenant-bound
//! transaction). Both tables have the same shape, keyed by the parent's id.

use sqlx::{PgExecutor, QueryBuilder};
use uuid::Uuid;

use crate::models::{Group, Member};
use crate::repos::users::escape_like;
use crate::util::cursor::Cursor;

const USER_COLUMNS: &str = "u.id, u.tenant_id, u.org_id, u.username, u.email, u.email_verified, u.phone, \
    u.phone_verified, u.password_hash, u.password_algo, u.must_change_password, u.password_expires_at, \
    u.password_changed_at, u.status, u.attributes, u.locale, u.external_id, u.last_login_at, u.failed_attempts, \
    u.locked_until, u.deleted_at, u.terms_accepted_at, u.created_at, u.updated_at";

/// Whose members: a group's or an organization's.
#[derive(Debug, Clone, Copy)]
pub enum Of {
    Group(Uuid),
    Organization(Uuid),
}

impl Of {
    fn table(self) -> &'static str {
        match self {
            Of::Group(_) => "group_members",
            Of::Organization(_) => "organization_members",
        }
    }

    fn parent_column(self) -> &'static str {
        match self {
            Of::Group(_) => "group_id",
            Of::Organization(_) => "org_id",
        }
    }

    fn id(self) -> Uuid {
        match self {
            Of::Group(id) | Of::Organization(id) => id,
        }
    }

    /// `FROM <table> m JOIN users u … WHERE m.tenant_id = … AND m.<parent> = …
    /// AND u.deleted_at IS NULL`.
    fn push_from(self, qb: &mut QueryBuilder<sqlx::Postgres>, tenant_id: Uuid) {
        qb.push(" FROM ")
            .push(self.table())
            .push(" m JOIN users u ON u.tenant_id = m.tenant_id AND u.id = m.user_id WHERE m.tenant_id = ")
            .push_bind(tenant_id)
            .push(" AND m.")
            .push(self.parent_column())
            .push(" = ")
            .push_bind(self.id())
            .push(" AND u.deleted_at IS NULL");
    }
}

/// Members (not soft-deleted) in the order they joined, one keyset page of
/// `limit + 1` rows, optionally only those whose username or email starts
/// with `search`.
pub async fn page<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    of: Of,
    search: Option<&str>,
    after: Option<Cursor>,
    limit: i64,
) -> Result<Vec<Member>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT ");
    qb.push(USER_COLUMNS).push(", m.created_at AS joined_at");
    of.push_from(&mut qb, tenant_id);
    if let Some(search) = search.map(str::trim).filter(|s| !s.is_empty()) {
        let pattern = format!("{}%", escape_like(&search.to_lowercase()));
        qb.push(" AND (u.username LIKE ")
            .push_bind(pattern.clone())
            .push(" OR u.email LIKE ")
            .push_bind(pattern)
            .push(")");
    }
    if let Some(c) = after {
        qb.push(" AND (m.created_at, m.user_id) > (")
            .push_bind(c.created_at)
            .push(", ")
            .push_bind(c.id)
            .push(")");
    }
    qb.push(" ORDER BY m.created_at, m.user_id LIMIT ")
        .push_bind(limit + 1);
    qb.build_query_as::<Member>().fetch_all(exec).await
}

/// How many members (not soft-deleted) there are.
pub async fn count<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    of: Of,
) -> Result<i64, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT count(*)");
    of.push_from(&mut qb, tenant_id);
    qb.build_query_scalar::<i64>().fetch_one(exec).await
}

/// Every member's id and username, ordered by username: what a SCIM group
/// document lists, without reading whole user rows.
pub async fn refs<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    of: Of,
) -> Result<Vec<(Uuid, String)>, sqlx::Error> {
    let mut qb = QueryBuilder::new("SELECT u.id, u.username");
    of.push_from(&mut qb, tenant_id);
    qb.push(" ORDER BY u.username");
    qb.build_query_as::<(Uuid, String)>().fetch_all(exec).await
}

/// The groups each of `user_ids` belongs to directly, as `(user id, group)`
/// ordered by user and group name: one read for a page of users.
pub async fn direct_groups_of_users<'e>(
    exec: impl PgExecutor<'e>,
    tenant_id: Uuid,
    user_ids: &[Uuid],
) -> Result<Vec<(Uuid, Group)>, sqlx::Error> {
    #[derive(sqlx::FromRow)]
    struct Row {
        user_id: Uuid,
        #[sqlx(flatten)]
        group: Group,
    }
    let rows = sqlx::query_as::<_, Row>(
        "SELECT gm.user_id, g.id, g.tenant_id, g.parent_id, g.name, g.description, g.attributes, \
                g.created_at, g.updated_at \
         FROM group_members gm JOIN groups g ON g.tenant_id = gm.tenant_id AND g.id = gm.group_id \
         WHERE gm.tenant_id = $1 AND gm.user_id = ANY($2) ORDER BY gm.user_id, g.name",
    )
    .bind(tenant_id)
    .bind(user_ids)
    .fetch_all(exec)
    .await?;
    Ok(rows.into_iter().map(|r| (r.user_id, r.group)).collect())
}
