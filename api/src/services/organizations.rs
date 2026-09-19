//! Organizations: groupings within one tenant that carry membership,
//! org-scoped role grants and email domains.
//!
//! A user may belong to several; `users.org_id` is the one they belong to
//! first, and a session records the one it acts in. A verified domain marked
//! `auto_join` makes users with a verified address at that domain members as
//! they sign in.

use hickory_resolver::Resolver;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use uuid::Uuid;

use crate::cache::keys;
use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{
    NewOrganization, NewOrganizationDomain, Organization, OrganizationDomain,
    OrganizationDomainUpdate, OrganizationFilter, OrganizationUpdate, Principal, User,
};
use crate::repos;
use crate::services::roles::{bump_roles_version, roles_version};
use crate::state::AppState;
use crate::util::cursor::{Cursor, Page};

/// Memberships are versioned by the roles version (org-scoped grants hang off
/// the same graph); the TTL only bounds a missed bump.
const ORGS_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// The DNS label a domain's proof is published under: a TXT record at
/// `_ridm-challenge.<domain>` whose value is the domain's `verification`.
pub const CHALLENGE_PREFIX: &str = "_ridm-challenge";

fn validate_slug(slug: &str) -> AppResult<String> {
    let s = slug.trim().to_lowercase();
    // Same shape as a tenant slug, and what the table's CHECK allows.
    let ok = !s.is_empty()
        && s.len() <= 63
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !s.starts_with('-')
        && !s.ends_with('-');
    if !ok {
        return Err(AppError::BadRequest(
            "slug must be 1-63 characters of lowercase letters, digits and hyphens, \
             and may not start or end with a hyphen"
                .into(),
        ));
    }
    Ok(s)
}

fn validate_name(name: &str) -> AppResult<String> {
    let n = name.trim();
    if n.is_empty() || n.len() > 255 {
        return Err(AppError::BadRequest(
            "display_name must be 1-255 characters".into(),
        ));
    }
    Ok(n.to_string())
}

fn validate_domain(domain: &str) -> AppResult<String> {
    let d = domain.trim().trim_end_matches('.').to_lowercase();
    let labels: Vec<&str> = d.split('.').collect();
    let ok = labels.len() > 1
        && d.len() <= 253
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        });
    if !ok {
        return Err(AppError::BadRequest(
            "domain must be a hostname such as example.com".into(),
        ));
    }
    Ok(d)
}

fn conflict(e: sqlx::Error, message: &str) -> AppError {
    match AppError::from_db(e) {
        AppError::Conflict(_) => AppError::Conflict(message.into()),
        other => other,
    }
}

pub async fn create(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    mut input: NewOrganization,
) -> AppResult<Organization> {
    input.slug = validate_slug(&input.slug)?;
    input.display_name = validate_name(&input.display_name)?;
    if let Some(attrs) = &input.attributes
        && !attrs.is_object()
    {
        return Err(AppError::BadRequest(
            "attributes must be a JSON object".into(),
        ));
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let org = repos::organizations::insert(&mut *tx, tenant_id, Uuid::now_v7(), &input)
        .await
        .map_err(|e| conflict(e, "an organization with this slug already exists"))?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::OrganizationCreated { org_id: org.id },
    ));
    Ok(org)
}

pub async fn get(state: &AppState, tenant_id: Uuid, id: Uuid) -> AppResult<Organization> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let org = repos::organizations::find_by_id(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    org.ok_or(AppError::NotFound("organization"))
}

pub async fn get_by_slug(state: &AppState, tenant_id: Uuid, slug: &str) -> AppResult<Organization> {
    let mut tx = db::read_tx(&state.db_read, tenant_id).await?;
    let org = repos::organizations::find_by_slug(&mut *tx, tenant_id, slug).await?;
    tx.commit().await?;
    org.ok_or(AppError::NotFound("organization"))
}

pub async fn list(
    state: &AppState,
    tenant_id: Uuid,
    filter: &OrganizationFilter,
    cursor: Option<Cursor>,
    limit: i64,
) -> AppResult<Page<Organization>> {
    let mut tx = db::read_tx(&state.db_read, tenant_id).await?;
    let rows = repos::organizations::list(
        &mut *tx,
        tenant_id,
        filter,
        cursor.map(|c| (c.created_at, c.id)),
        limit + 1,
    )
    .await?;
    tx.commit().await?;
    Ok(Page::from_rows(rows, limit, |o| Cursor {
        created_at: o.created_at,
        id: o.id,
    }))
}

pub async fn update(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    id: Uuid,
    mut patch: OrganizationUpdate,
) -> AppResult<Organization> {
    if patch.is_empty() {
        return get(state, tenant_id, id).await;
    }
    if let Some(s) = &patch.slug {
        patch.slug = Some(validate_slug(s)?);
    }
    if let Some(n) = &patch.display_name {
        patch.display_name = Some(validate_name(n)?);
    }
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let org = repos::organizations::update(&mut *tx, tenant_id, id, &patch)
        .await
        .map_err(|e| conflict(e, "an organization with this slug already exists"))?
        .ok_or(AppError::NotFound("organization"))?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::OrganizationUpdated { org_id: org.id },
    ));
    Ok(org)
}

/// Deletes an organization. Its memberships, domains and org-scoped role
/// grants go with it; members keep their accounts, and a member whose primary
/// organization this was is left without one.
pub async fn delete(state: &AppState, tenant_id: Uuid, actor: Actor, id: Uuid) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let deleted = repos::organizations::delete(&mut *tx, tenant_id, id).await?;
    tx.commit().await?;
    if !deleted {
        return Err(AppError::NotFound("organization"));
    }
    bump_roles_version(state, tenant_id).await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::OrganizationDeleted { org_id: id },
    ));
    Ok(())
}

// Membership ---------------------------------------------------------------

pub async fn members(state: &AppState, tenant_id: Uuid, org_id: Uuid) -> AppResult<Vec<User>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    if repos::organizations::find_by_id(&mut *tx, tenant_id, org_id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound("organization"));
    }
    let rows = repos::organizations::members(&mut *tx, tenant_id, org_id).await?;
    tx.commit().await?;
    Ok(rows)
}

pub async fn add_member(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    org_id: Uuid,
    user_id: Uuid,
) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    if repos::organizations::find_by_id(&mut *tx, tenant_id, org_id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound("organization"));
    }
    if repos::users::find_by_id(&mut *tx, tenant_id, user_id)
        .await?
        .filter(|u| u.deleted_at.is_none())
        .is_none()
    {
        return Err(AppError::NotFound("user"));
    }
    let added = repos::organizations::add_member(&mut *tx, tenant_id, org_id, user_id).await?;
    if added {
        repos::organizations::set_primary_org_if_unset(&mut *tx, tenant_id, user_id, org_id)
            .await?;
    }
    tx.commit().await?;
    if added {
        bump_roles_version(state, tenant_id).await?;
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::OrganizationMemberAdded { org_id, user_id },
        ));
    }
    Ok(())
}

pub async fn remove_member(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    org_id: Uuid,
    user_id: Uuid,
) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let removed = repos::organizations::remove_member(&mut *tx, tenant_id, org_id, user_id).await?;
    tx.commit().await?;
    if removed {
        bump_roles_version(state, tenant_id).await?;
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::OrganizationMemberRemoved { org_id, user_id },
        ));
    }
    Ok(())
}

/// A user's organizations, cached under the roles version, since the login
/// flow asks on every sign-in.
pub async fn of_user(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<Organization>> {
    let version = roles_version(state, tenant_id).await?;
    let key = keys::user_organizations(tenant_id, &version, user_id);
    let db = state.db.clone();
    let loaded = state
        .cache
        .get_or_load(&key, ORGS_TTL, || async move {
            let mut tx = db::tenant_tx(&db, tenant_id).await?;
            let rows = repos::organizations::of_user(&mut *tx, tenant_id, user_id).await?;
            tx.commit().await?;
            Ok(Some(rows))
        })
        .await?;
    Ok(loaded.map(|o| (*o).clone()).unwrap_or_default())
}

/// True when the user may act in the organization: a live membership of an
/// organization that is not disabled.
pub async fn may_act_in(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    org_id: Uuid,
) -> AppResult<bool> {
    Ok(of_user(state, tenant_id, user_id)
        .await?
        .into_iter()
        .any(|o| o.id == org_id && o.status == crate::models::OrganizationStatus::Active))
}

// Org-scoped role grants ---------------------------------------------------

/// Grants a role within one organization: it applies to sessions acting in
/// that organization and nowhere else.
pub async fn assign_role(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    org_id: Uuid,
    role_id: Uuid,
    principal: Principal,
) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    if repos::organizations::find_by_id(&mut *tx, tenant_id, org_id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound("organization"));
    }
    if repos::roles::find_by_id(&mut *tx, tenant_id, role_id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound("role"));
    }
    match principal {
        Principal::User { id } => {
            if !repos::organizations::is_member(&mut *tx, tenant_id, org_id, id).await? {
                return Err(AppError::BadRequest(
                    "the user is not a member of this organization".into(),
                ));
            }
        }
        Principal::Group { id } => {
            if repos::groups::find_by_id(&mut *tx, tenant_id, id)
                .await?
                .is_none()
            {
                return Err(AppError::NotFound("group"));
            }
        }
    }
    let added = repos::roles::assign(&mut *tx, tenant_id, role_id, principal, Some(org_id))
        .await
        .map_err(AppError::from_db)?;
    tx.commit().await?;
    if added {
        bump_roles_version(state, tenant_id).await?;
        let (user_id, group_id) = match principal {
            Principal::User { id } => (Some(id), None),
            Principal::Group { id } => (None, Some(id)),
        };
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::RoleAssigned {
                role_id,
                user_id,
                group_id,
            },
        ));
    }
    Ok(())
}

pub async fn unassign_role(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    org_id: Uuid,
    role_id: Uuid,
    principal: Principal,
) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let removed =
        repos::roles::unassign(&mut *tx, tenant_id, role_id, principal, Some(org_id)).await?;
    tx.commit().await?;
    if removed {
        bump_roles_version(state, tenant_id).await?;
        let (user_id, group_id) = match principal {
            Principal::User { id } => (Some(id), None),
            Principal::Group { id } => (None, Some(id)),
        };
        state.events.publish(Event::new(
            Some(tenant_id),
            actor,
            EventKind::RoleUnassigned {
                role_id,
                user_id,
                group_id,
            },
        ));
    }
    Ok(())
}

// Domains ------------------------------------------------------------------

pub async fn domains(
    state: &AppState,
    tenant_id: Uuid,
    org_id: Uuid,
) -> AppResult<Vec<OrganizationDomain>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    if repos::organizations::find_by_id(&mut *tx, tenant_id, org_id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound("organization"));
    }
    let rows = repos::organizations::domains(&mut *tx, tenant_id, org_id).await?;
    tx.commit().await?;
    Ok(rows)
}

pub async fn add_domain(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    org_id: Uuid,
    mut input: NewOrganizationDomain,
) -> AppResult<OrganizationDomain> {
    input.domain = validate_domain(&input.domain)?;
    let verification = format!("ridm-domain-verification={}", Uuid::now_v7().simple());
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    if repos::organizations::find_by_id(&mut *tx, tenant_id, org_id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound("organization"));
    }
    let domain = repos::organizations::insert_domain(
        &mut *tx,
        tenant_id,
        org_id,
        Uuid::now_v7(),
        &input,
        &verification,
    )
    .await
    .map_err(|e| {
        conflict(
            e,
            "this domain already belongs to an organization of this tenant",
        )
    })?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::OrganizationDomainAdded {
            org_id,
            domain_id: domain.id,
        },
    ));
    Ok(domain)
}

pub async fn update_domain(
    state: &AppState,
    tenant_id: Uuid,
    org_id: Uuid,
    id: Uuid,
    patch: OrganizationDomainUpdate,
) -> AppResult<OrganizationDomain> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let domain = repos::organizations::update_domain(&mut *tx, tenant_id, org_id, id, &patch)
        .await?
        .ok_or(AppError::NotFound("organization domain"))?;
    tx.commit().await?;
    Ok(domain)
}

/// Looks for the domain's TXT record and records the verification when it is
/// there. The lookup is the only outbound DNS rIDM makes.
pub async fn verify_domain(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    org_id: Uuid,
    id: Uuid,
) -> AppResult<OrganizationDomain> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let domain = repos::organizations::find_domain(&mut *tx, tenant_id, org_id, id)
        .await?
        .ok_or(AppError::NotFound("organization domain"))?;
    tx.commit().await?;
    if domain.verified_at.is_some() {
        return Ok(domain);
    }

    if !txt_record_present(&domain.domain, &domain.verification).await? {
        return Err(AppError::BadRequest(format!(
            "no TXT record {}.{} with the value {} was found",
            CHALLENGE_PREFIX, domain.domain, domain.verification
        )));
    }

    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let verified = repos::organizations::mark_domain_verified(&mut *tx, tenant_id, org_id, id)
        .await?
        .ok_or(AppError::NotFound("organization domain"))?;
    tx.commit().await?;
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::OrganizationDomainVerified {
            org_id,
            domain_id: id,
        },
    ));
    Ok(verified)
}

/// One TXT lookup of `_ridm-challenge.<domain>`. A resolver failure is a 503,
/// not a verification failure: the operator can retry.
async fn txt_record_present(domain: &str, expected: &str) -> AppResult<bool> {
    let name = format!("{CHALLENGE_PREFIX}.{domain}.");
    let resolver = Resolver::builder_tokio()
        .and_then(|b| b.build())
        .map_err(|e| {
            // No resolver configuration to read, or none usable: the operator
            // fixes the host, the administrator retries.
            tracing::warn!(error = %e, "no DNS resolver for organization domain verification");
            AppError::Unavailable("DNS resolver unavailable".into())
        })?;
    let lookup = match resolver.txt_lookup(name).await {
        Ok(lookup) => lookup,
        // A missing record and a broken zone look alike here; both mean "not
        // proven yet", which the caller reports as a bad request.
        Err(e) => {
            tracing::debug!(error = %e, domain, "domain verification lookup found nothing");
            return Ok(false);
        }
    };
    Ok(lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            hickory_resolver::proto::rr::RData::TXT(txt) => Some(txt),
            _ => None,
        })
        .any(|txt| {
            // A TXT record is a list of strings; a long value arrives split.
            let joined: Vec<u8> = txt
                .txt_data
                .iter()
                .flat_map(|d| d.iter().copied())
                .collect();
            String::from_utf8_lossy(&joined).trim() == expected
        }))
}

pub async fn delete_domain(
    state: &AppState,
    tenant_id: Uuid,
    actor: Actor,
    org_id: Uuid,
    id: Uuid,
) -> AppResult<()> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let deleted = repos::organizations::delete_domain(&mut *tx, tenant_id, org_id, id).await?;
    tx.commit().await?;
    if !deleted {
        return Err(AppError::NotFound("organization domain"));
    }
    state.events.publish(Event::new(
        Some(tenant_id),
        actor,
        EventKind::OrganizationDomainRemoved {
            org_id,
            domain_id: id,
        },
    ));
    Ok(())
}

/// Joins the user to the organization that owns their email domain, when that
/// domain is verified and set to auto-join. Runs at registration and at every
/// sign-in, so enabling auto-join later picks up the users already there.
/// Returns the organization joined, if any.
pub async fn ensure_auto_join(
    state: &AppState,
    tenant_id: Uuid,
    user: &User,
) -> AppResult<Option<Uuid>> {
    // An unverified address proves nothing, so it never joins anyone.
    if !user.email_verified {
        return Ok(None);
    }
    let Some(domain) = user
        .email
        .as_deref()
        .and_then(|e| e.rsplit_once('@'))
        .map(|(_, d)| d.to_lowercase())
    else {
        return Ok(None);
    };

    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let Some(org_id) =
        repos::organizations::auto_join_org_for_domain(&mut *tx, tenant_id, &domain).await?
    else {
        tx.commit().await?;
        return Ok(None);
    };
    let added = repos::organizations::add_member(&mut *tx, tenant_id, org_id, user.id).await?;
    if added {
        repos::organizations::set_primary_org_if_unset(&mut *tx, tenant_id, user.id, org_id)
            .await?;
    }
    tx.commit().await?;
    if added {
        bump_roles_version(state, tenant_id).await?;
        state.events.publish(Event::new(
            Some(tenant_id),
            Actor::System,
            EventKind::OrganizationMemberAdded {
                org_id,
                user_id: user.id,
            },
        ));
    }
    Ok(Some(org_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_are_dns_labels() {
        assert_eq!(validate_slug(" Acme-Corp ").unwrap(), "acme-corp");
        assert_eq!(validate_slug("a").unwrap(), "a");
        for bad in [
            "",
            "-acme",
            "acme-",
            "ac me",
            "acme.corp",
            "acme_corp",
            &"a".repeat(64),
        ] {
            assert!(validate_slug(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn domains_need_at_least_two_labels() {
        assert_eq!(validate_domain("Example.COM.").unwrap(), "example.com");
        assert_eq!(
            validate_domain("mail.example.co.uk").unwrap(),
            "mail.example.co.uk"
        );
        for bad in [
            "",
            "localhost",
            "example..com",
            "-example.com",
            "exa mple.com",
        ] {
            assert!(validate_domain(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn display_names_are_trimmed_and_bounded() {
        assert_eq!(validate_name("  Acme  ").unwrap(), "Acme");
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"a".repeat(256)).is_err());
    }
}
