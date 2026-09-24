//! Single-use download tickets for the admin exports.
//!
//! An export (a tenant's configuration, its users, an audit trail) can be
//! far larger than a browser should hold in memory, but a console download
//! made with `fetch` must be, because only `fetch` can send the
//! `Authorization` header. A ticket lets the browser's own download manager
//! fetch it instead, streaming it to disk: an administrator's authenticated
//! request asks for one naming the export (path and query), and the export
//! URL with `?download_ticket=` then authenticates exactly one `GET` of
//! exactly that export, within a minute, as that administrator.
//!
//! Only the export routes accept a ticket. The ticket is 256 random bits,
//! kept in Valkey under its hash with the caller's token, and taken with
//! GETDEL, so it works once. Redeeming it runs the whole admin
//! authentication again with that token (the session must still be live,
//! the user active, the permission held), except for a DPoP proof: a
//! browser navigation cannot make one, and the request that asked for the
//! ticket was checked for it.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cache::keys;
use crate::error::{AppError, AppResult};
use crate::middleware::is_valid_slug;
use crate::oidc::bearer::Scheme;
use crate::state::AppState;

/// The query parameter a ticket rides in.
pub const TICKET_PARAM: &str = "download_ticket";
/// How long a ticket waits to be used, in seconds.
pub const TICKET_TTL_SECS: u64 = 60;

/// An export a ticket may be issued for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Export {
    /// `/admin/tenants/{slug}/export`
    TenantConfig { slug: String },
    /// `/admin/tenants/{slug}/users/export`
    Users { slug: String },
    /// `/admin/tenants/{slug}/audit/export`
    Audit { slug: String },
    /// `/admin/audit/export`
    GlobalAudit,
}

impl Export {
    /// The export `path` names, if it names one.
    pub fn of_path(path: &str) -> Option<Self> {
        let segments: Vec<&str> = path.strip_prefix("/admin/")?.split('/').collect();
        let slug = |s: &str| is_valid_slug(s).then(|| s.to_string());
        match segments.as_slice() {
            ["audit", "export"] => Some(Self::GlobalAudit),
            ["tenants", s, "export"] => slug(s).map(|slug| Self::TenantConfig { slug }),
            ["tenants", s, "users", "export"] => slug(s).map(|slug| Self::Users { slug }),
            ["tenants", s, "audit", "export"] => slug(s).map(|slug| Self::Audit { slug }),
            _ => None,
        }
    }
}

/// What a ticket stands for.
#[derive(Serialize, Deserialize)]
struct Record {
    dpop: bool,
    token: String,
    path: String,
    query: String,
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("path", &self.path)
            .field("query", &self.query)
            .finish_non_exhaustive()
    }
}

/// A new ticket for one `GET` of `path?query` (an export route; `query`
/// may be empty) as the holder of `token`. Returns the URL to fetch.
pub async fn issue(
    state: &AppState,
    scheme: Scheme,
    token: &str,
    path: &str,
    query: &str,
) -> AppResult<String> {
    if Export::of_path(path).is_none() {
        return Err(AppError::BadRequest(
            "download tickets are for the export routes only".into(),
        ));
    }
    if query.split('&').any(is_ticket_pair) {
        return Err(AppError::BadRequest(format!(
            "the query already carries `{TICKET_PARAM}`"
        )));
    }
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let ticket = URL_SAFE_NO_PAD.encode(bytes);
    let record = Record {
        dpop: scheme == Scheme::Dpop,
        token: token.to_string(),
        path: path.to_string(),
        query: query.to_string(),
    };
    let mut conn = state.redis.get().await?;
    let _: () = conn
        .set_ex(
            keys::download_ticket(&hash(&ticket)),
            serde_json::to_string(&record)?,
            TICKET_TTL_SECS,
        )
        .await?;
    let base = state.config.public_url.as_str().trim_end_matches('/');
    let sep = if query.is_empty() { "" } else { "&" };
    Ok(format!("{base}{path}?{query}{sep}{TICKET_PARAM}={ticket}"))
}

/// The ticket a request carries in its query, if any.
pub fn ticket_of(query: Option<&str>) -> Option<&str> {
    query?
        .split('&')
        .find_map(|pair| pair.strip_prefix(TICKET_PARAM)?.strip_prefix('='))
        .filter(|t| !t.is_empty() && t.len() <= 64)
}

/// Take the ticket for a `GET` of `path?query` (the query including the
/// ticket itself): the token it stands for, and its scheme, when it was
/// issued for exactly this request and has not been used. Used or not, a
/// ticket presented here is gone afterwards.
pub async fn redeem(
    state: &AppState,
    ticket: &str,
    path: &str,
    query: &str,
) -> AppResult<Option<(Scheme, String)>> {
    let mut conn = state.redis.get().await?;
    let raw: Option<String> = conn.get_del(keys::download_ticket(&hash(ticket))).await?;
    let Some(record) = raw.and_then(|r| serde_json::from_str::<Record>(&r).ok()) else {
        return Ok(None);
    };
    let rest: Vec<&str> = query.split('&').filter(|p| !is_ticket_pair(p)).collect();
    if record.path != path || record.query != rest.join("&") || Export::of_path(path).is_none() {
        return Ok(None);
    }
    let scheme = if record.dpop {
        Scheme::Dpop
    } else {
        Scheme::Bearer
    };
    Ok(Some((scheme, record.token)))
}

fn is_ticket_pair(pair: &str) -> bool {
    pair == TICKET_PARAM
        || pair
            .strip_prefix(TICKET_PARAM)
            .is_some_and(|rest| rest.starts_with('='))
}

fn hash(ticket: &str) -> String {
    hex::encode(Sha256::digest(ticket.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_export_routes_take_tickets() {
        assert_eq!(
            Export::of_path("/admin/audit/export"),
            Some(Export::GlobalAudit)
        );
        assert_eq!(
            Export::of_path("/admin/tenants/acme/users/export"),
            Some(Export::Users {
                slug: "acme".into()
            })
        );
        assert_eq!(
            Export::of_path("/admin/tenants/acme/export"),
            Some(Export::TenantConfig {
                slug: "acme".into()
            })
        );
        assert_eq!(
            Export::of_path("/admin/tenants/acme/audit/export"),
            Some(Export::Audit {
                slug: "acme".into()
            })
        );
        for other in [
            "/admin/tenants/acme/users",
            "/admin/tenants/acme/users/export/",
            "/admin/tenants/ACME/users/export",
            "/admin/tenants/../users/export",
            "/admin/tenants/acme/clients/export",
            "/t/acme/admin/audit/export",
            "admin/audit/export",
        ] {
            assert_eq!(Export::of_path(other), None, "{other}");
        }
    }

    #[test]
    fn the_ticket_is_read_from_its_own_parameter() {
        assert_eq!(
            ticket_of(Some("format=csv&download_ticket=abc")),
            Some("abc")
        );
        assert_eq!(ticket_of(Some("download_ticket=abc")), Some("abc"));
        assert_eq!(ticket_of(Some("download_ticketx=abc")), None);
        assert_eq!(ticket_of(Some("download_ticket=")), None);
        assert_eq!(ticket_of(None), None);
        assert!(is_ticket_pair("download_ticket=abc"));
        assert!(!is_ticket_pair("download_tickets=abc"));
    }
}
