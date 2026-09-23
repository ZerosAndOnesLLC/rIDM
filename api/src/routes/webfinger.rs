//! WebFinger issuer discovery (OpenID Connect Discovery 1.0 §2):
//! `GET /.well-known/webfinger?resource=acct:alice@example.com&rel=http://openid.net/specs/connect/1.0/issuer`
//!
//! Resources resolve to a tenant in two ways:
//! * `acct:<user>@<domain>` where `<domain>` is listed in the tenant's
//!   `discovery.email_domains`;
//! * an issuer URL (`{PUBLIC_URL}/t/{slug}`) or any URL underneath it.

use std::time::Duration;

use axum::Router;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Serialize;

use crate::cache::keys as cache_keys;
use crate::error::AppError;
use crate::middleware::{TenantCtx, resolve_tenant};
use crate::repos;
use crate::state::AppState;

pub const OIDC_ISSUER_REL: &str = "http://openid.net/specs/connect/1.0/issuer";
const DOMAIN_CACHE_TTL: Duration = Duration::from_secs(300);

pub fn router() -> Router<AppState> {
    Router::new().route("/.well-known/webfinger", get(webfinger))
}

#[derive(Debug, Default)]
struct Params {
    resource: Option<String>,
    /// May be repeated (RFC 7033 §4.3).
    rel: Vec<String>,
}

impl Params {
    fn parse(raw: Option<&str>) -> Self {
        let mut p = Self::default();
        for (k, v) in url::form_urlencoded::parse(raw.unwrap_or_default().as_bytes()) {
            match &*k {
                "resource" => p.resource = Some(v.into_owned()),
                "rel" => p.rel.push(v.into_owned()),
                _ => {}
            }
        }
        p
    }
}

#[derive(Debug, Serialize)]
struct Jrd {
    subject: String,
    links: Vec<Link>,
}

#[derive(Debug, Serialize)]
struct Link {
    rel: &'static str,
    href: String,
}

async fn webfinger(
    State(state): State<AppState>,
    RawQuery(raw): RawQuery,
) -> Result<Response, AppError> {
    let params = Params::parse(raw.as_deref());
    let resource = params
        .resource
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .ok_or_else(|| AppError::BadRequest("resource is required".into()))?;
    if !params.rel.is_empty() && !params.rel.iter().any(|r| r == OIDC_ISSUER_REL) {
        // We only know the OIDC issuer relation; answer with an empty link set.
        return Ok(jrd_response(Jrd {
            subject: resource.to_string(),
            links: vec![],
        }));
    }

    let tenant = resolve_resource(&state, resource)
        .await?
        .ok_or(AppError::NotFound("resource"))?;
    let issuer = tenant.issuer(&state);
    Ok(jrd_response(Jrd {
        subject: resource.to_string(),
        links: vec![Link {
            rel: OIDC_ISSUER_REL,
            href: issuer,
        }],
    }))
}

fn jrd_response(jrd: Jrd) -> Response {
    let mut res = axum::Json(jrd).into_response();
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/jrd+json; charset=utf-8"),
    );
    res.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    res
}

async fn resolve_resource(state: &AppState, resource: &str) -> Result<Option<TenantCtx>, AppError> {
    // acct:user@domain (also accepts a bare email address).
    let acct = resource.strip_prefix("acct:").unwrap_or(resource);
    if let Some((_, domain)) = acct.rsplit_once('@')
        && !acct.contains("://")
    {
        let domain = domain.trim().to_lowercase();
        if domain.is_empty() {
            return Ok(None);
        }
        let db = state.db.clone();
        let d = domain.clone();
        let tenant = state
            .cache
            .get_or_load(
                &cache_keys::tenant_by_email_domain(&domain),
                DOMAIN_CACHE_TTL,
                || async move { Ok(repos::tenants::find_by_email_domain(db.home(), &d).await?) },
            )
            .await?;
        return Ok(tenant
            .filter(|t| t.is_active())
            .map(|tenant| TenantCtx { tenant }));
    }

    // Issuer URL or something beneath it.
    let base = state.config.public_url.as_str().trim_end_matches('/');
    if let Some(rest) = resource.strip_prefix(base)
        && let Some(rest) = rest.strip_prefix("/t/")
    {
        let slug = rest.split(['/', '?', '#']).next().unwrap_or_default();
        return Ok(resolve_tenant(state, slug)
            .await?
            .filter(|t| t.is_active())
            .map(|tenant| TenantCtx { tenant }));
    }
    Ok(None)
}
