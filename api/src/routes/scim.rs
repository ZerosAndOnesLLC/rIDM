//! SCIM 2.0 provisioning API: `/scim/v2/{slug}/...` (RFC 7644).
//!
//! Every request carries a provisioning token (`Authorization: Bearer
//! rscim_...`) minted for the tenant in the path; anything else is a SCIM
//! error document. Bodies and responses use `application/scim+json`.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use ridm_core::events::Actor;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::middleware::resolve_tenant;
use crate::models::{ScimToken, Tenant};
use crate::services::scim::{self, PageQuery, ScimError, ScimResult, scim_json};
use crate::services::scim_tokens;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/scim/v2/{slug}/ServiceProviderConfig",
            get(service_provider_config),
        )
        .route("/scim/v2/{slug}/ResourceTypes", get(resource_types))
        .route("/scim/v2/{slug}/Schemas", get(schemas))
        .route("/scim/v2/{slug}/Users", get(list_users).post(create_user))
        .route(
            "/scim/v2/{slug}/Users/{id}",
            get(get_user)
                .put(put_user)
                .patch(patch_user)
                .delete(delete_user),
        )
        .route(
            "/scim/v2/{slug}/Groups",
            get(list_groups).post(create_group),
        )
        .route(
            "/scim/v2/{slug}/Groups/{id}",
            get(get_group)
                .put(put_group)
                .patch(patch_group)
                .delete(delete_group),
        )
}

/// The tenant a provisioning token addresses, with the token itself.
pub struct ScimCtx {
    pub tenant: std::sync::Arc<Tenant>,
    pub token: ScimToken,
}

impl ScimCtx {
    pub fn base(&self, state: &AppState) -> String {
        scim_tokens::base_url(state, &self.tenant.slug)
    }

    /// Changes are attributed to the token (audit shows `client` = token id).
    pub fn actor(&self) -> Actor {
        Actor::Client { id: self.token.id }
    }
}

#[derive(Deserialize)]
struct SlugPath {
    slug: String,
}

fn unauthorized(detail: &str) -> Response {
    let mut res = ScimError::new(StatusCode::UNAUTHORIZED, None, detail).into_response();
    res.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"scim\""),
    );
    res
}

impl FromRequestParts<AppState> for ScimCtx {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let Path(SlugPath { slug }) = Path::<SlugPath>::from_request_parts(parts, state)
            .await
            .map_err(|_| ScimError::not_found("tenant").into_response())?;
        let tenant = resolve_tenant(state, &slug)
            .await
            .map_err(|e| ScimError::from(e).into_response())?
            .ok_or_else(|| ScimError::not_found("tenant").into_response())?;
        if !tenant.is_active() {
            return Err(
                ScimError::new(StatusCode::FORBIDDEN, None, "tenant is disabled").into_response(),
            );
        }
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, t)| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .ok_or_else(|| unauthorized("a provisioning bearer token is required"))?;
        let auth = scim_tokens::authenticate(state, &token)
            .await
            .map_err(|e| ScimError::from(e).into_response())?
            .ok_or_else(|| unauthorized("the provisioning token is invalid, expired or revoked"))?;
        if auth.tenant.id != tenant.id {
            return Err(unauthorized(
                "the provisioning token belongs to another tenant",
            ));
        }
        Ok(Self {
            tenant,
            token: auth.token,
        })
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ListParams {
    filter: Option<String>,
    #[serde(rename = "startIndex")]
    start_index: Option<i64>,
    count: Option<i64>,
    #[serde(rename = "excludedAttributes")]
    excluded_attributes: Option<String>,
}

#[derive(Deserialize)]
struct GetParams {
    #[serde(rename = "excludedAttributes")]
    excluded_attributes: Option<String>,
}

#[derive(Deserialize)]
struct IdPath {
    id: Uuid,
}

fn body_json(bytes: &Bytes) -> ScimResult<Value> {
    if bytes.is_empty() {
        return Err(ScimError::bad("invalidSyntax", "a JSON body is required"));
    }
    serde_json::from_slice::<Value>(bytes)
        .map_err(|e| ScimError::bad("invalidSyntax", format!("malformed JSON: {e}")))
        .and_then(|v| {
            v.is_object()
                .then_some(v)
                .ok_or_else(|| ScimError::bad("invalidSyntax", "the body must be an object"))
        })
}

fn ok(doc: Value) -> Response {
    scim_json(StatusCode::OK, &doc)
}

fn created(doc: Value) -> Response {
    let mut res = scim_json(StatusCode::CREATED, &doc);
    if let Some(loc) = doc["meta"]["location"].as_str()
        && let Ok(v) = HeaderValue::from_str(loc)
    {
        res.headers_mut().insert(header::LOCATION, v);
    }
    res
}

fn respond(r: ScimResult<Response>) -> Response {
    match r {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

// --- discovery ---------------------------------------------------------------

async fn service_provider_config(State(state): State<AppState>, ctx: ScimCtx) -> Response {
    ok(scim::service_provider_config(&ctx.base(&state)))
}

async fn resource_types(State(state): State<AppState>, ctx: ScimCtx) -> Response {
    ok(scim::resource_types(&ctx.base(&state)))
}

async fn schemas(State(state): State<AppState>, ctx: ScimCtx) -> Response {
    ok(scim::schemas(&ctx.base(&state)))
}

// --- users -------------------------------------------------------------------

async fn list_users(
    State(state): State<AppState>,
    ctx: ScimCtx,
    Query(p): Query<ListParams>,
) -> Response {
    respond(
        async {
            let q = PageQuery::new(p.filter, p.start_index, p.count)?;
            let page = scim::list_users(&state, &ctx.tenant, &ctx.base(&state), q).await?;
            Ok(scim_json(StatusCode::OK, &page))
        }
        .await,
    )
}

async fn create_user(State(state): State<AppState>, ctx: ScimCtx, body: Bytes) -> Response {
    respond(
        async {
            let doc = body_json(&body)?;
            let out = scim::create_user(&state, &ctx.tenant, &ctx.base(&state), ctx.actor(), &doc)
                .await?;
            Ok(created(out))
        }
        .await,
    )
}

async fn get_user(
    State(state): State<AppState>,
    ctx: ScimCtx,
    Path(IdPath { id }): Path<IdPath>,
) -> Response {
    respond(
        async {
            Ok(ok(scim::get_user(
                &state,
                &ctx.tenant,
                &ctx.base(&state),
                id,
            )
            .await?))
        }
        .await,
    )
}

async fn put_user(
    State(state): State<AppState>,
    ctx: ScimCtx,
    Path(IdPath { id }): Path<IdPath>,
    body: Bytes,
) -> Response {
    respond(
        async {
            let doc = body_json(&body)?;
            Ok(ok(scim::replace_user(
                &state,
                &ctx.tenant,
                &ctx.base(&state),
                ctx.actor(),
                id,
                &doc,
            )
            .await?))
        }
        .await,
    )
}

async fn patch_user(
    State(state): State<AppState>,
    ctx: ScimCtx,
    Path(IdPath { id }): Path<IdPath>,
    body: Bytes,
) -> Response {
    respond(
        async {
            let ops = scim::parse_patch(&body_json(&body)?)?;
            let base = ctx.base(&state);
            let current = scim::get_user(&state, &ctx.tenant, &base, id).await?;
            let patched = scim::apply_patch(&current, &ops)?;
            Ok(ok(scim::replace_user(
                &state,
                &ctx.tenant,
                &base,
                ctx.actor(),
                id,
                &patched,
            )
            .await?))
        }
        .await,
    )
}

async fn delete_user(
    State(state): State<AppState>,
    ctx: ScimCtx,
    Path(IdPath { id }): Path<IdPath>,
) -> Response {
    respond(
        async {
            scim::delete_user(&state, &ctx.tenant, ctx.actor(), id).await?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}

// --- groups ------------------------------------------------------------------

async fn list_groups(
    State(state): State<AppState>,
    ctx: ScimCtx,
    Query(p): Query<ListParams>,
) -> Response {
    respond(
        async {
            let q = PageQuery::new(p.filter, p.start_index, p.count)?;
            let exclude = scim::excludes_members(p.excluded_attributes.as_deref());
            let page =
                scim::list_groups(&state, &ctx.tenant, &ctx.base(&state), q, exclude).await?;
            Ok(scim_json(StatusCode::OK, &page))
        }
        .await,
    )
}

async fn create_group(State(state): State<AppState>, ctx: ScimCtx, body: Bytes) -> Response {
    respond(
        async {
            let doc = body_json(&body)?;
            Ok(created(
                scim::create_group(&state, &ctx.tenant, &ctx.base(&state), ctx.actor(), &doc)
                    .await?,
            ))
        }
        .await,
    )
}

async fn get_group(
    State(state): State<AppState>,
    ctx: ScimCtx,
    Path(IdPath { id }): Path<IdPath>,
    Query(p): Query<GetParams>,
) -> Response {
    respond(
        async {
            Ok(ok(scim::get_group(
                &state,
                &ctx.tenant,
                &ctx.base(&state),
                id,
                scim::excludes_members(p.excluded_attributes.as_deref()),
            )
            .await?))
        }
        .await,
    )
}

async fn put_group(
    State(state): State<AppState>,
    ctx: ScimCtx,
    Path(IdPath { id }): Path<IdPath>,
    body: Bytes,
) -> Response {
    respond(
        async {
            let doc = body_json(&body)?;
            Ok(ok(scim::replace_group(
                &state,
                &ctx.tenant,
                &ctx.base(&state),
                ctx.actor(),
                id,
                &doc,
            )
            .await?))
        }
        .await,
    )
}

async fn patch_group(
    State(state): State<AppState>,
    ctx: ScimCtx,
    Path(IdPath { id }): Path<IdPath>,
    body: Bytes,
) -> Response {
    respond(
        async {
            let ops = scim::parse_patch(&body_json(&body)?)?;
            let base = ctx.base(&state);
            let current = scim::get_group(&state, &ctx.tenant, &base, id, false).await?;
            let patched = scim::apply_patch(&current, &ops)?;
            Ok(ok(scim::replace_group(
                &state,
                &ctx.tenant,
                &base,
                ctx.actor(),
                id,
                &patched,
            )
            .await?))
        }
        .await,
    )
}

async fn delete_group(
    State(state): State<AppState>,
    ctx: ScimCtx,
    Path(IdPath { id }): Path<IdPath>,
) -> Response {
    respond(
        async {
            scim::delete_group(&state, &ctx.tenant, ctx.actor(), id).await?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        .await,
    )
}
