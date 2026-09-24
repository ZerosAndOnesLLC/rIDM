//! Cross-site form posts to the browser endpoints (`/authorize`,
//! `/end_session`). The session cookie is `SameSite=Lax`, which a browser
//! leaves off a POST that another site started, so a posted authorization
//! request would never see the user's session, and a posted logout would
//! think nobody was signed in. The post is parked here and the browser sent
//! back to the same endpoint with a GET (`303`), a top-level navigation that
//! carries the cookie; the GET takes the parked form, once. The SAML
//! endpoints do the same with their bindings.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::cache::keys;
use crate::error::AppResult;
use crate::state::AppState;

/// How long a parked form waits for the browser to come back: moments,
/// normally.
const PARKED_TTL_SECS: u64 = 300;

/// The query parameter the GET carries the parked form's id in.
pub const PARKED: &str = "parked";

fn key(tenant_id: Uuid, endpoint: &str, id: Uuid) -> String {
    format!("{}:t:{tenant_id}:oidc_post:{endpoint}:{id}", keys::PREFIX)
}

/// Park `form` (the posted body) and answer `303` to the same endpoint with
/// only `?parked=<id>`. The `Location` is relative, so the browser comes back
/// on the host (a tenant's custom domain or the main one) and path it posted
/// to.
pub async fn park(
    state: &AppState,
    tenant_id: Uuid,
    endpoint: &str,
    form: &str,
) -> AppResult<Response> {
    let id = Uuid::new_v4();
    let mut conn = state.redis.get().await?;
    let _: () = redis::cmd("SET")
        .arg(key(tenant_id, endpoint, id))
        .arg(form)
        .arg("EX")
        .arg(PARKED_TTL_SECS)
        .query_async(&mut conn)
        .await?;
    let location = format!("?{PARKED}={id}");
    let mut res = (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(res)
}

/// The id a GET names, when its query is just `parked=<id>`.
pub fn parked_id(params: &[(String, String)]) -> Option<Option<Uuid>> {
    match params {
        [(k, v)] if k == PARKED => Some(Uuid::parse_str(v).ok()),
        _ => None,
    }
}

/// Take a parked form (once). `None`: unknown, expired or already taken.
pub async fn unpark(
    state: &AppState,
    tenant_id: Uuid,
    endpoint: &str,
    id: Uuid,
) -> AppResult<Option<String>> {
    let mut conn = state.redis.get().await?;
    Ok(redis::cmd("GETDEL")
        .arg(key(tenant_id, endpoint, id))
        .query_async(&mut conn)
        .await?)
}
