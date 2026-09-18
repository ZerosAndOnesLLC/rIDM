//! Embedded UI mode: the static export of `ui/` served by the API itself, so
//! one process on one origin answers for the sign-in pages, both consoles and
//! the API (working-plan §1, "UI hosting", mode a).
//!
//! A build with the `embedded-ui` feature compiles `ui/out` into the binary
//! ([`EmbeddedUi::from_build`]); it is served when `EMBEDDED_UI` is on (the
//! default) and `UI_URL` is the API's own origin. The pages are the router's
//! fallback, so every API route wins over a file of the same name, and paths
//! under the API's own prefixes (`/t/`, `/admin`, `/scim/`, `/.well-known/`,
//! the probes, metrics and docs) never fall through to the UI: a miss there
//! stays the API's bare `404`.
//!
//! The export is built with `trailingSlash`, so every page is a directory
//! index: `/login/` serves `login/index.html`, `/login` redirects there
//! (`308`, query kept), and anything else answers `404.html` with status 404.
//! Hashed build assets under `/_next/static/` are cached for a year as
//! immutable; everything else is revalidated on each use against a weak
//! `ETag` (the file's SHA-256). Each page carries its own hash-based content
//! security policy in a `<meta>` tag (`ui/scripts/csp.mjs`); a meta policy
//! cannot restrict framing, so the headers sent here do: no page may be
//! framed, except that the login page may be framed by its own origin (the
//! admin console's live branding preview).

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rust_embed::EmbeddedFile;

use crate::config::Config;
use crate::state::AppState;

/// Looks a file of the export up by its path relative to `ui/out`.
pub type Lookup = fn(&str) -> Option<EmbeddedFile>;

/// The UI files a node serves.
#[derive(Clone, Copy)]
pub struct EmbeddedUi {
    get: Lookup,
}

#[cfg(feature = "embedded-ui")]
#[derive(rust_embed::RustEmbed)]
#[folder = "../ui/out"]
#[allow_missing = true]
struct Build;

/// First path segments that belong to the API. A request under one of them
/// that no route matched is the API's 404, never a page.
const API_PREFIXES: &[&str] = &[
    "t",
    "admin",
    "scim",
    ".well-known",
    "healthz",
    "readyz",
    "metrics",
    "docs",
    "openapi.json",
];

/// Header policy for UI responses: framing only. The page's own `<meta>`
/// policy governs everything else, and a header policy would intersect with
/// it (a second `default-src` could only take permissions away).
const UI_CSP: &str = "frame-ancestors 'none'";
/// The login page, which the console's branding preview frames.
const FRAMED_PAGE: &str = "login/index.html";
const FRAMED_CSP: &str = "frame-ancestors 'self'";

const IMMUTABLE: &str = "public, max-age=31536000, immutable";
const REVALIDATE: &str = "no-cache";

impl EmbeddedUi {
    pub const fn new(get: Lookup) -> Self {
        Self { get }
    }

    /// The UI compiled into this binary, when there is one and the
    /// configuration wants it served here.
    pub fn from_build(config: &Config) -> Option<Self> {
        #[cfg(feature = "embedded-ui")]
        {
            if !config.embedded_ui {
                return None;
            }
            let ui = Self::new(Build::get);
            if ui.file("index.html").is_none() {
                tracing::warn!(
                    "built with the embedded-ui feature but without ui/out (run `npm run build` in ui/ first); the UI is not served"
                );
                return None;
            }
            if config.ui_url.origin() != config.public_url.origin() || config.ui_url.path() != "/" {
                tracing::info!(
                    ui_url = %config.ui_url,
                    "UI_URL is not this server's origin; the embedded UI is not served"
                );
                return None;
            }
            Some(ui)
        }
        #[cfg(not(feature = "embedded-ui"))]
        {
            let _ = config;
            None
        }
    }

    fn file(&self, key: &str) -> Option<EmbeddedFile> {
        (self.get)(key)
    }

    /// What `path` (the request path, leading slash included) resolves to.
    pub fn resolve(&self, path: &str) -> Resolved {
        let Some(rel) = path.strip_prefix('/') else {
            return Resolved::NotFound;
        };
        if !is_safe(rel) {
            return Resolved::NotFound;
        }
        if rel.is_empty() || rel.ends_with('/') {
            let key = format!("{rel}index.html");
            return match self.file(&key) {
                Some(file) => Resolved::File { key, file },
                None => Resolved::NotFound,
            };
        }
        if let Some(file) = self.file(rel) {
            return Resolved::File {
                key: rel.to_string(),
                file,
            };
        }
        if self.file(&format!("{rel}/index.html")).is_some() {
            return Resolved::Redirect(format!("/{rel}/"));
        }
        Resolved::NotFound
    }

    /// Does `path` name something the UI serves (a file, or a directory
    /// index with or without its slash)?
    pub fn serves(&self, path: &str) -> bool {
        !matches!(self.resolve(path), Resolved::NotFound)
    }

    /// The response for a GET or HEAD of `path`.
    fn respond(
        &self,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        head: bool,
    ) -> Response {
        match self.resolve(path) {
            Resolved::File { key, file } => {
                file_response(&key, &file, headers, StatusCode::OK, head)
            }
            Resolved::Redirect(to) => {
                let location = match query {
                    Some(q) => format!("{to}?{q}"),
                    None => to,
                };
                let mut res = StatusCode::PERMANENT_REDIRECT.into_response();
                if let Ok(v) = HeaderValue::from_str(&location) {
                    res.headers_mut().insert(header::LOCATION, v);
                }
                res
            }
            Resolved::NotFound => match self.file("404.html") {
                Some(file) => {
                    file_response("404.html", &file, headers, StatusCode::NOT_FOUND, head)
                }
                None => StatusCode::NOT_FOUND.into_response(),
            },
        }
    }
}

/// Outcome of looking a request path up in the export.
pub enum Resolved {
    File {
        key: String,
        file: EmbeddedFile,
    },
    /// A directory asked for without its trailing slash.
    Redirect(String),
    NotFound,
}

/// Only plain relative paths: no empty, `.` or `..` segments, no
/// backslashes and nothing percent-encoded (the export's file names never
/// need escaping, and the lookup must not see a decoded `..`).
fn is_safe(rel: &str) -> bool {
    if rel.contains(['\\', '%', '\0']) {
        return false;
    }
    let trimmed = rel.strip_suffix('/').unwrap_or(rel);
    trimmed.is_empty()
        || trimmed
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Is `path` under one of the API's own prefixes?
pub fn is_api_path(path: &str) -> bool {
    let first = path
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or_default();
    API_PREFIXES.contains(&first)
}

fn file_response(
    key: &str,
    file: &EmbeddedFile,
    headers: &HeaderMap,
    status: StatusCode,
    head: bool,
) -> Response {
    let etag = format!(
        "W/\"{}\"",
        URL_SAFE_NO_PAD.encode(file.metadata.sha256_hash())
    );
    let cache = if key.starts_with("_next/static/") {
        IMMUTABLE
    } else {
        REVALIDATE
    };
    let fresh = status == StatusCode::OK
        && headers
            .get_all(header::IF_NONE_MATCH)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .any(|tag| tag == "*" || weak_eq(tag, &etag));
    let (status, body) = if fresh {
        (StatusCode::NOT_MODIFIED, Body::empty())
    } else if head {
        (status, Body::empty())
    } else {
        (status, Body::from(file.data.clone()))
    };
    let mut res = Response::new(body);
    *res.status_mut() = status;
    let h = res.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    if !fresh {
        if let Ok(v) = HeaderValue::from_str(&content_type(file.metadata.mimetype())) {
            h.insert(header::CONTENT_TYPE, v);
        }
        if head {
            h.insert(header::CONTENT_LENGTH, HeaderValue::from(file.data.len()));
        }
    }
    let (csp, frame) = if key == FRAMED_PAGE {
        (FRAMED_CSP, "SAMEORIGIN")
    } else {
        (UI_CSP, "DENY")
    };
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(csp),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static(frame));
    res
}

/// The export is UTF-8 throughout; say so for text types.
fn content_type(mime: &str) -> String {
    let text =
        mime.starts_with("text/") || mime == "application/javascript" || mime == "application/json";
    if text && !mime.contains("charset") {
        format!("{mime}; charset=utf-8")
    } else {
        mime.to_string()
    }
}

/// Weak comparison (RFC 9110 §8.8.3.2): the opaque tags match, `W/` aside.
fn weak_eq(a: &str, b: &str) -> bool {
    a.trim_start_matches("W/") == b.trim_start_matches("W/")
}

/// Router fallback: a page of the UI, or the API's bare 404.
pub async fn fallback(State(state): State<AppState>, req: Request) -> Response {
    let Some(ui) = state.ui else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let head = req.method() == Method::HEAD;
    if !(head || req.method() == Method::GET) || is_api_path(req.uri().path()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    ui.respond(req.uri().path(), req.uri().query(), req.headers(), head)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_relative_paths_are_looked_up() {
        for ok in [
            "",
            "login/",
            "_next/static/chunks/a-1.js",
            "404.html",
            "console/users/",
        ] {
            assert!(is_safe(ok), "{ok}");
        }
        for bad in [
            "../Cargo.toml",
            "login/../../x",
            "./index.html",
            "a//b",
            "/etc/passwd",
            "a\\b",
            "%2e%2e/x",
            "login/.",
        ] {
            assert!(!is_safe(bad), "{bad}");
        }
    }

    #[test]
    fn api_prefixes_never_reach_the_ui() {
        for p in [
            "/t/acme/nope",
            "/admin",
            "/admin/x",
            "/scim/v2/a",
            "/.well-known/x",
            "/metrics",
            "/docs/",
            "/openapi.json",
            "/healthz",
        ] {
            assert!(is_api_path(p), "{p}");
        }
        for p in [
            "/",
            "/login/",
            "/console/",
            "/account/",
            "/_next/static/x.js",
            "/tenants/",
            "/administrator/",
        ] {
            assert!(!is_api_path(p), "{p}");
        }
    }

    #[test]
    fn weak_and_strong_tags_compare_by_value() {
        assert!(weak_eq("\"abc\"", "W/\"abc\""));
        assert!(weak_eq("W/\"abc\"", "W/\"abc\""));
        assert!(!weak_eq("W/\"abd\"", "W/\"abc\""));
    }
}
