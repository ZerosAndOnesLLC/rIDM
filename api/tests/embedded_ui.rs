//! Embedded UI mode (`routes::ui`): pages served as the router's fallback
//! from a fixture export, with the trailing-slash redirect, the export's own
//! 404 page, caching and revalidation, compression, and the API keeping every
//! path of its own.

mod common;

use common::TestApp;
use ridm_api::routes::ui::EmbeddedUi;

#[derive(rust_embed::RustEmbed)]
#[folder = "tests/fixtures/ui"]
struct Fixture;

async fn spawn() -> TestApp {
    TestApp::spawn_configured(axum::Router::new(), |state| {
        state.ui = Some(EmbeddedUi::new(Fixture::get));
    })
    .await
}

fn header<'a>(res: &'a reqwest::Response, name: &str) -> &'a str {
    res.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
}

#[tokio::test]
async fn pages_are_served_as_directory_indexes() {
    let app = spawn().await;
    for (path, text) in [("/", "home"), ("/console/", "console page")] {
        let res = app.http.get(app.url(path)).send().await.unwrap();
        assert_eq!(res.status(), 200, "{path}");
        assert!(
            header(&res, "content-type").starts_with("text/html"),
            "{path}"
        );
        assert_eq!(header(&res, "cache-control"), "no-cache", "{path}");
        // The page's <meta> policy governs the rest; the header only forbids framing.
        assert_eq!(
            header(&res, "content-security-policy"),
            "frame-ancestors 'none'"
        );
        assert_eq!(header(&res, "x-frame-options"), "DENY");
        assert_eq!(header(&res, "x-content-type-options"), "nosniff");
        assert!(header(&res, "etag").starts_with("W/\""), "{path}");
        assert!(res.text().await.unwrap().contains(text), "{path}");
    }
    // Only the login page may be framed, and only by its own origin: the
    // console's branding preview shows it in an iframe.
    for path in ["/login/", "/login/?flow=abc"] {
        let res = app.http.get(app.url(path)).send().await.unwrap();
        assert_eq!(res.status(), 200, "{path}");
        assert_eq!(header(&res, "content-type"), "text/html; charset=utf-8");
        assert_eq!(
            header(&res, "content-security-policy"),
            "frame-ancestors 'self'"
        );
        assert_eq!(header(&res, "x-frame-options"), "SAMEORIGIN");
        assert!(res.text().await.unwrap().contains("login page"), "{path}");
    }
    // Client-side navigation fetches the pages' payloads beside them.
    let res = app
        .http
        .get(app.url("/login/index.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert!(header(&res, "content-type").starts_with("text/plain"));
}

#[tokio::test]
async fn a_page_without_its_slash_redirects_keeping_the_query() {
    let app = spawn().await;
    let res = app
        .http
        .get(app.url("/login?flow=abc&tenant=acme"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 308);
    assert_eq!(header(&res, "location"), "/login/?flow=abc&tenant=acme");
    let res = app.http.get(app.url("/console")).send().await.unwrap();
    assert_eq!(res.status(), 308);
    assert_eq!(header(&res, "location"), "/console/");
}

#[tokio::test]
async fn unknown_paths_get_the_exports_404_page() {
    let app = spawn().await;
    for path in ["/nope/", "/nope", "/login/missing.js", "/_next/static/"] {
        let res = app.http.get(app.url(path)).send().await.unwrap();
        assert_eq!(res.status(), 404, "{path}");
        assert!(
            header(&res, "content-type").starts_with("text/html"),
            "{path}"
        );
        assert!(
            res.text().await.unwrap().contains("page not found"),
            "{path}"
        );
    }
}

#[tokio::test]
async fn the_api_keeps_its_own_paths() {
    let app = spawn().await;
    assert_eq!(
        app.http
            .get(app.url("/healthz"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let discovery = app
        .http
        .get(app.tenant_url("/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap();
    assert_eq!(discovery.status(), 200);
    assert!(header(&discovery, "content-type").starts_with("application/json"));
    // A miss under an API prefix is the API's bare 404, not a page.
    for path in [
        format!("/t/{}/nope", app.tenant.slug),
        "/t/nope".to_string(),
        "/admin/nope".to_string(),
        "/scim/v2/nope".to_string(),
        "/.well-known/nope".to_string(),
    ] {
        let res = app.http.get(app.url(&path)).send().await.unwrap();
        assert_eq!(res.status(), 404, "{path}");
        assert!(
            !header(&res, "content-type").starts_with("text/html"),
            "{path}"
        );
        assert!(
            !res.text().await.unwrap().contains("page not found"),
            "{path}"
        );
    }
    // Only GET and HEAD reach the pages.
    let res = app.http.post(app.url("/login/")).send().await.unwrap();
    assert_eq!(res.status(), 404);
    assert!(res.text().await.unwrap().is_empty());
}

#[tokio::test]
async fn build_assets_are_immutable_and_pages_revalidate() {
    let app = spawn().await;
    let res = app
        .http
        .get(app.url("/_next/static/chunks/app-3f9a.js"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert!(header(&res, "content-type").contains("javascript"));
    assert_eq!(
        header(&res, "cache-control"),
        "public, max-age=31536000, immutable"
    );

    let page = app.http.get(app.url("/login/")).send().await.unwrap();
    let etag = header(&page, "etag").to_string();
    let res = app
        .http
        .get(app.url("/login/"))
        .header("if-none-match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 304);
    assert_eq!(header(&res, "etag"), etag);
    assert!(res.bytes().await.unwrap().is_empty());
    // A strong form of the same tag matches too (weak comparison), another does not.
    let strong = etag.trim_start_matches("W/");
    let res = app
        .http
        .get(app.url("/login/"))
        .header("if-none-match", format!("\"other\", {strong}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 304);
    let res = app
        .http
        .get(app.url("/console/"))
        .header("if-none-match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn text_is_compressed_when_the_client_accepts_it() {
    let app = spawn().await;
    let res = app
        .http
        .get(app.url("/_next/static/chunks/app-3f9a.js"))
        .header("accept-encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(header(&res, "content-encoding"), "gzip");
    assert!(
        header(&res, "vary")
            .to_ascii_lowercase()
            .contains("accept-encoding")
    );
}

#[tokio::test]
async fn head_answers_without_a_body() {
    let app = spawn().await;
    let res = app.http.head(app.url("/login/")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert!(header(&res, "content-type").starts_with("text/html"));
    assert!(header(&res, "content-length").parse::<usize>().unwrap() > 0);
}

#[tokio::test]
async fn nothing_outside_the_export_is_reachable() {
    let app = spawn().await;
    for path in [
        "/..%2f..%2fCargo.toml",
        "/login/..%2f..%2f..%2fCargo.toml",
        "/%2e%2e/%2e%2e/Cargo.toml",
        "/login/.%2e/.%2e/Cargo.toml",
    ] {
        let res = app.http.get(app.url(path)).send().await.unwrap();
        assert_eq!(res.status(), 404, "{path}");
        assert!(!res.text().await.unwrap().contains("[package]"), "{path}");
    }
}

#[tokio::test]
async fn without_an_embedded_ui_the_fallback_is_a_bare_404() {
    let app = TestApp::spawn().await;
    for path in ["/", "/login/", "/console/"] {
        let res = app.http.get(app.url(path)).send().await.unwrap();
        assert_eq!(res.status(), 404, "{path}");
        assert!(res.text().await.unwrap().is_empty(), "{path}");
    }
}
