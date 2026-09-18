//! Review finding (Phase 10): the session and trusted-device cookies were
//! `__Host-` prefixed with `Path=/t/{slug}` when `COOKIE_SECURE=true`, which
//! browsers reject (a `__Host-` cookie must have `Path=/`), so no secure
//! deployment kept a session; and on a custom domain the path never matched.
//! The cookies now use `Path=/` and carry the tenant in their name.

use ridm_api::models::NewClient;
use ridm_api::services::{sessions, tenants};

use crate::common::{self, TestApp};
use crate::support::{self, browser, param};

/// Two tenants on one host, one browser: signing in to the second must not
/// replace the first tenant's session.
#[tokio::test]
async fn two_tenants_on_one_host_keep_separate_sessions() {
    let app = TestApp::spawn().await;
    let a = app.tenant.clone();
    let b = common::create_tenant(&app.state.db).await;
    for t in [&a, &b] {
        support::spa(&app, t.id, NewClient::default()).await;
        support::user_with_password(&app, t.id, "alice").await;
    }

    let jar = browser();
    let (_, after_a) = support::password_login(&jar, &app, &a.slug, "alice").await;
    assert_eq!(after_a["stage"], "done", "{after_a}");
    let (_, after_b) = support::password_login(&jar, &app, &b.slug, "alice").await;
    assert_eq!(after_b["stage"], "done", "{after_b}");

    // Both sessions are still usable from the same jar without a new login.
    for t in [&a, &b] {
        let loc = support::authorize(&jar, &app, &t.slug, None, &[("prompt", "none")]).await;
        assert!(
            param(&loc, "code").is_some(),
            "tenant {} lost its session: {loc}",
            t.slug
        );
    }
}

/// With `COOKIE_SECURE` the cookie satisfies the `__Host-` rules: `Secure`,
/// `Path=/`, no `Domain`, and its name names the tenant.
#[tokio::test]
async fn secure_session_cookies_meet_the_host_prefix_rules() {
    let app = TestApp::spawn_configured(axum::Router::new(), |state| {
        let mut config = (*state.config).clone();
        config.cookie_secure = true;
        state.config = std::sync::Arc::new(config);
    })
    .await;
    let tid = app.tenant.id;
    support::spa(&app, tid, NewClient::default()).await;
    support::user_with_password(&app, tid, "alice").await;

    // Drive the password step by hand: a jar would not store a `Secure`
    // cookie received over plain http.
    let http = browser();
    let loc = support::authorize(&http, &app, &app.tenant.slug, None, &[]).await;
    let flow = param(&loc, "flow").unwrap();
    let state: serde_json::Value = http
        .get(app.tenant_url(&format!("/flows/{flow}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let res = http
        .post(app.tenant_url(&format!("/flows/{flow}/password")))
        .json(&serde_json::json!({
            "csrf": state["csrf"],
            "identifier": "alice",
            "password": support::PASSWORD,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let set_cookie = res.headers()["set-cookie"].to_str().unwrap().to_string();
    let name = format!("__Host-ridm_session_{}", app.tenant.slug);
    assert!(set_cookie.starts_with(&format!("{name}=")), "{set_cookie}");
    let attrs: Vec<&str> = set_cookie.split(';').map(str::trim).skip(1).collect();
    assert!(attrs.contains(&"Path=/"), "{set_cookie}");
    assert!(attrs.contains(&"Secure"), "{set_cookie}");
    assert!(
        !attrs
            .iter()
            .any(|a| a.to_ascii_lowercase().starts_with("domain")),
        "{set_cookie}"
    );

    // The server reads it back under that name, and only under that name.
    let tenant = tenants::get(&app.state, tid).await.unwrap();
    assert_eq!(sessions::cookie_name(&app.state, &tenant.slug), name);
    let value = set_cookie.split(';').next().unwrap().to_string();
    let loc = support::authorize(
        &app.http,
        &app,
        &app.tenant.slug,
        Some(&value),
        &[("prompt", "none")],
    )
    .await;
    assert!(param(&loc, "code").is_some(), "{loc}");
    let other = common::create_tenant(&app.state.db).await;
    support::spa(&app, other.id, NewClient::default()).await;
    let loc = support::authorize(
        &app.http,
        &app,
        &other.slug,
        Some(&value),
        &[("prompt", "none")],
    )
    .await;
    assert_eq!(
        param(&loc, "error").as_deref(),
        Some("login_required"),
        "another tenant's cookie is not this tenant's session"
    );
}
