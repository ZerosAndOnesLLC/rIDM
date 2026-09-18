//! Review finding (Phase 10): a tenant's custom domain mapped only paths no
//! route matched, so everything with a route of its own — the admin API,
//! `/scim`, `/metrics`, `/docs`, `/openapi.json`, and every OTHER tenant's
//! `/t/{slug}/…` — answered on the tenant's host as well. A custom domain now
//! serves its tenant and the host-wide probes, nothing else.

use ridm_api::models::TenantSettings;
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_core::events::Actor;

use crate::common::{self, TestApp};

async fn get_on(app: &TestApp, host: &str, path: &str) -> u16 {
    app.http
        .get(app.url(path))
        .header("host", host)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn a_custom_domain_serves_only_its_own_tenant() {
    let app = TestApp::spawn().await;
    let host = format!("login-{}.acme.test", &app.tenant.slug[2..]);
    let current = tenants::get(&app.state, app.tenant.id).await.unwrap();
    tenants::update(
        &app.state,
        Actor::System,
        app.tenant.id,
        TenantUpdate {
            settings: Some(TenantSettings {
                custom_domain: Some(host.clone()),
                ..current.settings.0.clone()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let own = app.tenant.slug.clone();
    let other = common::create_tenant(&app.state.db).await;

    // What the tenant serves there keeps working.
    for path in [
        "/.well-known/openid-configuration".to_string(),
        "/.well-known/jwks.json".to_string(),
        "/branding".to_string(),
        "/healthz".to_string(),
        format!("/t/{own}/.well-known/openid-configuration"),
    ] {
        assert_eq!(get_on(&app, &host, &path).await, 200, "{path}");
    }

    // Nothing else answers on the tenant's host.
    for path in [
        format!("/t/{}/.well-known/openid-configuration", other.slug),
        format!("/t/{}/.well-known/jwks.json", other.slug),
        format!("/scim/v2/{}/ServiceProviderConfig", other.slug),
        "/admin/tenants".to_string(),
        format!("/admin/tenants/{own}"),
        "/metrics".to_string(),
        "/docs/".to_string(),
        "/openapi.json".to_string(),
    ] {
        assert_eq!(get_on(&app, &host, &path).await, 404, "{path} on {host}");
    }

    // The primary host is unchanged.
    let primary = url::Url::parse(&app.base_url).unwrap();
    let primary = format!(
        "{}:{}",
        primary.host_str().unwrap(),
        primary.port().unwrap()
    );
    for path in [
        format!("/t/{}/.well-known/openid-configuration", other.slug),
        "/openapi.json".to_string(),
    ] {
        assert_eq!(get_on(&app, &primary, &path).await, 200, "{path}");
    }
    assert_eq!(get_on(&app, &primary, "/admin/tenants").await, 401);
}
