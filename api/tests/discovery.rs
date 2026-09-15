mod common;

use common::TestApp;
use ridm_api::models::{KeyStatus, RsaBits, SigningAlg, TenantSettings};
use ridm_api::routes::webfinger::OIDC_ISSUER_REL;
use ridm_api::services::keys;
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_core::events::Actor;

#[tokio::test]
async fn jwks_is_created_lazily_cached_with_etag_and_invalidated_on_rotation() {
    let app = TestApp::spawn().await;
    let url = app.tenant_url("/.well-known/jwks.json");

    // No keys yet: first fetch creates the tenant's initial key.
    assert!(
        keys::list(&app.state, app.tenant.id, None)
            .await
            .unwrap()
            .is_empty()
    );
    let res = app.http.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["content-type"], "application/jwk-set+json");
    assert!(
        res.headers()["cache-control"]
            .to_str()
            .unwrap()
            .contains("max-age=300")
    );
    let etag = res.headers()["etag"].to_str().unwrap().to_string();
    assert!(etag.starts_with('"') && etag.ends_with('"'));
    let body: serde_json::Value = res.json().await.unwrap();
    let keys_arr = body["keys"].as_array().unwrap();
    assert_eq!(keys_arr.len(), 1);
    assert_eq!(keys_arr[0]["kty"], "RSA", "default policy is RS256");
    assert_eq!(keys_arr[0]["use"], "sig");
    assert!(keys_arr[0].get("d").is_none());

    // Conditional request → 304 with the same ETag.
    let res = app
        .http
        .get(&url)
        .header("If-None-Match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 304);
    assert_eq!(res.headers()["etag"].to_str().unwrap(), etag);

    // Rotation changes the document (new key + retiring old one) and the ETag.
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    keys::rotate(
        &app.state,
        app.tenant.id,
        &tenant.settings.keys,
        Actor::System,
    )
    .await
    .unwrap();
    let res = app
        .http
        .get(&url)
        .header("If-None-Match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "cache must be invalidated by rotation");
    let new_etag = res.headers()["etag"].to_str().unwrap().to_string();
    assert_ne!(new_etag, etag);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(
        body["keys"].as_array().unwrap().len(),
        2,
        "active + retiring are published"
    );

    // Revoked keys disappear.
    for k in keys::list(&app.state, app.tenant.id, Some(KeyStatus::Retiring))
        .await
        .unwrap()
    {
        keys::revoke(&app.state, app.tenant.id, Actor::System, k.id)
            .await
            .unwrap();
    }
    let body: serde_json::Value = app
        .http
        .get(&url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["keys"].as_array().unwrap().len(), 1);

    // Unknown tenant → 404.
    let res = app
        .http
        .get(app.url("/t/nope-nope/.well-known/jwks.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test]
async fn jwks_lists_every_published_algorithm() {
    let app = TestApp::spawn().await;
    for alg in [SigningAlg::ES256, SigningAlg::EdDSA] {
        keys::create(
            &app.state,
            app.tenant.id,
            Actor::System,
            alg,
            RsaBits::B2048,
            KeyStatus::Active,
            None,
        )
        .await
        .unwrap();
    }
    let body: serde_json::Value = app
        .http
        .get(app.tenant_url("/.well-known/jwks.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ktys: Vec<&str> = body["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kty"].as_str().unwrap())
        .collect();
    assert!(ktys.contains(&"EC") && ktys.contains(&"OKP"), "{ktys:?}");
}

#[tokio::test]
async fn webfinger_resolves_issuer_by_email_domain_and_issuer_url() {
    let app = TestApp::spawn().await;
    let issuer = format!("{}/t/{}", app.base_url, app.tenant.slug);
    let domain = format!("{}.example", app.tenant.slug);
    let settings = TenantSettings {
        discovery: ridm_api::models::DiscoverySettings {
            email_domains: vec![domain.clone()],
        },
        ..Default::default()
    };
    tenants::update(
        &app.state,
        Actor::System,
        app.tenant.id,
        TenantUpdate {
            settings: Some(settings),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let wf = |resource: String, rel: Option<&str>| {
        let http = app.http.clone();
        let url = app.url("/.well-known/webfinger");
        let rel = rel.map(str::to_string);
        async move {
            let mut q = vec![("resource", resource)];
            if let Some(r) = rel {
                q.push(("rel", r));
            }
            http.get(url).query(&q).send().await.unwrap()
        }
    };

    // acct: by email domain.
    let res = wf(
        format!("acct:alice@{}", domain.to_uppercase()),
        Some(OIDC_ISSUER_REL),
    )
    .await;
    assert_eq!(res.status(), 200);
    assert!(
        res.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("application/jrd+json")
    );
    let jrd: serde_json::Value = res.json().await.unwrap();
    assert_eq!(
        jrd["subject"],
        format!("acct:alice@{}", domain.to_uppercase())
    );
    assert_eq!(jrd["links"][0]["rel"], OIDC_ISSUER_REL);
    assert_eq!(jrd["links"][0]["href"], issuer);

    // Bare email and issuer URL forms.
    let jrd: serde_json::Value = wf(format!("alice@{domain}"), None)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(jrd["links"][0]["href"], issuer);
    let jrd: serde_json::Value = wf(format!("{issuer}/anything?x=1"), None)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(jrd["links"][0]["href"], issuer);

    // Unknown rel → empty links; unknown domain → 404; missing resource → 400.
    let jrd: serde_json::Value = wf(
        format!("acct:alice@{domain}"),
        Some("http://example.com/other"),
    )
    .await
    .json()
    .await
    .unwrap();
    assert!(jrd["links"].as_array().unwrap().is_empty());
    assert_eq!(
        wf("acct:alice@unknown.invalid".into(), None).await.status(),
        404
    );
    assert_eq!(
        wf(format!("{}/t/ghost", app.base_url), None).await.status(),
        404
    );
    assert_eq!(
        app.http
            .get(app.url("/.well-known/webfinger"))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );

    // Removing the domain invalidates the cached lookup.
    tenants::update(
        &app.state,
        Actor::System,
        app.tenant.id,
        TenantUpdate {
            settings: Some(TenantSettings::default()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(wf(format!("acct:alice@{domain}"), None).await.status(), 404);
}
