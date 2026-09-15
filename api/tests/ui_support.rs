mod common;

use common::TestApp;
use ridm_api::models::{AuthMethods, Branding, BrandingLink, LocaleSettings, TenantSettings};
use ridm_api::services::tenants::{self, TenantUpdate};
use ridm_core::events::Actor;
use serde_json::{Value, json};

#[tokio::test]
async fn branding_document_is_public_and_cacheable() {
    let app = TestApp::spawn().await;
    tenants::update(
        &app.state,
        Actor::System,
        app.tenant.id,
        TenantUpdate {
            settings: Some(TenantSettings {
                branding: Branding {
                    logo_url: Some("https://cdn.example/logo.svg".into()),
                    primary_color: Some("#0f6e6e".into()),
                    custom_css: Some(".card{border-radius:0}".into()),
                    links: vec![BrandingLink {
                        label: "Help".into(),
                        url: "https://help.example".into(),
                    }],
                    ..Default::default()
                },
                locale: LocaleSettings {
                    default: "de".into(),
                    supported: vec!["de".into(), "en".into()],
                },
                auth: AuthMethods {
                    password: true,
                    magic_link: true,
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let res = app
        .http
        .get(app.tenant_url("/branding"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["cache-control"], "public, max-age=60");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["slug"], app.tenant.slug);
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    assert_eq!(body["display_name"], tenant.display_name);
    assert_eq!(body["branding"]["logo_url"], "https://cdn.example/logo.svg");
    assert_eq!(body["branding"]["primary_color"], "#0f6e6e");
    assert_eq!(body["branding"]["custom_css"], ".card{border-radius:0}");
    assert_eq!(body["branding"]["links"][0]["label"], "Help");
    assert_eq!(
        body["locale"],
        json!({"default": "de", "supported": ["de", "en"]})
    );
    assert_eq!(body["methods"], json!(["password", "magic_link"]));
    assert_eq!(body["registration"]["enabled"], false);
    // Nothing beyond the public surface leaks.
    let mut keys: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "branding",
            "display_name",
            "locale",
            "methods",
            "registration",
            "slug"
        ]
    );

    let res = app
        .http
        .get(format!("{}/t/nope/branding", app.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}
