//! Phase 5.12: the OpenAPI document is derived from the admin routers, served
//! at `/openapi.json`, and the committed `api/openapi.json` (the source of the
//! generated TypeScript client) matches what the binary produces.

mod common;

use common::TestApp;
use serde_json::Value;

const METHODS: [&str; 5] = ["get", "post", "put", "patch", "delete"];

#[tokio::test]
async fn openapi_document_is_served_and_complete() {
    let app = TestApp::spawn().await;
    let res = app.http.get(app.url("/openapi.json")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let doc: Value = res.json().await.unwrap();
    assert_eq!(doc["openapi"].as_str().unwrap()[..2], *"3.");
    assert_eq!(doc["info"]["title"], "rIDM Admin API");
    assert!(doc["components"]["securitySchemes"]["bearer"].is_object());

    let paths = doc["paths"].as_object().unwrap();
    for must in [
        "/admin/me",
        "/admin/permissions",
        "/admin/tenants",
        "/admin/tenants/{slug}",
        "/admin/tenants/{slug}/export",
        "/admin/tenants/{slug}/import",
        "/admin/tenants/{slug}/clients/{client}/secrets",
        "/admin/tenants/{slug}/users/import",
        "/admin/tenants/{slug}/users/{user}/roles/{role_id}",
        "/admin/tenants/{slug}/groups/{group}/members/{user_id}",
        "/admin/tenants/{slug}/roles/{role}/permissions/{permission_id}",
        "/admin/tenants/{slug}/resource-servers/{rs}/permissions",
        "/admin/tenants/{slug}/scopes/{scope}",
        "/admin/tenants/{slug}/claim-mappers/{mapper}",
        "/admin/tenants/{slug}/keys/rotate",
        "/admin/master-key/rotate",
        "/admin/tenants/{slug}/invitations/{invitation}/resend",
        "/admin/tenants/{slug}/messaging/templates/{channel}/{event}/{locale}",
        "/admin/tenants/{slug}/audit/verify",
        "/admin/audit",
        "/admin/tenants/{slug}/webhooks/{webhook}/deliveries/{delivery}/redeliver",
        "/admin/tenants/{slug}/ip-rules/{rule}",
    ] {
        assert!(paths.contains_key(must), "{must} missing from the document");
    }
    assert!(paths.len() >= 85, "{} paths", paths.len());

    // Every operation is tagged, secured, uniquely identified (generated
    // clients key on the id) and documents the auth failures.
    let mut operations = 0;
    let mut ids = std::collections::HashSet::new();
    for (path, item) in paths {
        for m in METHODS {
            let Some(op) = item.get(m) else { continue };
            operations += 1;
            let id = op["operationId"].as_str().unwrap_or_default();
            assert!(
                !id.is_empty() && ids.insert(id.to_string()),
                "{m} {path}: operationId `{id}` missing or duplicated"
            );
            assert!(
                op["tags"].as_array().is_some_and(|t| !t.is_empty()),
                "{m} {path} has no tag"
            );
            assert!(op["security"].is_array(), "{m} {path} has no security");
            let responses = op["responses"].as_object().unwrap();
            assert!(responses.contains_key("401"), "{m} {path} lacks 401");
            assert!(
                responses.keys().any(|k| k.starts_with('2')),
                "{m} {path} lacks a success response"
            );
        }
    }
    assert!(operations >= 130, "{operations} operations");

    // Path parameters are all declared.
    for (path, item) in paths {
        let placeholders: Vec<&str> = path
            .split('/')
            .filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
            .collect();
        for m in METHODS {
            let Some(op) = item.get(m) else { continue };
            let declared: Vec<&str> = op["parameters"]
                .as_array()
                .map(|ps| {
                    ps.iter()
                        .filter(|p| p["in"] == "path")
                        .filter_map(|p| p["name"].as_str())
                        .collect()
                })
                .unwrap_or_default();
            for ph in &placeholders {
                assert!(declared.contains(ph), "{m} {path}: `{ph}` undeclared");
            }
        }
    }

    // The committed document (input of the generated TypeScript client) is current.
    let committed: Value = serde_json::from_str(include_str!("../openapi.json")).unwrap();
    let generated = serde_json::to_value(ridm_api::openapi::openapi()).unwrap();
    assert_eq!(
        committed, generated,
        "api/openapi.json is stale: run `cargo run -p ridm-api -- openapi > api/openapi.json` \
         and `npm run gen:api` in ui/"
    );
    // ...and the served route hands out that very document.
    assert_eq!(
        doc, committed,
        "GET /openapi.json differs from the CLI document"
    );
}
