//! Phase 5.11: tenant configuration export/import round trip.

mod common;

use common::admin::{admin_token, call, get_json};
use common::{TestApp, create_tenant};
use reqwest::Method;
use ridm_api::models::NewRole;
use ridm_api::services::admin_access::{
    self, ADMIN_AUDIENCE, ADMIN_ROLE, Grant, OWNER_ROLE, VIEWER_ROLE,
};
use ridm_api::services::{resource_servers, roles};
use ridm_core::events::Actor;
use serde_json::{Value, json};

async fn export(app: &TestApp, slug: &str, bearer: &str) -> (u16, String) {
    let res = app
        .http
        .get(app.url(&format!("/admin/tenants/{slug}/export")))
        .bearer_auth(bearer)
        .send()
        .await
        .unwrap();
    (res.status().as_u16(), res.text().await.unwrap())
}

fn contains_key(v: &Value, needle: &str) -> bool {
    match v {
        Value::Object(m) => m
            .iter()
            .any(|(k, v)| k.contains(needle) || contains_key(v, needle)),
        Value::Array(a) => a.iter().any(|v| contains_key(v, needle)),
        _ => false,
    }
}

/// Fill a tenant with one of everything through the admin API.
async fn populate(app: &TestApp, slug: &str, t: &str) {
    let base = format!("/admin/tenants/{slug}");
    let ok = |status: reqwest::StatusCode, body: &Value, what: &str| {
        assert!(status.is_success(), "{what}: {status} {body}");
    };
    let (s, b, _) = call(
        app,
        Method::PATCH,
        &base,
        Some(t),
        Some(&json!({"display_name": "Acme", "settings": {"password": {"min_length": 14}, "features": {"beta": true}}})),
    )
    .await;
    ok(s, &b, "settings");
    let (s, b, _) = call(
        app,
        Method::POST,
        &format!("{base}/resource-servers"),
        Some(t),
        Some(&json!({"identifier": "https://api.acme.example", "name": "Acme API", "token_ttl_secs": 900})),
    )
    .await;
    ok(s, &b, "rs");
    let rs_id = b["id"].as_str().unwrap().to_string();
    let (s, b, _) = call(
        app,
        Method::POST,
        &format!("{base}/resource-servers/{rs_id}/permissions"),
        Some(t),
        Some(&json!({"name": "docs:read", "description": "Read docs"})),
    )
    .await;
    ok(s, &b, "perm");
    let (s, b, _) = call(
        app,
        Method::POST,
        &format!("{base}/scopes"),
        Some(t),
        Some(&json!({"name": "docs", "description": "Docs access", "claims": ["docs"], "resource_server_id": rs_id})),
    )
    .await;
    ok(s, &b, "scope");
    let (s, b, _) = call(
        app,
        Method::POST,
        &format!("{base}/clients"),
        Some(t),
        Some(&json!({"client_id": "acme-batch", "name": "Batch", "client_type": "machine", "allowed_audiences": ["https://api.acme.example"]})),
    )
    .await;
    ok(s, &b, "client");
    let client_uuid = b["id"].as_str().unwrap().to_string();
    let (s, b, _) = call(
        app,
        Method::PUT,
        &format!("{base}/clients/{client_uuid}/service-account"),
        Some(t),
        None,
    )
    .await;
    ok(s, &b, "service account");
    let (s, b, _) = call(
        app,
        Method::POST,
        &format!("{base}/clients"),
        Some(t),
        Some(&json!({"client_id": "acme-web", "name": "Web", "redirect_uris": ["https://acme.example/cb"], "cors_origins": ["https://acme.example"]})),
    )
    .await;
    ok(s, &b, "web client");
    let (s, b, _) = call(
        app,
        Method::POST,
        &format!("{base}/roles"),
        Some(t),
        Some(&json!({"name": "reader", "description": "reads"})),
    )
    .await;
    ok(s, &b, "role reader");
    let reader = b["id"].as_str().unwrap().to_string();
    let (s, b, _) = call(
        app,
        Method::POST,
        &format!("{base}/roles"),
        Some(t),
        Some(&json!({"name": "editor"})),
    )
    .await;
    ok(s, &b, "role editor");
    let editor = b["id"].as_str().unwrap().to_string();
    let (s, b, _) = call(
        app,
        Method::POST,
        &format!("{base}/roles"),
        Some(t),
        Some(&json!({"name": "batch-admin", "client_id": client_uuid})),
    )
    .await;
    ok(s, &b, "client role");
    let (s, b, _) = call(
        app,
        Method::PUT,
        &format!("{base}/roles/{editor}/composites/{reader}"),
        Some(t),
        None,
    )
    .await;
    ok(s, &b, "composite");
    let (_, perms, _) = get_json(
        app,
        &format!("{base}/resource-servers/{rs_id}/permissions"),
        Some(t),
    )
    .await;
    let perm_id = perms[0]["id"].as_str().unwrap().to_string();
    let (s, b, _) = call(
        app,
        Method::PUT,
        &format!("{base}/roles/{reader}/permissions/{perm_id}"),
        Some(t),
        None,
    )
    .await;
    ok(s, &b, "grant");
    let (_, catalogue, _) = get_json(app, &format!("{base}/resource-servers"), Some(t)).await;
    let admin_rs = catalogue
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["identifier"] == "urn:ridm:admin")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, admin_perms, _) = get_json(
        app,
        &format!("{base}/resource-servers/{admin_rs}/permissions"),
        Some(t),
    )
    .await;
    let users_read = admin_perms
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "ridm:users:read")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, b, _) = call(
        app,
        Method::PUT,
        &format!("{base}/roles/{editor}/permissions/{users_read}"),
        Some(t),
        None,
    )
    .await;
    ok(s, &b, "admin grant");
    let (s, b, _) = call(
        app,
        Method::POST,
        &format!("{base}/groups"),
        Some(t),
        Some(&json!({"name": "staff", "description": "all staff", "attributes": {"floor": 3}})),
    )
    .await;
    ok(s, &b, "group");
    let staff = b["id"].as_str().unwrap().to_string();
    let (s, b, _) = call(
        app,
        Method::POST,
        &format!("{base}/groups"),
        Some(t),
        Some(&json!({"name": "helpdesk", "parent_id": staff})),
    )
    .await;
    ok(s, &b, "child group");
    let helpdesk = b["id"].as_str().unwrap().to_string();
    let (s, b, _) = call(
        app,
        Method::PUT,
        &format!("{base}/groups/{helpdesk}/roles/{editor}"),
        Some(t),
        None,
    )
    .await;
    ok(s, &b, "group role");
    let (s, b, _) = call(
        app,
        Method::POST,
        &format!("{base}/claim-mappers"),
        Some(t),
        Some(&json!({"name": "tier", "config": {"type": "hardcoded", "claim": "tier", "value": "gold", "include_in": ["access"]}})),
    )
    .await;
    ok(s, &b, "mapper");
    let (s, b, _) = call(
        app,
        Method::POST,
        &format!("{base}/claim-mappers"),
        Some(t),
        Some(&json!({"name": "region", "client_id": client_uuid, "config": {"type": "hardcoded", "claim": "region", "value": "eu", "include_in": ["access"]}})),
    )
    .await;
    ok(s, &b, "client mapper");
    let (s, b, _) = call(
        app,
        Method::PUT,
        &format!("{base}/messaging/templates/sms/otp/de"),
        Some(t),
        Some(&json!({"body_text": "Code {{code}}"})),
    )
    .await;
    ok(s, &b, "template");
    let (s, b, _) = call(
        app,
        Method::POST,
        &format!("{base}/webhooks"),
        Some(t),
        Some(&json!({"name": "crm", "url": "https://crm.example/hook", "events": ["user.*"], "headers": {"X-Api-Key": "k"}})),
    )
    .await;
    ok(s, &b, "webhook");
    let (s, b, _) = call(
        app,
        Method::POST,
        &format!("{base}/ip-rules"),
        Some(t),
        Some(&json!({"cidr": "203.0.113.0/24", "action": "allow", "description": "office"})),
    )
    .await;
    ok(s, &b, "ip rule");
    let (s, b, _) = call(
        app,
        Method::POST,
        &format!("{base}/ip-rules"),
        Some(t),
        Some(&json!({"cidr": "198.51.100.7", "client_id": client_uuid})),
    )
    .await;
    ok(s, &b, "client ip rule");
    let (s, b, _) = call(
        app,
        Method::POST,
        &format!("{base}/identity-providers"),
        Some(t),
        Some(&json!({"alias": "github", "preset": "github", "client_id": "gh-app", "client_secret": "gh-secret", "link_policy": "explicit"})),
    )
    .await;
    ok(s, &b, "identity provider");
}

#[tokio::test]
async fn export_is_deterministic_secret_free_and_imports_idempotently() {
    let app = TestApp::spawn().await;
    let a = app.tenant.slug.clone();
    let ta = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    populate(&app, &a, &ta).await;

    // Export: deterministic and free of secrets.
    let (status, first) = export(&app, &a, &ta).await;
    assert_eq!(status, 200, "{first}");
    let (_, second) = export(&app, &a, &ta).await;
    assert_eq!(first, second, "two exports must be byte-identical");
    let doc: Value = serde_json::from_str(&first).unwrap();
    assert_eq!(doc["format"], "ridm.tenant/1");
    for needle in ["secret", "password_hash", "pairwise", "hash"] {
        assert!(
            !contains_key(&doc, needle),
            "export leaks `{needle}`: {first}"
        );
    }
    assert_eq!(doc["tenant"]["settings"]["password"]["min_length"], 14);
    assert_eq!(
        doc["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| s["name"] == "docs")
            .count(),
        1
    );
    assert!(
        doc["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["name"] == "openid"),
        "standard scopes travel too"
    );
    assert_eq!(
        doc["resource_servers"].as_array().unwrap().len(),
        1,
        "built-in server excluded"
    );
    assert!(
        doc["roles"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| !r["name"].as_str().unwrap().starts_with("ridm:"))
    );
    let editor = doc["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "editor")
        .unwrap();
    assert_eq!(editor["composites"], json!(["reader"]));
    assert_eq!(
        editor["permissions"],
        json!(["urn:ridm:admin#ridm:users:read"])
    );
    let reader = doc["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "reader")
        .unwrap();
    assert_eq!(
        reader["permissions"],
        json!(["https://api.acme.example#docs:read"])
    );
    assert!(
        doc["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["client"] == "acme-batch" && r["name"] == "batch-admin")
    );
    let helpdesk = doc["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["path"] == json!(["staff", "helpdesk"]))
        .unwrap();
    assert_eq!(helpdesk["roles"], json!(["editor"]));
    let batch = doc["clients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["client_id"] == "acme-batch")
        .unwrap();
    assert_eq!(batch["service_account"], true);
    assert_eq!(batch["token_endpoint_auth_method"], "client_secret_basic");
    assert!(
        doc["claim_mappers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["client"] == "acme-batch")
    );
    assert_eq!(doc["message_templates"][0]["locale"], "de");
    assert_eq!(doc["webhooks"][0]["name"], "crm");
    assert_eq!(doc["identity_providers"][0]["alias"], "github");
    assert_eq!(doc["identity_providers"][0]["kind"], "oauth2");
    assert_eq!(doc["identity_providers"][0]["client_id"], "gh-app");
    assert_eq!(doc["identity_providers"][0]["link_policy"], "explicit");
    assert!(
        doc["identity_providers"][0]
            .get("client_secret_set")
            .is_none()
    );
    assert!(
        doc["ip_rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["cidr"] == "198.51.100.7/32" && r["client"] == "acme-batch")
    );

    // Import into a fresh tenant: plan, apply, compare.
    let b = create_tenant(&app.state.db).await;
    let tb = admin_token(&app, b.id, OWNER_ROLE).await;
    let (status, plan, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/import?dry_run=true", b.slug),
        Some(&tb),
        Some(&doc),
    )
    .await;
    assert_eq!(status, 200, "{plan}");
    assert_eq!(plan["dry_run"], true);
    assert!(plan["summary"]["create"].as_u64().unwrap() >= 12, "{plan}");
    assert_eq!(plan["summary"]["delete"], 0);
    assert!(
        plan["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["resource"] == "tenant" && c["op"] == "update")
    );
    let (status, report, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/import", b.slug),
        Some(&tb),
        Some(&doc),
    )
    .await;
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert!(report["applied"].as_u64().unwrap() >= 12);
    assert!(
        report["secrets"]["clients"]["acme-batch"]
            .as_str()
            .unwrap()
            .starts_with("cs_")
    );
    assert!(
        report["secrets"]["clients"]["acme-web"]
            .as_str()
            .unwrap()
            .starts_with("cs_")
    );
    assert!(
        report["secrets"]["webhooks"]["crm"]
            .as_str()
            .unwrap()
            .starts_with("whsec_")
    );
    assert_eq!(
        report["secrets"]["identity_providers"],
        json!(["github"]),
        "the provider's secret must be set by hand: {report}"
    );

    let (_, exported_b) = export(&app, &b.slug, &tb).await;
    let mut doc_b: Value = serde_json::from_str(&exported_b).unwrap();
    let mut doc_a = doc.clone();
    doc_a["tenant"]["slug"] = Value::Null;
    doc_b["tenant"]["slug"] = Value::Null;
    assert_eq!(doc_a, doc_b, "imported tenant exports identically");

    // Idempotent: the same document again changes nothing.
    let (_, again, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/import?dry_run=true&prune=true", b.slug),
        Some(&tb),
        Some(&doc),
    )
    .await;
    assert_eq!(again["changes"], json!([]), "{again}");
    assert_eq!(again["summary"]["create"], 0);
    assert_eq!(again["summary"]["update"], 0);
    assert_eq!(again["summary"]["delete"], 0);
    let (_, applied_again, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/import?prune=true", b.slug),
        Some(&tb),
        Some(&doc),
    )
    .await;
    assert_eq!(applied_again["applied"], 0);
    assert!(applied_again.get("secrets").is_none());

    // Edit the document: update, delete (prune) and create show up as such.
    let mut edited = doc.clone();
    for s in edited["scopes"].as_array_mut().unwrap() {
        if s["name"] == "docs" {
            s["description"] = json!("Documentation");
        }
    }
    edited["webhooks"] = json!([]);
    edited["ip_rules"]
        .as_array_mut()
        .unwrap()
        .push(json!({"cidr": "192.0.2.0/24", "action": "deny"}));
    for r in edited["roles"].as_array_mut().unwrap() {
        if r["name"] == "editor" {
            r["composites"] = json!([]);
        }
    }
    let (_, plan, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/import?dry_run=true&prune=true", b.slug),
        Some(&tb),
        Some(&edited),
    )
    .await;
    let changes = plan["changes"].as_array().unwrap();
    let find = |resource: &str, key: &str| {
        changes
            .iter()
            .find(|c| c["resource"] == resource && c["key"] == key)
            .cloned()
    };
    let scope_change = find("scope", "docs").expect("scope update planned");
    assert_eq!(scope_change["op"], "update");
    assert_eq!(scope_change["fields"][0]["field"], "description");
    assert_eq!(scope_change["fields"][0]["to"], "Documentation");
    assert_eq!(find("webhook", "crm").unwrap()["op"], "delete");
    assert_eq!(find("ip_rule", "192.0.2.0/24").unwrap()["op"], "create");
    assert_eq!(find("role", "editor").unwrap()["op"], "update");
    assert_eq!(plan["summary"]["update"], 2);
    // Without prune the deletion is not planned.
    let (_, no_prune, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/import?dry_run=true", b.slug),
        Some(&tb),
        Some(&edited),
    )
    .await;
    assert_eq!(no_prune["summary"]["delete"], 0);
    let (_, applied, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/import?prune=true", b.slug),
        Some(&tb),
        Some(&edited),
    )
    .await;
    assert_eq!(applied["errors"], json!([]), "{applied}");
    let (_, exported_b2) = export(&app, &b.slug, &tb).await;
    let mut doc_b2: Value = serde_json::from_str(&exported_b2).unwrap();
    doc_b2["tenant"]["slug"] = Value::Null;
    let mut expected = edited.clone();
    expected["tenant"]["slug"] = Value::Null;
    // Normalization applied by the server: the new rule's optional fields.
    expected["ip_rules"] = doc_b2["ip_rules"].clone();
    assert_eq!(doc_b2, expected);
    assert!(
        doc_b2["ip_rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["cidr"] == "192.0.2.0/24" && r["action"] == "deny")
    );
    assert!(doc_b2["webhooks"].as_array().unwrap().is_empty());

    // Bad documents are refused before anything happens.
    let (status, err, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/import?dry_run=true", b.slug),
        Some(&tb),
        Some(&json!({"format": "ridm.tenant/9", "tenant": {"slug": "x", "display_name": "x"}})),
    )
    .await;
    assert_eq!(status, 400, "{err}");
    let (status, err, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/import?dry_run=true", b.slug),
        Some(&tb),
        Some(&json!({"format": "ridm.tenant/1", "tenant": {"slug": "x", "display_name": "x"}, "colour": "red"})),
    )
    .await;
    assert_eq!(status, 400, "{err}");
}

#[tokio::test]
async fn export_and_import_follow_the_permission_model() {
    let app = TestApp::spawn().await;
    let slug = app.tenant.slug.clone();
    let owner = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let admin = admin_token(&app, app.tenant.id, ADMIN_ROLE).await;
    let viewer = admin_token(&app, app.tenant.id, VIEWER_ROLE).await;
    let (_, doc_text) = export(&app, &slug, &owner).await;
    let doc: Value = serde_json::from_str(&doc_text).unwrap();
    assert_eq!(export(&app, &slug, &admin).await.0, 200);
    assert_eq!(export(&app, &slug, &viewer).await.0, 403);
    let path = format!("/admin/tenants/{slug}/import?dry_run=true");
    let (status, _, _) = call(&app, Method::POST, &path, Some(&owner), Some(&doc)).await;
    assert_eq!(status, 200);
    let (status, _, _) = call(&app, Method::POST, &path, Some(&admin), Some(&doc)).await;
    assert_eq!(status, 403, "import is an owner power");
    let other = create_tenant(&app.state.db).await;
    let (status, _) = export(&app, &other.slug, &owner).await;
    assert_eq!(status, 403);
}

/// An importer who holds `ridm:tenants:import` but not the permissions a
/// document would hand out cannot use the import to grant them: new admin
/// composites, built-in permission grants and group roles are refused per
/// item, the way the single-assignment routes refuse them.
#[tokio::test]
async fn import_cannot_grant_admin_permissions_the_importer_lacks() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let slug = app.tenant.slug.clone();
    let importer = roles::create(
        &app.state,
        tid,
        Actor::System,
        NewRole {
            name: "importer".into(),
            client_id: None,
            description: None,
        },
    )
    .await
    .unwrap();
    let admin_rs = resource_servers::list(&app.state, tid)
        .await
        .unwrap()
        .into_iter()
        .find(|rs| rs.identifier == ADMIN_AUDIENCE)
        .unwrap();
    for p in resource_servers::list_permissions(&app.state, tid, admin_rs.id)
        .await
        .unwrap()
        .into_iter()
        .filter(|p| p.name.starts_with("ridm:tenants:"))
    {
        resource_servers::grant(&app.state, tid, Actor::System, importer.id, p.id)
            .await
            .unwrap();
    }
    let bearer = admin_token(&app, tid, "importer").await;
    let owner = admin_token(&app, tid, OWNER_ROLE).await;

    let (_, doc_text) = export(&app, &slug, &owner).await;
    let mut doc: Value = serde_json::from_str(&doc_text).unwrap();
    let roles_doc = doc["roles"].as_array_mut().unwrap();
    roles_doc.push(json!({ "name": "sneaky-composite", "composites": [OWNER_ROLE] }));
    roles_doc.push(json!({
        "name": "sneaky-permission",
        "permissions": [format!("{ADMIN_AUDIENCE}#ridm:users:write")]
    }));
    roles_doc.push(json!({ "name": "harmless" }));
    doc["groups"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "path": ["sneaky-group"], "roles": [OWNER_ROLE] }));

    let path = format!("/admin/tenants/{slug}/import");

    // The dry run already names what applying would refuse, and changes
    // nothing; the owner's dry run of the same document flags nothing.
    let (status, plan, _) = call(
        &app,
        Method::POST,
        &format!("{path}?dry_run=true"),
        Some(&bearer),
        Some(&doc),
    )
    .await;
    assert_eq!(status, 200, "{plan}");
    assert_eq!(plan["dry_run"], true);
    let flagged: Vec<(&str, &str)> = plan["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["resource"].as_str().unwrap(), e["key"].as_str().unwrap()))
        .collect();
    for want in [
        ("role", "sneaky-composite"),
        ("role", "sneaky-permission"),
        ("group", "sneaky-group"),
    ] {
        assert!(flagged.contains(&want), "{want:?} not flagged: {plan}");
    }
    assert!(!flagged.contains(&("role", "harmless")), "{plan}");
    assert!(
        plan["errors"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["error"].as_str().unwrap().contains("cannot grant")),
        "{plan}"
    );
    {
        let mut tx = ridm_api::db::tenant_tx(&app.state.db, tid).await.unwrap();
        let none = ridm_api::repos::roles::find_by_name(&mut *tx, tid, None, "sneaky-composite")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(none.is_none(), "a dry run creates nothing");
    }
    let (status, plan, _) = call(
        &app,
        Method::POST,
        &format!("{path}?dry_run=true"),
        Some(&owner),
        Some(&doc),
    )
    .await;
    assert_eq!(status, 200, "{plan}");
    assert_eq!(plan["errors"], json!([]), "{plan}");

    let (status, report, _) = call(&app, Method::POST, &path, Some(&bearer), Some(&doc)).await;
    assert_eq!(status, 200, "{report}");
    let refused: Vec<(&str, &str)> = report["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["resource"].as_str().unwrap(), e["key"].as_str().unwrap()))
        .collect();
    for want in [
        ("role", "sneaky-composite"),
        ("role", "sneaky-permission"),
        ("group", "sneaky-group"),
    ] {
        assert!(refused.contains(&want), "{want:?} not refused: {report}");
    }
    assert!(
        report["errors"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["error"].as_str().unwrap().contains("cannot grant")),
        "{report}"
    );
    // Nothing was linked: the refused role holds no admin permission.
    let sneaky = common::admin::role_id(&app, tid, "sneaky-permission").await;
    let granted = admin_access::permissions_of_grant(&app.state, tid, Grant::Role(sneaky))
        .await
        .unwrap();
    assert!(granted.is_empty(), "{granted:?}");
    let sneaky = common::admin::role_id(&app, tid, "sneaky-composite").await;
    let granted = admin_access::permissions_of_grant(&app.state, tid, Grant::Role(sneaky))
        .await
        .unwrap();
    assert!(granted.is_empty(), "{granted:?}");

    // The owner may import the same document.
    let (status, report, _) = call(&app, Method::POST, &path, Some(&owner), Some(&doc)).await;
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
}
