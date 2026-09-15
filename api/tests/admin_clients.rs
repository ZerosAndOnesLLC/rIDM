//! Phase 5.3: admin API for OAuth/OIDC clients.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::admin::{admin_token, call, get_json};
use common::{TestApp, create_tenant};
use reqwest::Method;
use ridm_api::models::MASTER_TENANT_ID;
use ridm_api::services::admin_access::{
    ADMIN_ROLE, CLIENT_MANAGER_ROLE, OWNER_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE,
};
use ridm_api::services::clients;
use serde_json::{Value, json};
use uuid::Uuid;

fn payload(jwt: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

/// `client_credentials` at the tenant's token endpoint with HTTP basic auth.
async fn client_credentials(app: &TestApp, client_id: &str, secret: &str) -> (u16, Value) {
    let res = app
        .http
        .post(app.tenant_url("/token"))
        .basic_auth(client_id, Some(secret))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap();
    (res.status().as_u16(), res.json().await.unwrap())
}

#[tokio::test]
async fn client_manager_runs_the_client_lifecycle() {
    let app = TestApp::spawn().await;
    let slug = app.tenant.slug.clone();
    let t = admin_token(&app, app.tenant.id, CLIENT_MANAGER_ROLE).await;
    let base = format!("/admin/tenants/{slug}/clients");

    // Validation: unknown fields, unknown scopes and audiences, bad URIs.
    for (body, needle) in [
        (
            json!({"name": "x", "redirect_uris": ["https://a.example/cb"], "colour": "red"}),
            "colour",
        ),
        (
            json!({"name": "x", "redirect_uris": ["https://a.example/cb"], "allowed_scopes": ["openid", "nope"]}),
            "nope",
        ),
        (
            json!({"name": "x", "redirect_uris": ["https://a.example/cb"], "allowed_audiences": ["urn:missing"]}),
            "urn:missing",
        ),
        (
            json!({"name": "x", "redirect_uris": ["http://a.example/cb"]}),
            "loopback",
        ),
        (json!({"name": "x"}), "redirect_uri"),
    ] {
        let (status, err, _) = call(&app, Method::POST, &base, Some(&t), Some(&body)).await;
        assert_eq!(status, 400, "{err}");
        assert!(
            err["detail"].as_str().unwrap().contains(needle),
            "{err} should mention {needle}"
        );
    }

    // Create a web client: type-driven defaults, secret shown once.
    let (status, created, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({
            "client_id": "acme-web",
            "name": "Acme Web",
            "redirect_uris": ["https://acme.example/cb"],
            "cors_origins": ["https://acme.example"],
            "description": "the web app"
        })),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["client_type"], "web");
    assert_eq!(created["token_endpoint_auth_method"], "client_secret_basic");
    assert_eq!(created["require_pkce"], true);
    assert_eq!(
        created["allowed_grants"],
        json!(["authorization_code", "refresh_token"])
    );
    assert!(
        created["allowed_scopes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "openid")
    );
    let secret = created["client_secret"].as_str().unwrap().to_string();
    assert!(secret.starts_with("cs_"));
    assert_eq!(created["secrets"].as_array().unwrap().len(), 1);
    assert!(created["secrets"][0]["expires_at"].is_null());
    assert!(created.get("secret_hashes").is_none());
    assert!(created.get("registration_access_token_hash").is_none());
    let id = created["id"].as_str().unwrap().to_string();

    // Duplicate public id.
    let (status, dup, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"name": "again", "client_id": "acme-web", "redirect_uris": ["https://b.example/cb"]})),
    )
    .await;
    assert_eq!(status, 409, "{dup}");

    // Read by id and by public client_id; the secret never comes back.
    let (status, got, _) = get_json(&app, &format!("{base}/{id}"), Some(&t)).await;
    assert_eq!(status, 200, "{got}");
    assert!(got.get("client_secret").is_none());
    assert_eq!(got["secrets"][0]["id"], created["secrets"][0]["id"]);
    let (status, by_public, _) = get_json(&app, &format!("{base}/acme-web"), Some(&t)).await;
    assert_eq!(status, 200);
    assert_eq!(by_public["id"], id);
    let (status, _, _) = get_json(&app, &format!("{base}/{}", Uuid::new_v4()), Some(&t)).await;
    assert_eq!(status, 404);

    // List with search.
    let (status, page, _) = get_json(&app, &format!("{base}?search=acme"), Some(&t)).await;
    assert_eq!(status, 200, "{page}");
    assert!(
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == id)
    );
    let (_, page, _) = get_json(&app, &format!("{base}?search=zzz-none"), Some(&t)).await;
    assert!(page["items"].as_array().unwrap().is_empty());

    // Merge patch: only the named fields change, `null` clears, siblings survive.
    let path = format!("{base}/{id}");
    let (status, patched, _) = call(
        &app,
        Method::PATCH,
        &path,
        Some(&t),
        Some(&json!({
            "name": "Acme Web 2",
            "description": null,
            "post_logout_redirect_uris": ["https://acme.example/bye"],
            "access_token_ttl_secs": 600,
            "allowed_audiences": ["urn:ridm:admin"]
        })),
    )
    .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["name"], "Acme Web 2");
    assert!(patched["description"].is_null());
    assert_eq!(patched["redirect_uris"], json!(["https://acme.example/cb"]));
    assert_eq!(patched["cors_origins"], json!(["https://acme.example"]));
    assert_eq!(patched["access_token_ttl_secs"], 600);
    assert_eq!(patched["allowed_audiences"], json!(["urn:ridm:admin"]));
    assert!(patched.get("client_secret").is_none(), "no new secret");
    assert_eq!(patched["secrets"].as_array().unwrap().len(), 1);

    // Patch rejections: identity, unknown fields, bad values.
    for body in [
        json!({"client_id": "renamed"}),
        json!({"id": Uuid::new_v4()}),
        json!({"colour": "red"}),
        json!({"status": "gone"}),
        json!({"redirect_uris": []}),
        json!({"allowed_scopes": ["nope"]}),
        json!(["not", "an", "object"]),
    ] {
        let (status, err, _) = call(&app, Method::PATCH, &path, Some(&t), Some(&body)).await;
        assert_eq!(status, 400, "{body} -> {err}");
    }

    // Status rides along with the patch.
    let (status, disabled, _) = call(
        &app,
        Method::PATCH,
        &path,
        Some(&t),
        Some(&json!({"status": "disabled"})),
    )
    .await;
    assert_eq!(status, 200, "{disabled}");
    assert_eq!(disabled["status"], "disabled");
    assert_eq!(disabled["name"], "Acme Web 2");
    let (_, enabled, _) = call(
        &app,
        Method::PATCH,
        &path,
        Some(&t),
        Some(&json!({"status": "active"})),
    )
    .await;
    assert_eq!(enabled["status"], "active");

    // Switching to private_key_jwt drops the secrets; switching back mints one.
    let jwk = json!({"keys": [{"kty": "RSA", "kid": "k1", "n": "AQAB", "e": "AQAB"}]});
    let (status, pkj, _) = call(
        &app,
        Method::PATCH,
        &path,
        Some(&t),
        Some(&json!({"token_endpoint_auth_method": "private_key_jwt", "jwks": jwk})),
    )
    .await;
    assert_eq!(status, 200, "{pkj}");
    assert!(pkj["secrets"].as_array().unwrap().is_empty());
    assert!(pkj.get("client_secret").is_none());
    let (status, back, _) = call(
        &app,
        Method::PATCH,
        &path,
        Some(&t),
        Some(&json!({"token_endpoint_auth_method": "client_secret_post", "jwks": null})),
    )
    .await;
    assert_eq!(status, 200, "{back}");
    assert!(back["client_secret"].as_str().unwrap().starts_with("cs_"));
    assert_eq!(back["secrets"].as_array().unwrap().len(), 1);
    assert!(back["jwks"].is_null());

    // Delete.
    let (status, _, _) = call(&app, Method::DELETE, &path, Some(&t), None).await;
    assert_eq!(status, 204);
    let (status, _, _) = get_json(&app, &path, Some(&t)).await;
    assert_eq!(status, 404);
    assert!(
        clients::find_by_client_id(&app.state, app.tenant.id, "acme-web")
            .await
            .unwrap()
            .is_none(),
        "cache evicted"
    );
}

#[tokio::test]
async fn secrets_rotate_with_grace_and_revoke_by_id() {
    let app = TestApp::spawn().await;
    let slug = app.tenant.slug.clone();
    let t = admin_token(&app, app.tenant.id, ADMIN_ROLE).await;
    let base = format!("/admin/tenants/{slug}/clients");

    let (status, created, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"client_id": "batch", "name": "Batch", "client_type": "machine"})),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["allowed_grants"], json!(["client_credentials"]));
    assert_eq!(created["require_pkce"], false);
    let id = created["id"].as_str().unwrap();
    let first = created["client_secret"].as_str().unwrap().to_string();
    let first_id = created["secrets"][0]["id"].as_str().unwrap().to_string();
    let (status, tok) = client_credentials(&app, "batch", &first).await;
    assert_eq!(status, 200, "{tok}");

    // Rotate with a one hour grace: both secrets authenticate.
    let (status, rotated, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{id}/secrets"),
        Some(&t),
        Some(&json!({"grace_secs": 3600})),
    )
    .await;
    assert_eq!(status, 201, "{rotated}");
    let second = rotated["client_secret"].as_str().unwrap().to_string();
    assert_ne!(second, first);
    let secrets = rotated["secrets"].as_array().unwrap();
    assert_eq!(secrets.len(), 2);
    let old = secrets.iter().find(|s| s["id"] == first_id).unwrap();
    assert!(
        old["expires_at"].is_string(),
        "previous secret is on a timer"
    );
    assert_eq!(client_credentials(&app, "batch", &first).await.0, 200);
    assert_eq!(client_credentials(&app, "batch", &second).await.0, 200);

    // Revoke the previous one by id: only the new secret works.
    let (status, revoked, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{id}/secrets/{first_id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200, "{revoked}");
    assert_eq!(revoked["secrets"].as_array().unwrap().len(), 1);
    assert_eq!(client_credentials(&app, "batch", &first).await.0, 401);
    assert_eq!(client_credentials(&app, "batch", &second).await.0, 200);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{id}/secrets/{first_id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404, "already gone");
    let last_id = revoked["secrets"][0]["id"].as_str().unwrap();
    let (status, err, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{id}/secrets/{last_id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 400, "{err}");

    // Bodyless rotation takes the default grace; zero grace retires at once.
    let (status, again, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{id}/secrets"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 201, "{again}");
    assert_eq!(again["secrets"].as_array().unwrap().len(), 2);
    let (status, now, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{id}/secrets"),
        Some(&t),
        Some(&json!({"grace_secs": 0})),
    )
    .await;
    assert_eq!(status, 201, "{now}");
    assert_eq!(now["secrets"].as_array().unwrap().len(), 1);
    assert_eq!(client_credentials(&app, "batch", &second).await.0, 401);
    let (status, err, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{id}/secrets"),
        Some(&t),
        Some(&json!({"grace_secs": 86400 * 31})),
    )
    .await;
    assert_eq!(status, 400, "{err}");

    // Public clients have nothing to rotate.
    let (_, spa, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"name": "SPA", "client_type": "spa", "redirect_uris": ["https://spa.example/cb"]})),
    )
    .await;
    assert!(spa.get("client_secret").is_none());
    let (status, err, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{}/secrets", spa["id"].as_str().unwrap()),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 400, "{err}");
}

#[tokio::test]
async fn service_account_gives_client_credentials_a_subject() {
    let app = TestApp::spawn().await;
    let slug = app.tenant.slug.clone();
    let t = admin_token(&app, app.tenant.id, CLIENT_MANAGER_ROLE).await;
    let base = format!("/admin/tenants/{slug}/clients");

    let (_, created, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"client_id": "Robot.1", "name": "Robot", "client_type": "machine"})),
    )
    .await;
    let id = created["id"].as_str().unwrap();
    let secret = created["client_secret"].as_str().unwrap().to_string();
    let (_, tok) = client_credentials(&app, "Robot.1", &secret).await;
    assert_eq!(
        payload(tok["access_token"].as_str().unwrap())["sub"],
        "Robot.1",
        "without a service account the client is its own subject"
    );

    let sa = format!("{base}/{id}/service-account");
    let (status, enabled, _) = call(&app, Method::PUT, &sa, Some(&t), None).await;
    assert_eq!(status, 200, "{enabled}");
    assert_eq!(enabled["service_account"]["username"], "svc-robot.1");
    let user_id = enabled["service_account"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(enabled["service_account_user_id"], user_id);
    let (status, twice, _) = call(&app, Method::PUT, &sa, Some(&t), None).await;
    assert_eq!(status, 200, "{twice}");
    assert_eq!(twice["service_account"]["id"], user_id, "idempotent");

    let (status, tok) = client_credentials(&app, "Robot.1", &secret).await;
    assert_eq!(status, 200, "{tok}");
    assert_eq!(
        payload(tok["access_token"].as_str().unwrap())["sub"],
        user_id
    );

    let (status, removed, _) = call(&app, Method::DELETE, &sa, Some(&t), None).await;
    assert_eq!(status, 200, "{removed}");
    assert!(removed["service_account_user_id"].is_null());
    let (status, tok) = client_credentials(&app, "Robot.1", &secret).await;
    assert_eq!(status, 200, "{tok}");
    assert_eq!(
        payload(tok["access_token"].as_str().unwrap())["sub"],
        "Robot.1"
    );
    let (status, _, _) = call(&app, Method::DELETE, &sa, Some(&t), None).await;
    assert_eq!(status, 200, "idempotent");
    // The username is free again.
    let (status, re, _) = call(&app, Method::PUT, &sa, Some(&t), None).await;
    assert_eq!(status, 200, "{re}");
    assert_ne!(re["service_account"]["id"], user_id);

    // Only clients with client_credentials can have one.
    let (_, spa, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"name": "SPA", "client_type": "spa", "redirect_uris": ["https://spa.example/cb"]})),
    )
    .await;
    let (status, err, _) = call(
        &app,
        Method::PUT,
        &format!("{base}/{}/service-account", spa["id"].as_str().unwrap()),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 400, "{err}");
}

#[tokio::test]
async fn registration_token_unlocks_rfc7592_management() {
    let app = TestApp::spawn().await;
    let slug = app.tenant.slug.clone();
    let t = admin_token(&app, app.tenant.id, ADMIN_ROLE).await;
    let base = format!("/admin/tenants/{slug}/clients");
    let (_, created, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"client_id": "managed", "name": "Managed", "redirect_uris": ["https://m.example/cb"]})),
    )
    .await;
    let id = created["id"].as_str().unwrap();
    let (status, issued, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{id}/registration-token"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 201, "{issued}");
    let rat = issued["registration_access_token"].as_str().unwrap();
    assert!(rat.starts_with("rat_"));
    let uri = issued["registration_client_uri"].as_str().unwrap();
    assert!(
        uri.ends_with(&format!("/t/{slug}/register/managed")),
        "{uri}"
    );
    let res = app.http.get(uri).bearer_auth(rat).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let doc: Value = res.json().await.unwrap();
    assert_eq!(doc["client_id"], "managed");

    // A second issue replaces the first.
    let (_, reissued, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{id}/registration-token"),
        Some(&t),
        None,
    )
    .await;
    assert_ne!(reissued["registration_access_token"], rat);
    let res = app.http.get(uri).bearer_auth(rat).send().await.unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn built_in_roles_map_onto_client_routes() {
    let app = TestApp::spawn().await;
    let slug = app.tenant.slug.clone();
    let base = format!("/admin/tenants/{slug}/clients");
    for (role, list, create) in [
        (OWNER_ROLE, 200, 201),
        (ADMIN_ROLE, 200, 201),
        (CLIENT_MANAGER_ROLE, 200, 201),
        (USER_MANAGER_ROLE, 403, 403),
        (VIEWER_ROLE, 200, 403),
    ] {
        let t = admin_token(&app, app.tenant.id, role).await;
        let (status, body, _) = get_json(&app, &base, Some(&t)).await;
        assert_eq!(status, list, "{role} list: {body}");
        let (status, body, _) = call(
            &app,
            Method::POST,
            &base,
            Some(&t),
            Some(&json!({"name": format!("by {role}"), "client_type": "machine"})),
        )
        .await;
        assert_eq!(status, create, "{role} create: {body}");
        if status == 201 {
            let id = body["id"].as_str().unwrap();
            let (status, _, _) = call(
                &app,
                Method::POST,
                &format!("{base}/{id}/secrets"),
                Some(&t),
                None,
            )
            .await;
            assert_eq!(status, 201, "{role} rotate");
        }
    }
    // A viewer can read a client but cannot touch secrets or the service account.
    let owner = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let (_, page, _) = get_json(&app, &base, Some(&owner)).await;
    let id = page["items"][0]["id"].as_str().unwrap().to_string();
    let viewer = admin_token(&app, app.tenant.id, VIEWER_ROLE).await;
    let (status, _, _) = get_json(&app, &format!("{base}/{id}"), Some(&viewer)).await;
    assert_eq!(status, 200);
    for (method, path) in [
        (Method::PATCH, format!("{base}/{id}")),
        (Method::DELETE, format!("{base}/{id}")),
        (Method::POST, format!("{base}/{id}/secrets")),
        (Method::PUT, format!("{base}/{id}/service-account")),
        (Method::POST, format!("{base}/{id}/registration-token")),
    ] {
        let body = (method == Method::PATCH).then(|| json!({"name": "x"}));
        let (status, _, _) = call(&app, method.clone(), &path, Some(&viewer), body.as_ref()).await;
        assert_eq!(status, 403, "{method} {path}");
    }
    let (status, _, _) = get_json(&app, &base, None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn clients_are_confined_to_the_admins_tenant() {
    let app = TestApp::spawn().await;
    let other = create_tenant(&app.state.db).await;
    let own = app.tenant.slug.clone();
    let t = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let global = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;

    // The global admin creates a client in the other tenant.
    let (status, theirs, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/clients", other.slug),
        Some(&global),
        Some(&json!({"client_id": "theirs", "name": "Theirs", "client_type": "machine"})),
    )
    .await;
    assert_eq!(status, 201, "{theirs}");
    let their_id = theirs["id"].as_str().unwrap();

    // The tenant owner cannot see or touch it, by slug, by id or by public id.
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/clients", other.slug),
        Some(&t),
    )
    .await;
    assert_eq!(status, 403);
    for path in [
        format!("/admin/tenants/{}/clients/{their_id}", other.slug),
        format!("/admin/tenants/{}/clients/theirs", other.slug),
    ] {
        let (status, _, _) = get_json(&app, &path, Some(&t)).await;
        assert_eq!(status, 403, "{path}");
        let (status, _, _) = call(&app, Method::DELETE, &path, Some(&t), None).await;
        assert_eq!(status, 403, "{path}");
    }
    // Their ids do not resolve under the owner's own tenant either.
    for key in [their_id.to_string(), "theirs".to_string()] {
        let (status, _, _) = get_json(
            &app,
            &format!("/admin/tenants/{own}/clients/{key}"),
            Some(&t),
        )
        .await;
        assert_eq!(status, 404, "{key}");
    }
    let (_, page, _) = get_json(&app, &format!("/admin/tenants/{own}/clients"), Some(&t)).await;
    assert!(
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["tenant_id"] == app.tenant.id.to_string())
    );
    // Global scope reaches both.
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/clients/theirs", other.slug),
        Some(&global),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{own}/clients"),
        Some(&global),
    )
    .await;
    assert_eq!(status, 200);
}
