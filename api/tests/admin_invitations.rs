//! Phase 5.7: admin API for invitations.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use common::admin::{admin_token, call, get_json, role_id};
use common::{TestApp, create_tenant};
use reqwest::Method;
use ridm_api::messaging::SenderFactory;
use ridm_api::models::{MASTER_TENANT_ID, NewRole};
use ridm_api::services::admin_access::{
    ADMIN_ROLE, CLIENT_MANAGER_ROLE, OWNER_ROLE, USER_MANAGER_ROLE, VIEWER_ROLE,
};
use ridm_api::services::roles;
use ridm_api::state::AppState;
use ridm_core::events::Actor;
use ridm_core::providers::{EmailSender, SmsSender};
use ridm_core::test_support::{MockEmailSender, MockSmsSender};
use serde_json::json;
use uuid::Uuid;

struct Mocks(Arc<MockEmailSender>);
#[async_trait]
impl SenderFactory for Mocks {
    async fn email(
        &self,
        _: &AppState,
        _: Uuid,
    ) -> ridm_api::error::AppResult<Option<Arc<dyn EmailSender>>> {
        Ok(Some(self.0.clone()))
    }
    async fn sms(
        &self,
        _: &AppState,
        _: Uuid,
    ) -> ridm_api::error::AppResult<Option<Arc<dyn SmsSender>>> {
        Ok(Some(Arc::new(MockSmsSender::new())))
    }
}

async fn fixture() -> (TestApp, Arc<MockEmailSender>) {
    let email = Arc::new(MockEmailSender::new());
    let e2 = email.clone();
    let app = TestApp::spawn_configured(axum::Router::new(), move |st| {
        st.senders = Arc::new(Mocks(e2))
    })
    .await;
    (app, email)
}

fn link_token(text: &str) -> String {
    let line = text
        .lines()
        .find(|l| l.contains("token="))
        .expect("link line");
    url::Url::parse(line.trim())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "token")
        .unwrap()
        .1
        .to_string()
}

#[tokio::test]
async fn user_manager_runs_the_invitation_lifecycle() {
    let (app, email) = fixture().await;
    let tid = app.tenant.id;
    let base = format!("/admin/tenants/{}/invitations", app.tenant.slug);
    let t = admin_token(&app, tid, USER_MANAGER_ROLE).await;
    let editor = roles::create(
        &app.state,
        tid,
        Actor::System,
        NewRole {
            name: "editor".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    for body in [
        json!({"email": "not-an-email"}),
        json!({"email": "carol@example.com", "colour": "red"}),
        json!({"email": "carol@example.com", "roles": [Uuid::new_v4()]}),
    ] {
        let (status, err, _) = call(&app, Method::POST, &base, Some(&t), Some(&body)).await;
        assert_eq!(status, 400, "{body} -> {err}");
    }
    // Inviting into an admin role is guarded like any grant.
    let admin_role = role_id(&app, tid, ADMIN_ROLE).await;
    let (status, err, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"email": "carol@example.com", "roles": [admin_role]})),
    )
    .await;
    assert_eq!(status, 403, "{err}");

    common::settle(&app.state).await;
    let sent_before = email.sent().len();
    let (status, inv, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"email": "Carol@Example.com", "roles": [editor.id], "expires_days": 3})),
    )
    .await;
    assert_eq!(status, 201, "{inv}");
    assert_eq!(inv["email"], "carol@example.com");
    assert!(inv.get("token_hash").is_none() && inv.get("token").is_none());
    let id = inv["id"].as_str().unwrap().to_string();
    common::settle(&app.state).await;
    assert_eq!(email.sent().len(), sent_before + 1);
    common::settle(&app.state).await;
    let first_token = link_token(&email.last().unwrap().text);
    let (status, dup, _) = call(
        &app,
        Method::POST,
        &base,
        Some(&t),
        Some(&json!({"email": "carol@example.com"})),
    )
    .await;
    assert_eq!(status, 201, "a second open invitation is allowed: {dup}");
    let dup_id = dup["id"].as_str().unwrap().to_string();

    let (status, page, _) = get_json(&app, &format!("{base}?open_only=true"), Some(&t)).await;
    assert_eq!(status, 200, "{page}");
    assert!(
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["id"] == id)
    );
    let (status, got, _) = get_json(&app, &format!("{base}/{id}"), Some(&t)).await;
    assert_eq!(status, 200, "{got}");
    assert_eq!(got["roles"][0], editor.id.to_string());

    // Resend: a new link goes out and the old one stops working.
    let (status, resent, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{id}/resend"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 200, "{resent}");
    common::settle(&app.state).await;
    let second_token = link_token(&email.last().unwrap().text);
    assert_ne!(second_token, first_token);
    let old = app
        .http
        .get(app.tenant_url(&format!("/invitations/{first_token}")))
        .send()
        .await
        .unwrap();
    assert_eq!(old.status(), 404);
    let fresh = app
        .http
        .get(app.tenant_url(&format!("/invitations/{second_token}")))
        .send()
        .await
        .unwrap();
    assert_eq!(fresh.status(), 200);

    // Revoke: gone from the open list, link dead, resend refused.
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (_, page, _) = get_json(&app, &format!("{base}?open_only=true"), Some(&t)).await;
    assert!(
        !page["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["id"] == id)
    );
    let (_, page, _) = get_json(&app, &base, Some(&t)).await;
    assert!(
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["id"] == id)
    );
    let dead = app
        .http
        .get(app.tenant_url(&format!("/invitations/{second_token}")))
        .send()
        .await
        .unwrap();
    assert_eq!(dead.status(), 404);
    let (status, err, _) = call(
        &app,
        Method::POST,
        &format!("{base}/{id}/resend"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 400, "{err}");
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{}", Uuid::new_v4()),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("{base}/{dup_id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 204);
}

#[tokio::test]
async fn built_in_roles_map_onto_invitation_routes() {
    let (app, _email) = fixture().await;
    let base = format!("/admin/tenants/{}/invitations", app.tenant.slug);
    for (role, list, create) in [
        (OWNER_ROLE, 200, 201),
        (ADMIN_ROLE, 200, 201),
        (USER_MANAGER_ROLE, 200, 201),
        (CLIENT_MANAGER_ROLE, 403, 403),
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
            Some(&json!({"email": format!("{}@example.com", role.replace(':', "-"))})),
        )
        .await;
        assert_eq!(status, create, "{role} create: {body}");
    }
    let (status, _, _) = get_json(&app, &base, None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn invitations_are_confined_to_the_admins_tenant() {
    let (app, _email) = fixture().await;
    let other = create_tenant(&app.state.db).await;
    let t = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let global = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;
    let (status, theirs, _) = call(
        &app,
        Method::POST,
        &format!("/admin/tenants/{}/invitations", other.slug),
        Some(&global),
        Some(&json!({"email": "theirs@example.com"})),
    )
    .await;
    assert_eq!(status, 201, "{theirs}");
    let their_id = theirs["id"].as_str().unwrap();
    let (status, _, _) = get_json(
        &app,
        &format!("/admin/tenants/{}/invitations/{their_id}", other.slug),
        Some(&t),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("/admin/tenants/{}/invitations/{their_id}", app.tenant.slug),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, 404);
}
