//! Review finding (Phase 10): a user manager may mint SCIM tokens, and SCIM
//! group writes (POST, PUT and PATCH `members`) added members without any
//! no-escalation check, so the token could put anyone into a group that
//! grants `ridm:owner`. A SCIM token carries no administrator to measure the
//! grant against, so adding members to a group whose roles (its ancestors'
//! and composites included) grant any admin permission is refused with 403,
//! and the refused request changes nothing.

use reqwest::Method;
use ridm_api::models::{NewGroup, NewScimToken, NewUser, Principal};
use ridm_api::services::admin_access::{self, OWNER_ROLE};
use ridm_api::services::{groups, roles, scim_tokens, users};
use ridm_core::events::Actor;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::common::TestApp;
use crate::common::admin::role_id;

const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

async fn scim(app: &TestApp, token: &str, method: Method, path: &str, body: Value) -> (u16, Value) {
    let res = app
        .http
        .request(
            method,
            app.url(&format!("/scim/v2/{}{path}", app.tenant.slug)),
        )
        .bearer_auth(token)
        .header("content-type", "application/scim+json")
        .body(serde_json::to_vec(&body).unwrap())
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

async fn group(app: &TestApp, name: &str, parent_id: Option<Uuid>) -> Uuid {
    groups::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewGroup {
            name: name.into(),
            parent_id,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .id
}

async fn member_count(app: &TestApp, group_id: Uuid) -> usize {
    groups::members(&app.state, app.tenant.id, group_id)
        .await
        .unwrap()
        .len()
}

#[tokio::test]
async fn scim_cannot_add_members_to_a_group_that_grants_admin_permissions() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let token = scim_tokens::create(
        &app.state,
        tid,
        Actor::System,
        NewScimToken {
            name: "idp".into(),
            expires_in_days: None,
        },
    )
    .await
    .unwrap()
    .token;
    let mallory = users::create(
        &app.state,
        tid,
        Actor::System,
        NewUser {
            username: "mallory".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .id;

    let owners = group(&app, "owners", None).await;
    roles::assign(
        &app.state,
        tid,
        Actor::System,
        role_id(&app, tid, OWNER_ROLE).await,
        Principal::Group { id: owners },
    )
    .await
    .unwrap();
    // Membership of a child inherits the parent's roles.
    let nested = group(&app, "nested", Some(owners)).await;
    let plain = group(&app, "plain", None).await;

    // PATCH add, on the granting group and on its child.
    for gid in [owners, nested] {
        let (status, body) = scim(
            &app,
            &token,
            Method::PATCH,
            &format!("/Groups/{gid}"),
            json!({
                "schemas": [PATCH_SCHEMA],
                "Operations": [{ "op": "add", "path": "members", "value": [{ "value": mallory }] }]
            }),
        )
        .await;
        assert_eq!(status, 403, "{body}");
        assert_eq!(body["status"], "403");
        assert_eq!(member_count(&app, gid).await, 0);
    }

    // PUT with members is refused before the rename lands.
    let (status, _) = scim(
        &app,
        &token,
        Method::PUT,
        &format!("/Groups/{owners}"),
        json!({
            "schemas": [GROUP_SCHEMA], "displayName": "renamed",
            "members": [{ "value": mallory }]
        }),
    )
    .await;
    assert_eq!(status, 403);
    let after = groups::get(&app.state, tid, owners).await.unwrap();
    assert_eq!(after.name, "owners");
    assert_eq!(member_count(&app, owners).await, 0);

    // A group without admin roles still takes members, and a PUT that adds
    // nobody to the granting group (a rename) is still fine.
    let (status, body) = scim(
        &app,
        &token,
        Method::PATCH,
        &format!("/Groups/{plain}"),
        json!({
            "schemas": [PATCH_SCHEMA],
            "Operations": [{ "op": "add", "path": "members", "value": [{ "value": mallory }] }]
        }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(member_count(&app, plain).await, 1);
    let (status, body) = scim(
        &app,
        &token,
        Method::PUT,
        &format!("/Groups/{owners}"),
        json!({ "schemas": [GROUP_SCHEMA], "displayName": "owners-renamed" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let held = admin_access::permissions_of_user(&app.state, tid, mallory)
        .await
        .unwrap();
    assert!(held.is_empty(), "mallory must hold no admin permission");
}
