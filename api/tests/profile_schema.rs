mod common;

use common::TestApp;
use ridm_api::error::AppError;
use ridm_api::models::{
    AttributeDef, AttributeType, AttributeValidation, EditableBy, NewUser, ProfileSchema,
    UserUpdate,
};
use ridm_api::services::{profile_schema, users};
use ridm_core::events::Actor;
use serde_json::json;
use uuid::Uuid;

fn schema() -> ProfileSchema {
    ProfileSchema {
        attributes: vec![
            AttributeDef {
                name: "department".into(),
                kind: AttributeType::Enum,
                required: true,
                validation: AttributeValidation {
                    values: vec!["eng".into(), "sales".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
            AttributeDef {
                name: "badge".into(),
                editable_by: EditableBy::Admin,
                ..Default::default()
            },
        ],
        allow_undeclared: false,
    }
}

#[tokio::test]
async fn schema_is_enforced_on_user_create_and_update() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;
    let admin = Actor::Admin { id: Uuid::now_v7() };

    // Empty schema by default: any object is accepted, nothing is required.
    let s = profile_schema::get(&app.state, tid).await.unwrap();
    assert!(s.attributes.is_empty());
    assert!(
        matches!(
            users::create(
                &app.state,
                tid,
                Actor::System,
                NewUser {
                    username: "free".into(),
                    attributes: Some(json!({"anything": 1})),
                    ..Default::default()
                }
            )
            .await,
            Err(AppError::Validation(_))
        ),
        "undeclared attributes are rejected even with an empty schema"
    );

    profile_schema::set(&app.state, tid, admin.clone(), schema())
        .await
        .unwrap();
    // Cached read reflects the write (invalidation).
    assert_eq!(
        profile_schema::get(&app.state, tid)
            .await
            .unwrap()
            .attributes
            .len(),
        2
    );

    // Missing required attribute.
    let r = users::create(
        &app.state,
        tid,
        admin.clone(),
        NewUser {
            username: "a".into(),
            ..Default::default()
        },
    )
    .await;
    assert!(matches!(r, Err(AppError::Validation(_))), "{r:?}");

    let u = users::create(
        &app.state,
        tid,
        admin.clone(),
        NewUser {
            username: "alice".into(),
            attributes: Some(json!({"department": "eng", "badge": "B-1"})),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(u.attributes, json!({"department": "eng", "badge": "B-1"}));

    // The user may change their own department but not the admin-only badge.
    let me = Actor::User { id: u.id };
    let u2 = users::update(
        &app.state,
        tid,
        me.clone(),
        u.id,
        UserUpdate {
            attributes: Some(json!({"department": "sales"})),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        u2.attributes,
        json!({"department": "sales", "badge": "B-1"}),
        "protected attribute preserved"
    );
    let r = users::update(
        &app.state,
        tid,
        me,
        u.id,
        UserUpdate {
            attributes: Some(json!({"department": "sales", "badge": "B-2"})),
            ..Default::default()
        },
    )
    .await;
    assert!(matches!(r, Err(AppError::Validation(_))), "{r:?}");

    // Invalid schema is rejected and the old one stays in effect.
    let bad = ProfileSchema {
        attributes: vec![AttributeDef {
            name: "1bad".into(),
            ..Default::default()
        }],
        allow_undeclared: false,
    };
    assert!(matches!(
        profile_schema::set(&app.state, tid, admin, bad).await,
        Err(AppError::Validation(_))
    ));
    assert_eq!(
        profile_schema::get(&app.state, tid)
            .await
            .unwrap()
            .attributes
            .len(),
        2
    );

    // Schemas are per tenant.
    let other = common::create_tenant(&app.state.db).await;
    assert!(
        profile_schema::get(&app.state, other.id)
            .await
            .unwrap()
            .attributes
            .is_empty()
    );
}
