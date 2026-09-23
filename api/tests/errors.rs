//! Database constraint violations surface as client errors, never as 500s.
mod common;

use common::TestApp;
use ridm_api::error::AppError;
use uuid::Uuid;

#[tokio::test]
async fn constraint_violations_map_to_client_errors() {
    let app = TestApp::spawn().await;
    let tid = app.tenant.id;

    // Unique violation → Conflict.
    let dup = sqlx::query("INSERT INTO tenants (slug, display_name) VALUES ($1, 'x')")
        .bind(&app.tenant.slug)
        .execute(app.state.db.home())
        .await
        .unwrap_err();
    assert!(matches!(AppError::from_db(dup), AppError::Conflict(_)));

    // Check violation → BadRequest naming the constraint.
    let bad = sqlx::query("INSERT INTO tenants (slug, display_name) VALUES ('Bad Slug', 'x')")
        .execute(app.state.db.home())
        .await
        .unwrap_err();
    match AppError::from_db(bad) {
        AppError::BadRequest(m) => assert!(m.contains("tenants_slug_format"), "{m}"),
        other => panic!("{other:?}"),
    }

    // Foreign key violation → BadRequest.
    let mut tx = ridm_api::db::tenant_tx(&app.state.db, tid).await.unwrap();
    let fk =
        sqlx::query("INSERT INTO group_members (tenant_id, group_id, user_id) VALUES ($1, $2, $3)")
            .bind(tid)
            .bind(Uuid::now_v7())
            .bind(Uuid::now_v7())
            .execute(&mut *tx)
            .await
            .unwrap_err();
    assert!(matches!(AppError::from_db(fk), AppError::BadRequest(_)));
    tx.rollback().await.unwrap();

    // RLS violation → Forbidden.
    let other = common::create_tenant(&app.state.db).await;
    let mut tx = ridm_api::db::tenant_tx(&app.state.db, tid).await.unwrap();
    let rls = sqlx::query("INSERT INTO users (tenant_id, username) VALUES ($1, 'x')")
        .bind(other.id)
        .execute(&mut *tx)
        .await
        .unwrap_err();
    assert!(matches!(AppError::from_db(rls), AppError::Forbidden(_)));
    tx.rollback().await.unwrap();

    // Problem+json shape for validation errors.
    let problem = AppError::Validation(vec![ridm_api::error::FieldError {
        field: "password".into(),
        message: "too short".into(),
    }])
    .problem();
    assert_eq!(problem.status, 400);
    assert_eq!(problem.kind, "urn:ridm:error:validation");
    assert_eq!(problem.errors.as_ref().map(Vec::len), Some(1));
}
