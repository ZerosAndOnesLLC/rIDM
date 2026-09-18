//! The extractor and the guard, driven through a real router.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::middleware::from_fn_with_state;
use axum::response::Response;
use axum::routing::get;
use common::{Issuer, ROGUE_PEM, access_token, sign};
use ridm_auth::Validator;
use ridm_auth::axum::{Guard, OptionalRidmClaims, RidmClaims, guard};
use serde_json::json;
use tower::ServiceExt as _;

async fn whoami(RidmClaims(claims): RidmClaims) -> String {
    claims.sub
}

async fn maybe(OptionalRidmClaims(claims): OptionalRidmClaims) -> String {
    claims.map_or_else(|| "anonymous".to_string(), |c| c.sub)
}

/// Both handlers behind a guard that asks for a permission, plus two that are
/// not guarded at all.
async fn app(validator: Arc<Validator>) -> Router {
    Router::new()
        .route("/orders", get(whoami))
        .route_layer(from_fn_with_state(
            Guard::new(validator.clone())
                .permission("orders:read")
                .realm("orders"),
            guard,
        ))
        .route("/whoami", get(whoami))
        .route("/maybe", get(maybe))
        .with_state(validator)
}

async fn call(app: &Router, path: &str, authorization: Option<&str>) -> Response {
    let mut request = Request::builder().uri(path);
    if let Some(value) = authorization {
        request = request.header(header::AUTHORIZATION, value);
    }
    app.clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn body(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn a_guarded_route_serves_a_token_that_carries_what_it_asks_for() {
    let issuer = Issuer::start().await;
    let validator = issuer.validator().discover().await.unwrap().shared();
    let app = app(validator).await;

    let token = access_token(&issuer.claims());
    let response = call(&app, "/orders", Some(&format!("Bearer {token}"))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await, "5d3a1f12-4b0e-4a5f-9b6f-1c2d3e4f5a6b");
}

#[tokio::test]
async fn a_guarded_route_answers_a_missing_token_with_a_challenge() {
    let issuer = Issuer::start().await;
    let validator = issuer.validator().discover().await.unwrap().shared();
    let app = app(validator).await;

    let response = call(&app, "/orders", None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()[header::WWW_AUTHENTICATE],
        "Bearer realm=\"orders\""
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
}

#[tokio::test]
async fn a_guarded_route_forbids_a_valid_token_that_falls_short() {
    let issuer = Issuer::start().await;
    let validator = issuer.validator().discover().await.unwrap().shared();
    let app = app(validator).await;

    let mut lesser = issuer.claims();
    lesser["permissions"] = json!(["orders:list"]);
    let token = access_token(&lesser);

    let response = call(&app, "/orders", Some(&format!("Bearer {token}"))).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let challenge = response.headers()[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap()
        .to_string();
    assert!(challenge.contains("insufficient_scope"), "{challenge}");
    let body = body(response).await;
    assert!(body.contains("orders:read"), "{body}");

    // The unguarded route takes the same token: the guard is what refused it.
    let response = call(&app, "/whoami", Some(&format!("Bearer {token}"))).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_bad_token_is_refused_the_same_way_by_the_guard_and_the_extractor() {
    let issuer = Issuer::start().await;
    let validator = issuer.validator().discover().await.unwrap().shared();
    let app = app(validator).await;

    let forged = sign(ROGUE_PEM, "k1", "at+jwt", &issuer.claims());
    for path in ["/orders", "/whoami", "/maybe"] {
        let response = call(&app, path, Some(&format!("Bearer {forged}"))).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        let challenge = response.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap();
        assert!(
            challenge.contains("error=\"invalid_token\""),
            "{path}: {challenge}"
        );
    }
}

#[tokio::test]
async fn an_optional_extractor_serves_anonymous_callers_but_not_bad_tokens() {
    let issuer = Issuer::start().await;
    let validator = issuer.validator().discover().await.unwrap().shared();
    let app = app(validator).await;

    let response = call(&app, "/maybe", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await, "anonymous");

    let token = access_token(&issuer.claims());
    let response = call(&app, "/maybe", Some(&format!("Bearer {token}"))).await;
    assert_eq!(body(response).await, "5d3a1f12-4b0e-4a5f-9b6f-1c2d3e4f5a6b");
}

#[tokio::test]
async fn the_guard_validates_once_and_the_handler_reuses_what_it_found() {
    let issuer = Issuer::start().await;
    // Every validation would refetch the key set, so a second one would show.
    let validator = issuer
        .validator()
        .jwks_max_age(std::time::Duration::ZERO)
        .min_refresh_interval(std::time::Duration::ZERO)
        .discover()
        .await
        .unwrap()
        .shared();
    let app = app(validator).await;

    let token = access_token(&issuer.claims());
    let response = call(&app, "/orders", Some(&format!("Bearer {token}"))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        issuer.jwks_requests(),
        1,
        "the handler reuses the guard's work"
    );
}

#[tokio::test]
async fn a_header_that_is_not_text_is_refused_rather_than_ignored() {
    let issuer = Issuer::start().await;
    let validator = issuer.validator().discover().await.unwrap().shared();
    let app = app(validator).await;

    let request = Request::builder()
        .uri("/whoami")
        .header(
            header::AUTHORIZATION,
            axum::http::HeaderValue::from_bytes(b"Bearer \xff\xfe").unwrap(),
        )
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
