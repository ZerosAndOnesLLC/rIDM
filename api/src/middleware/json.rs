//! JSON body extractor whose rejections are RFC 9457 problems, for the admin
//! and account APIs (OAuth endpoints keep their own error shape).

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, OptionalFromRequest, Request};

use crate::error::AppError;
use crate::state::AppState;

#[derive(Debug, Clone, Copy, Default)]
pub struct Json<T>(pub T);

impl<T> FromRequest<AppState> for Json<T>
where
    T: serde::de::DeserializeOwned,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, AppError> {
        <axum::Json<T> as FromRequest<AppState>>::from_request(req, state)
            .await
            .map(|axum::Json(v)| Self(v))
            .map_err(problem)
    }
}

fn problem(e: JsonRejection) -> AppError {
    match e {
        JsonRejection::MissingJsonContentType(_) => {
            AppError::BadRequest("expected a JSON body (Content-Type: application/json)".into())
        }
        JsonRejection::JsonDataError(e) => {
            AppError::BadRequest(format!("invalid body: {}", e.body_text()))
        }
        JsonRejection::JsonSyntaxError(e) => {
            AppError::BadRequest(format!("malformed JSON: {}", e.body_text()))
        }
        JsonRejection::BytesRejection(_) => {
            AppError::BadRequest("could not read the request body".into())
        }
        _ => AppError::BadRequest("invalid JSON body".into()),
    }
}

/// `Option<Json<T>>`: `None` when the request carries no JSON content type
/// (a bodyless POST); a JSON body that fails to parse is still rejected.
impl<T> OptionalFromRequest<AppState> for Json<T>
where
    T: serde::de::DeserializeOwned,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &AppState) -> Result<Option<Self>, AppError> {
        <axum::Json<T> as OptionalFromRequest<AppState>>::from_request(req, state)
            .await
            .map(|opt| opt.map(|axum::Json(v)| Self(v)))
            .map_err(problem)
    }
}

impl<T: serde::Serialize> axum::response::IntoResponse for Json<T> {
    fn into_response(self) -> axum::response::Response {
        axum::Json(self.0).into_response()
    }
}
