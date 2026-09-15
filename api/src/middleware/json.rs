//! JSON body extractor whose rejections are RFC 9457 problems, for the admin
//! and account APIs (OAuth endpoints keep their own error shape).

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};

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
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(v)) => Ok(Self(v)),
            Err(JsonRejection::MissingJsonContentType(_)) => Err(AppError::BadRequest(
                "expected a JSON body (Content-Type: application/json)".into(),
            )),
            Err(JsonRejection::JsonDataError(e)) => Err(AppError::BadRequest(format!(
                "invalid body: {}",
                e.body_text()
            ))),
            Err(JsonRejection::JsonSyntaxError(e)) => Err(AppError::BadRequest(format!(
                "malformed JSON: {}",
                e.body_text()
            ))),
            Err(JsonRejection::BytesRejection(_)) => Err(AppError::BadRequest(
                "could not read the request body".into(),
            )),
            Err(_) => Err(AppError::BadRequest("invalid JSON body".into())),
        }
    }
}

impl<T: serde::Serialize> axum::response::IntoResponse for Json<T> {
    fn into_response(self) -> axum::response::Response {
        axum::Json(self.0).into_response()
    }
}
