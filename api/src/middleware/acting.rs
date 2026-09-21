//! Gives every request an empty "acting for" slot
//! ([`ridm_core::events::acting`]). Whatever finds the request comes from an
//! impersonated session fills it, and the events the request publishes then
//! name the administrator behind it.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

pub async fn acting_scope(req: Request, next: Next) -> Response {
    ridm_core::events::acting::scope(next.run(req)).await
}
