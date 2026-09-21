//! Who is really behind a request.
//!
//! An administrator impersonating a user acts through the user's own
//! session, so the events that session causes name the user as their actor.
//! The server wraps each request in [`scope`], an empty slot; whatever
//! authenticates the request as an impersonated session fills it with
//! [`set`]; and [`super::EventBus`] copies it into every event published
//! while the request runs, as [`super::Event::impersonator`].
//!
//! The slot is task-local: work a request hands to another task does not see
//! it, and anything published outside a request sees nothing.

use std::cell::Cell;
use std::future::Future;

use uuid::Uuid;

tokio::task_local! {
    static IMPERSONATOR: Cell<Option<Uuid>>;
}

/// Run `fut` with an empty slot.
pub async fn scope<F: Future>(fut: F) -> F::Output {
    IMPERSONATOR.scope(Cell::new(None), fut).await
}

/// Record that the current request acts for `impersonator`. Outside a
/// [`scope`] this does nothing.
pub fn set(impersonator: Uuid) {
    let _ = IMPERSONATOR.try_with(|slot| slot.set(Some(impersonator)));
}

/// The administrator the current request acts for, if any.
pub fn current() -> Option<Uuid> {
    IMPERSONATOR.try_with(Cell::get).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_slot_lives_only_inside_its_scope() {
        let id = Uuid::now_v7();
        set(id);
        assert_eq!(current(), None, "no slot outside a scope");
        let seen = scope(async {
            assert_eq!(current(), None, "a scope starts empty");
            set(id);
            current()
        })
        .await;
        assert_eq!(seen, Some(id));
        assert_eq!(current(), None);
    }
}
