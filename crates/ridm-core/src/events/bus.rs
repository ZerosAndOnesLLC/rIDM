//! In-process event bus. Publishing never blocks or fails the caller: if no
//! subscriber is listening the event is dropped (logged at debug), and slow
//! subscribers lose the oldest events (they must be idempotent and tolerate
//! gaps, e.g. by reconciling from the database).
//!
//! Cross-node fan-out (Redis pub/sub) is layered on top by the server: a
//! forwarder subscribes here and republishes to Redis, and a receiver publishes
//! remote events into the local bus with `origin = Remote`.

use std::sync::Arc;

use tokio::sync::broadcast;

use super::Event;

/// Where an event entered this node's bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Local,
    Remote,
}

#[derive(Debug, Clone)]
pub struct Envelope {
    pub origin: Origin,
    pub event: Arc<Event>,
}

/// Anything that can accept events. Domain services depend on this trait so
/// tests can inject a recording sink.
pub trait EventSink: Send + Sync {
    fn publish(&self, event: Event);
}

#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<Envelope>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Envelope> {
        self.tx.subscribe()
    }

    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }

    pub fn publish_with_origin(&self, event: Event, origin: Origin) {
        let name = event.name();
        let envelope = Envelope {
            origin,
            event: Arc::new(event),
        };
        if let Err(err) = self.tx.send(envelope) {
            // Normal before the audit/webhook subscribers are running.
            tracing::debug!(event = name, "event dropped: no subscribers ({err})");
        }
    }
}

impl EventSink for EventBus {
    fn publish(&self, event: Event) {
        self.publish_with_origin(event, Origin::Local);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Actor, EventKind};
    use uuid::Uuid;

    #[tokio::test]
    async fn subscribers_receive_published_events() {
        let bus = EventBus::new(8);
        let mut rx = bus.subscribe();
        bus.publish(Event::new(
            None,
            Actor::System,
            EventKind::MasterKeyRotated { new_version: 2 },
        ));
        let env = rx.recv().await.unwrap();
        assert_eq!(env.origin, Origin::Local);
        assert_eq!(env.event.name(), "master_key.rotated");
    }

    #[test]
    fn publishing_without_subscribers_does_not_panic() {
        let bus = EventBus::new(8);
        bus.publish(Event::new(
            Some(Uuid::nil()),
            Actor::System,
            EventKind::TenantCreated {
                tenant_id: Uuid::nil(),
            },
        ));
    }
}
