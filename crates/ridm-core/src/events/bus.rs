//! In-process event bus. Publishing never blocks or fails the caller: if no
//! subscriber is listening the event is dropped (logged at debug). There are
//! two kinds of subscriber: a [`EventBus::subscribe`] receiver shares a
//! bounded ring and loses the oldest events when it lags (it must tolerate
//! gaps), while a [`EventBus::subscribe_durable`] receiver has its own queue
//! and loses nothing (the audit trail and webhooks, which must see every
//! event); its depth is what to watch under load.
//!
//! Cross-node fan-out (Redis pub/sub) is layered on top by the server: a
//! forwarder subscribes here and republishes to Redis, and a receiver publishes
//! remote events into the local bus with `origin = Remote`.

use std::sync::{Arc, Mutex};

use tokio::sync::{broadcast, mpsc};

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
    durable: Arc<Mutex<Vec<mpsc::UnboundedSender<Envelope>>>>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self {
            tx,
            durable: Arc::default(),
        }
    }

    /// A receiver that may miss the oldest events when it falls behind.
    pub fn subscribe(&self) -> broadcast::Receiver<Envelope> {
        self.tx.subscribe()
    }

    /// A receiver with its own unbounded queue: every event published from
    /// now on reaches it, however far behind it is. Dropping it unsubscribes.
    pub fn subscribe_durable(&self) -> mpsc::UnboundedReceiver<Envelope> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.durable
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(tx);
        rx
    }

    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count() + self.durable.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn publish_with_origin(&self, mut event: Event, origin: Origin) {
        if origin == Origin::Local && event.impersonator.is_none() {
            event.impersonator = super::acting::current();
        }
        let name = event.name();
        let envelope = Envelope {
            origin,
            event: Arc::new(event),
        };
        let durable = {
            let mut subs = self.durable.lock().unwrap_or_else(|e| e.into_inner());
            subs.retain(|sub| sub.send(envelope.clone()).is_ok());
            subs.len()
        };
        if self.tx.send(envelope).is_err() && durable == 0 {
            // Normal before the audit/webhook subscribers are running.
            tracing::debug!(event = name, "event dropped: no subscribers");
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

    #[tokio::test]
    async fn a_durable_subscriber_misses_nothing_however_far_behind() {
        let bus = EventBus::new(2);
        let mut lossy = bus.subscribe();
        let mut durable = bus.subscribe_durable();
        for v in 0..10 {
            bus.publish(Event::new(
                None,
                Actor::System,
                EventKind::MasterKeyRotated { new_version: v },
            ));
        }
        assert!(matches!(
            lossy.recv().await,
            Err(broadcast::error::RecvError::Lagged(8))
        ));
        for _ in 0..10 {
            durable.try_recv().expect("every event queued");
        }
        drop(durable);
        bus.publish(Event::new(
            None,
            Actor::System,
            EventKind::MasterKeyRotated { new_version: 11 },
        ));
        assert_eq!(bus.subscriber_count(), 1, "a dropped receiver unsubscribes");
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
