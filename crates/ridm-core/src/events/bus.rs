//! In-process event bus. Publishing never blocks or fails the caller: if no
//! subscriber is listening the event is dropped (logged at debug). There are
//! two kinds of subscriber: a [`EventBus::subscribe`] receiver shares a
//! bounded ring and loses the oldest events when it lags (it must tolerate
//! gaps), while a [`EventBus::subscribe_durable`] receiver has its own queue
//! and loses nothing while it keeps up (the audit trail and webhooks, which
//! must see every event).
//!
//! A durable queue is bounded too ([`EventBus::durable_capacity`]): a
//! consumer that stops keeping up would otherwise hold every event in memory
//! until the process ran out of it. Its depth is reported by
//! [`EventBus::durable_stats`], which the server turns into metrics and into
//! a readiness failure well before the queue is full, so a load balancer
//! steers traffic away while it drains; only an event published into a full
//! queue is dropped, counted and logged.
//!
//! Cross-node fan-out (Redis pub/sub) is layered on top by the server: a
//! forwarder subscribes here and republishes to Redis, and a receiver publishes
//! remote events into the local bus with `origin = Remote`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{broadcast, mpsc};

use super::Event;

/// Events a durable subscriber may have queued before new ones are dropped.
pub const DEFAULT_DURABLE_CAPACITY: usize = 100_000;

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

struct Durable {
    name: &'static str,
    tx: mpsc::Sender<Envelope>,
    dropped: Arc<AtomicU64>,
}

/// One durable subscriber's queue, as [`EventBus::durable_stats`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableStats {
    pub name: &'static str,
    /// Events queued and not yet received.
    pub depth: usize,
    pub capacity: usize,
    /// Events dropped because the queue was full, since start.
    pub dropped: u64,
}

impl DurableStats {
    /// Past `percent` of its capacity.
    pub fn above(&self, percent: usize) -> bool {
        self.depth * 100 > self.capacity * percent
    }
}

#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<Envelope>,
    durable: Arc<Mutex<Vec<Durable>>>,
    durable_capacity: usize,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        Self::with_durable_capacity(capacity, DEFAULT_DURABLE_CAPACITY)
    }

    /// A bus whose durable subscribers each queue up to `durable_capacity`.
    pub fn with_durable_capacity(capacity: usize, durable_capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self {
            tx,
            durable: Arc::default(),
            durable_capacity: durable_capacity.max(1),
        }
    }

    pub fn durable_capacity(&self) -> usize {
        self.durable_capacity
    }

    /// A receiver that may miss the oldest events when it falls behind.
    pub fn subscribe(&self) -> broadcast::Receiver<Envelope> {
        self.tx.subscribe()
    }

    /// A receiver with its own queue: every event published from now on
    /// reaches it while it keeps the queue from filling up. `name` labels it
    /// in [`EventBus::durable_stats`]. Dropping it unsubscribes.
    pub fn subscribe_durable(&self, name: &'static str) -> mpsc::Receiver<Envelope> {
        let (tx, rx) = mpsc::channel(self.durable_capacity);
        self.durable
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Durable {
                name,
                tx,
                dropped: Arc::default(),
            });
        rx
    }

    /// Every durable subscriber's queue.
    pub fn durable_stats(&self) -> Vec<DurableStats> {
        self.durable
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|d| DurableStats {
                name: d.name,
                depth: d.tx.max_capacity() - d.tx.capacity(),
                capacity: d.tx.max_capacity(),
                dropped: d.dropped.load(Ordering::Relaxed),
            })
            .collect()
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
            subs.retain(|sub| match sub.tx.try_send(envelope.clone()) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    let dropped = sub.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                    // The first drop and every thousandth after it: a full
                    // queue under load would otherwise log once per event.
                    if dropped == 1 || dropped.is_multiple_of(1000) {
                        tracing::error!(
                            subscriber = sub.name,
                            event = name,
                            dropped,
                            "event queue full: event dropped"
                        );
                    }
                    true
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            });
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
        let mut durable = bus.subscribe_durable("test");
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

    #[tokio::test]
    async fn a_full_durable_queue_drops_and_counts_instead_of_growing() {
        let bus = EventBus::with_durable_capacity(8, 4);
        let mut rx = bus.subscribe_durable("audit");
        for v in 0..6 {
            bus.publish(Event::new(
                None,
                Actor::System,
                EventKind::MasterKeyRotated { new_version: v },
            ));
        }
        let stats = bus.durable_stats();
        assert_eq!(
            stats,
            vec![DurableStats {
                name: "audit",
                depth: 4,
                capacity: 4,
                dropped: 2
            }]
        );
        assert!(stats[0].above(75));
        // The oldest are kept; receiving frees room for new events.
        for v in 0..4 {
            let env = rx.recv().await.unwrap();
            assert!(matches!(
                env.event.kind,
                EventKind::MasterKeyRotated { new_version } if new_version == v
            ));
        }
        bus.publish(Event::new(
            None,
            Actor::System,
            EventKind::MasterKeyRotated { new_version: 9 },
        ));
        assert_eq!(bus.durable_stats()[0].depth, 1);
        assert_eq!(bus.durable_stats()[0].dropped, 2);
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
