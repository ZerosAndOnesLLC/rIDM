//! In-process cache in front of Redis for the hottest read-mostly objects
//! (tenants, clients, keys, users). Short TTL; evicted immediately on
//! invalidation messages from any node. Bounded by entry count: past it the
//! least useful entries go, so a node with many per-user keys neither grows
//! without bound nor pays a sweep on every insert.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use moka::Expiry;
use moka::sync::Cache;

/// Entries a node keeps at most.
const MAX_ENTRIES: u64 = 100_000;

#[derive(Clone)]
struct Entry {
    ttl: Duration,
    value: Arc<dyn Any + Send + Sync>,
}

/// Each entry lives for the TTL it was inserted with.
struct PerEntryTtl;

impl Expiry<String, Entry> for PerEntryTtl {
    fn expire_after_create(&self, _key: &String, entry: &Entry, _now: Instant) -> Option<Duration> {
        Some(entry.ttl)
    }

    fn expire_after_update(
        &self,
        _key: &String,
        entry: &Entry,
        _now: Instant,
        _current: Option<Duration>,
    ) -> Option<Duration> {
        Some(entry.ttl)
    }
}

pub struct L1Cache {
    entries: Cache<String, Entry>,
    /// When each key was last evicted (a generation, not a time), kept a
    /// while after the eviction; see [`L1Cache::ticket`].
    evicted: Cache<String, u64>,
    /// Generation of the last eviction of any key, or of a `clear`.
    generation: AtomicU64,
    /// Generation of the last `clear`.
    cleared: AtomicU64,
}

/// How long an eviction is remembered: longer than any load a ticket covers.
const EVICTION_MEMORY: Duration = Duration::from_secs(120);

/// What a loader saw before it read the source: [`L1Cache::insert_fresh`]
/// refuses its value if the key was evicted (or the cache cleared) since, as
/// the value may predate the write behind the eviction.
#[derive(Debug, Clone, Copy)]
pub struct Ticket {
    evicted: Option<u64>,
    cleared: u64,
}

impl Default for L1Cache {
    fn default() -> Self {
        Self::with_capacity(MAX_ENTRIES)
    }
}

impl L1Cache {
    pub fn with_capacity(max_entries: u64) -> Self {
        Self {
            entries: Cache::builder()
                .max_capacity(max_entries)
                .expire_after(PerEntryTtl)
                .build(),
            evicted: Cache::builder()
                .max_capacity(max_entries)
                .time_to_live(EVICTION_MEMORY)
                .build(),
            generation: AtomicU64::new(0),
            cleared: AtomicU64::new(0),
        }
    }

    /// Take before reading the source of a value to be cached with
    /// [`L1Cache::insert_fresh`].
    pub fn ticket(&self, key: &str) -> Ticket {
        Ticket {
            evicted: self.evicted.get(key),
            cleared: self.cleared.load(Ordering::Acquire),
        }
    }

    /// Insert `value` read after `ticket` was taken, unless the key was
    /// evicted or the cache cleared in between: a write (and the eviction
    /// that follows it) that raced the read would otherwise be undone for as
    /// long as the entry lives. `false`: not inserted.
    pub fn insert_fresh<T: Send + Sync + 'static>(
        &self,
        key: String,
        value: Arc<T>,
        ttl: Duration,
        ticket: Ticket,
    ) -> bool {
        if self.evicted.get(&key) != ticket.evicted
            || self.cleared.load(Ordering::Acquire) != ticket.cleared
        {
            return false;
        }
        self.insert(key.clone(), value, ttl);
        // An eviction between the check and the insert: undo the insert.
        if self.evicted.get(&key) != ticket.evicted
            || self.cleared.load(Ordering::Acquire) != ticket.cleared
        {
            self.entries.invalidate(&key);
            return false;
        }
        true
    }

    pub fn get<T: Send + Sync + 'static>(&self, key: &str) -> Option<Arc<T>> {
        self.entries.get(key)?.value.downcast::<T>().ok()
    }

    pub fn insert<T: Send + Sync + 'static>(&self, key: String, value: Arc<T>, ttl: Duration) {
        if ttl.is_zero() {
            self.entries.invalidate(&key);
            return;
        }
        self.entries.insert(key, Entry { ttl, value });
    }

    pub fn remove(&self, key: &str) {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.evicted.insert(key.to_string(), generation);
        self.entries.invalidate(key);
    }

    pub fn clear(&self) {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.cleared.store(generation, Ordering::Release);
        self.entries.invalidate_all();
    }

    /// Entries held (after pending evictions are applied).
    pub fn len(&self) -> usize {
        self.entries.run_pending_tasks();
        self.entries.entry_count() as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_round_trip_and_expiry() {
        let c = L1Cache::default();
        c.insert("k".into(), Arc::new(42u32), Duration::from_secs(60));
        assert_eq!(c.get::<u32>("k").as_deref(), Some(&42));
        assert!(c.get::<String>("k").is_none(), "wrong type must miss");
        c.insert("e".into(), Arc::new(1u32), Duration::ZERO);
        assert!(c.get::<u32>("e").is_none());
        c.insert("s".into(), Arc::new(1u32), Duration::from_millis(20));
        std::thread::sleep(Duration::from_millis(40));
        assert!(c.get::<u32>("s").is_none(), "expires after its own ttl");
        c.remove("k");
        assert!(c.get::<u32>("k").is_none());
    }

    #[test]
    fn a_value_read_before_an_eviction_is_not_cached() {
        let c = L1Cache::default();
        let ticket = c.ticket("u");
        // A write elsewhere evicts the key while this loader reads the old row.
        c.remove("u");
        assert!(!c.insert_fresh("u".into(), Arc::new(1u32), Duration::from_secs(60), ticket));
        assert!(c.get::<u32>("u").is_none());
        // A load that starts after the eviction caches.
        let ticket = c.ticket("u");
        assert!(c.insert_fresh("u".into(), Arc::new(2u32), Duration::from_secs(60), ticket));
        assert_eq!(c.get::<u32>("u").as_deref(), Some(&2));
        // A clear (the invalidation listener reconnecting) spoils every ticket.
        let ticket = c.ticket("v");
        c.clear();
        assert!(!c.insert_fresh("v".into(), Arc::new(3u32), Duration::from_secs(60), ticket));
        // Evicting another key does not.
        let ticket = c.ticket("w");
        c.remove("x");
        assert!(c.insert_fresh("w".into(), Arc::new(4u32), Duration::from_secs(60), ticket));
    }

    #[test]
    fn stays_within_its_capacity() {
        let c = L1Cache::with_capacity(100);
        for i in 0..1_000u32 {
            c.insert(format!("k{i}"), Arc::new(i), Duration::from_secs(60));
        }
        assert!(c.len() <= 100, "{} entries", c.len());
    }
}
