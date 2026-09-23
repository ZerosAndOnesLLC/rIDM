//! In-process cache in front of Redis for the hottest read-mostly objects
//! (tenants, clients, keys, users). Short TTL; evicted immediately on
//! invalidation messages from any node. Bounded by entry count: past it the
//! least useful entries go, so a node with many per-user keys neither grows
//! without bound nor pays a sweep on every insert.

use std::any::Any;
use std::sync::Arc;
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
        }
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
        self.entries.invalidate(key);
    }

    pub fn clear(&self) {
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
    fn stays_within_its_capacity() {
        let c = L1Cache::with_capacity(100);
        for i in 0..1_000u32 {
            c.insert(format!("k{i}"), Arc::new(i), Duration::from_secs(60));
        }
        assert!(c.len() <= 100, "{} entries", c.len());
    }
}
