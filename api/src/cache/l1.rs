//! In-process cache in front of Redis for the hottest read-mostly objects
//! (tenants, clients, keys). Short TTL; evicted immediately on invalidation
//! messages from any node.

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

struct Entry {
    expires_at: Instant,
    value: Arc<dyn Any + Send + Sync>,
}

#[derive(Default)]
pub struct L1Cache {
    entries: RwLock<HashMap<String, Entry>>,
}

impl L1Cache {
    pub fn get<T: Send + Sync + 'static>(&self, key: &str) -> Option<Arc<T>> {
        let guard = self.entries.read().expect("l1 cache poisoned");
        let entry = guard.get(key)?;
        if entry.expires_at <= Instant::now() {
            return None;
        }
        entry.value.clone().downcast::<T>().ok()
    }

    pub fn insert<T: Send + Sync + 'static>(&self, key: String, value: Arc<T>, ttl: Duration) {
        let mut guard = self.entries.write().expect("l1 cache poisoned");
        // Opportunistic sweep so the map cannot grow without bound.
        if guard.len() > 10_000 {
            let now = Instant::now();
            guard.retain(|_, e| e.expires_at > now);
        }
        guard.insert(
            key,
            Entry {
                expires_at: Instant::now() + ttl,
                value,
            },
        );
    }

    pub fn remove(&self, key: &str) {
        self.entries.write().expect("l1 cache poisoned").remove(key);
    }

    pub fn clear(&self) {
        self.entries.write().expect("l1 cache poisoned").clear();
    }

    pub fn len(&self) -> usize {
        self.entries.read().expect("l1 cache poisoned").len()
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
        c.remove("k");
        assert!(c.get::<u32>("k").is_none());
    }
}
