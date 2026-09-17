//! The published key set, cached, and refreshed when a token names a key the
//! cache has not seen.
//!
//! Two clocks govern a refresh. `max_age` is how long a cached set is trusted
//! even when it answers: a key that was revoked must stop verifying tokens
//! within that window. `min_refresh_interval` is the floor between fetches, so
//! a stream of tokens naming keys that do not exist cannot turn this process
//! into a load generator against the issuer.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey};

use crate::error::AuthError;

/// One published key, parsed once.
#[derive(Debug)]
pub(crate) struct Key {
    pub(crate) decoding: DecodingKey,
    /// The `alg` the JWK names. A token must agree with it.
    pub(crate) alg: Option<Algorithm>,
}

#[derive(Debug)]
struct Snapshot {
    keys: HashMap<String, Arc<Key>>,
    fetched_at: Instant,
}

impl Snapshot {
    /// A set that has never been fetched: empty, and old enough that the first
    /// token triggers a fetch.
    fn empty(min_refresh_interval: Duration, max_age: Duration) -> Self {
        let stale = max_age.max(min_refresh_interval) + Duration::from_secs(1);
        Self {
            keys: HashMap::new(),
            fetched_at: Instant::now()
                .checked_sub(stale)
                .unwrap_or_else(Instant::now),
        }
    }
}

/// The issuer's key set, fetched on demand and shared by every request.
#[derive(Debug)]
pub(crate) struct JwksCache {
    uri: String,
    http: reqwest::Client,
    snapshot: RwLock<Arc<Snapshot>>,
    /// Held across a fetch so concurrent misses make one request, not many.
    refresh: tokio::sync::Mutex<Option<Instant>>,
    min_refresh_interval: Duration,
    max_age: Duration,
}

impl JwksCache {
    pub(crate) fn new(
        uri: String,
        http: reqwest::Client,
        min_refresh_interval: Duration,
        max_age: Duration,
    ) -> Self {
        Self {
            snapshot: RwLock::new(Arc::new(Snapshot::empty(min_refresh_interval, max_age))),
            refresh: tokio::sync::Mutex::new(None),
            uri,
            http,
            min_refresh_interval,
            max_age,
        }
    }

    pub(crate) fn uri(&self) -> &str {
        &self.uri
    }

    fn snapshot(&self) -> Arc<Snapshot> {
        // A poisoned lock means a panic while swapping an `Arc`, which cannot
        // leave the value torn; the set inside is still sound to read.
        match self.snapshot.read() {
            Ok(s) => s.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// The key `kid` names, fetching the set if the cache cannot answer or has
    /// grown older than `max_age`.
    pub(crate) async fn key(&self, kid: &str) -> Result<Arc<Key>, AuthError> {
        let cached = self.snapshot();
        if cached.fetched_at.elapsed() < self.max_age
            && let Some(key) = cached.keys.get(kid)
        {
            return Ok(key.clone());
        }

        let mut last_attempt = self.refresh.lock().await;

        // Another task may have fetched while this one waited for the lock.
        let cached = self.snapshot();
        if cached.fetched_at.elapsed() < self.max_age
            && let Some(key) = cached.keys.get(kid)
        {
            return Ok(key.clone());
        }
        if let Some(at) = *last_attempt
            && at.elapsed() < self.min_refresh_interval
        {
            // Too soon to ask again. Answer from what is cached, stale or not:
            // refusing here would make an issuer's brief outage a total one.
            return cached
                .keys
                .get(kid)
                .cloned()
                .ok_or_else(|| AuthError::UnknownKey(kid.to_string()));
        }

        *last_attempt = Some(Instant::now());
        match self.fetch().await {
            Ok(keys) => {
                let found = keys.get(kid).cloned();
                self.store(Snapshot {
                    keys,
                    fetched_at: Instant::now(),
                });
                found.ok_or_else(|| AuthError::UnknownKey(kid.to_string()))
            }
            Err(e) => {
                // Serve the stale set rather than fail every request while the
                // issuer is unreachable. A key it no longer publishes keeps
                // verifying for at most `min_refresh_interval` past `max_age`.
                match cached.keys.get(kid) {
                    Some(key) => {
                        tracing::warn!(uri = %self.uri, error = %e, "serving a stale key set");
                        Ok(key.clone())
                    }
                    None => Err(e),
                }
            }
        }
    }

    /// Fetch the set ahead of any request, so the first caller does not pay for
    /// it. Failure here is not fatal: the set is fetched again on demand.
    pub(crate) async fn warm(&self) -> Result<(), AuthError> {
        let mut last_attempt = self.refresh.lock().await;
        *last_attempt = Some(Instant::now());
        let keys = self.fetch().await?;
        self.store(Snapshot {
            keys,
            fetched_at: Instant::now(),
        });
        Ok(())
    }

    fn store(&self, snapshot: Snapshot) {
        let snapshot = Arc::new(snapshot);
        match self.snapshot.write() {
            Ok(mut slot) => *slot = snapshot,
            Err(poisoned) => *poisoned.into_inner() = snapshot,
        }
    }

    async fn fetch(&self) -> Result<HashMap<String, Arc<Key>>, AuthError> {
        let fail = |message: String| AuthError::Jwks {
            url: self.uri.clone(),
            message,
        };
        let response = self
            .http
            .get(&self.uri)
            .send()
            .await
            .map_err(|e| fail(e.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(fail(format!("HTTP {}", status.as_u16())));
        }
        let set: JwkSet = response.json().await.map_err(|e| fail(e.to_string()))?;
        let keys = parse(&set);
        if keys.is_empty() {
            return Err(fail("the key set holds no usable key".into()));
        }
        tracing::debug!(uri = %self.uri, keys = keys.len(), "key set fetched");
        Ok(keys)
    }
}

/// Turn a fetched set into decoding keys, skipping what cannot be used for
/// signature verification rather than refusing the whole document.
fn parse(set: &JwkSet) -> HashMap<String, Arc<Key>> {
    let mut keys = HashMap::new();
    for jwk in &set.keys {
        let Some(kid) = jwk.common.key_id.clone() else {
            continue;
        };
        if !usable_for_signing(jwk) {
            continue;
        }
        let alg = jwk
            .common
            .key_algorithm
            .and_then(|a| Algorithm::try_from(a).ok());
        match DecodingKey::from_jwk(jwk) {
            Ok(decoding) => {
                keys.insert(kid, Arc::new(Key { decoding, alg }));
            }
            Err(e) => tracing::debug!(%kid, error = %e, "skipping an unusable key"),
        }
    }
    keys
}

/// `use: enc` and `key_ops` without `verify` say the key is not for this.
fn usable_for_signing(jwk: &Jwk) -> bool {
    use jsonwebtoken::jwk::{KeyOperations, PublicKeyUse};
    if matches!(jwk.common.public_key_use, Some(PublicKeyUse::Encryption)) {
        return false;
    }
    match &jwk.common.key_operations {
        Some(ops) if !ops.is_empty() => ops.iter().any(|o| matches!(o, KeyOperations::Verify)),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(json: serde_json::Value) -> JwkSet {
        serde_json::from_value(json).expect("key set")
    }

    /// A P-256 public key, in the shape rIDM publishes.
    fn ec(kid: &str) -> serde_json::Value {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "alg": "ES256",
            "use": "sig",
            "kid": kid,
        })
    }

    #[test]
    fn keys_are_indexed_by_kid_with_the_algorithm_they_name() {
        let keys = parse(&set(serde_json::json!({ "keys": [ec("one"), ec("two")] })));
        assert_eq!(keys.len(), 2);
        assert_eq!(keys["one"].alg, Some(Algorithm::ES256));
    }

    #[test]
    fn a_key_that_cannot_verify_is_skipped_without_losing_the_rest() {
        let mut encryption = ec("enc");
        encryption["use"] = serde_json::json!("enc");
        let mut no_kid = ec("gone");
        no_kid.as_object_mut().unwrap().remove("kid");
        let mut wrong_ops = ec("sign-only");
        wrong_ops.as_object_mut().unwrap().remove("use");
        wrong_ops["key_ops"] = serde_json::json!(["sign"]);

        let keys = parse(&set(serde_json::json!({
            "keys": [encryption, no_kid, wrong_ops, ec("good")]
        })));
        assert_eq!(keys.keys().collect::<Vec<_>>(), ["good"]);
    }

    #[test]
    fn a_fresh_cache_is_stale_enough_to_fetch_at_once() {
        let snapshot = Snapshot::empty(Duration::from_secs(30), Duration::from_secs(600));
        assert!(snapshot.fetched_at.elapsed() >= Duration::from_secs(600));
    }
}
