//! The server's [`KeyEncryptor`]: XChaCha20-Poly1305 under a master-key
//! generation's 32-byte key. Generations come from the environment
//! (`MASTER_KEY`, `MASTER_KEY_PREVIOUS`) or, with a key custody backend, from
//! `master_key_generations`, where each is a random data key the backend
//! wrapped. Either way the key is in memory once loaded, so encrypting a row
//! never calls the backend; mixing the two is what lets `rotate-master-key`
//! move a deployment from one to the other online.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ridm_core::providers::{Encrypted, KeyEncryptor, KeyWrapper, ProviderError};
use zeroize::Zeroizing;

use super::generations::{self, GenerationInfo, GenerationRow};
use crate::config::{Config, MASTER_KEY_LEN};
use crate::db::Db;
use crate::util::secret::SecretBytes;

const NONCE_LEN: usize = 24;

/// How long a generation that failed to load is not asked for again: rows
/// under it fail fast instead of each calling the backend.
const LOAD_RETRY: Duration = Duration::from_secs(30);

/// Failed loads remembered at once; a corrupt blob's nonsense version cannot
/// grow the map without bound.
const LOAD_FAILURES_MAX: usize = 1024;

/// What a generation's data key was wrapped with, so a wrapped key cannot be
/// passed off as another generation's (where the backend takes additional
/// authenticated data).
pub fn wrap_context(version: u32) -> Vec<u8> {
    format!("ridm:master-key:v{version}").into_bytes()
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct CustodyError(pub String);

impl From<sqlx::Error> for CustodyError {
    fn from(e: sqlx::Error) -> Self {
        Self(format!("master_key_generations: {e}"))
    }
}

impl From<ProviderError> for CustodyError {
    fn from(e: ProviderError) -> Self {
        Self(e.to_string())
    }
}

/// The database and the backends, once [`EnvelopeEncryptor::attach`] ran.
struct Custody {
    db: Db,
    wrappers: HashMap<&'static str, Arc<dyn KeyWrapper>>,
    /// The backend new generations are wrapped by (`KEY_WRAPPER`).
    primary: Option<&'static str>,
}

pub struct EnvelopeEncryptor {
    current: AtomicU32,
    keys: RwLock<HashMap<u32, Arc<SecretBytes>>>,
    /// Generations defined by the environment.
    env_versions: Vec<u32>,
    custody: OnceLock<Custody>,
    /// Serialises lazy loads; remembers recent failures.
    loading: tokio::sync::Mutex<HashMap<u32, Instant>>,
}

/// What [`EnvelopeEncryptor::attach`] did.
#[derive(Debug, Default)]
pub struct AttachReport {
    /// Generations unwrapped from the table.
    pub loaded: Vec<u32>,
    /// A generation created because the configured backend had none.
    pub created: Option<u32>,
    /// Generations this node cannot read (backend not configured, or the
    /// unwrap failed), with why. Rows under them fail to decrypt; the
    /// start-up check decides whether that is fatal.
    pub unreadable: Vec<(u32, String)>,
}

impl EnvelopeEncryptor {
    /// Generations from the environment only: `current` (absent when a key
    /// custody backend supplies it) and older ones.
    pub fn new(current: Option<(u32, SecretBytes)>, previous: Vec<(u32, SecretBytes)>) -> Self {
        let mut keys = HashMap::with_capacity(previous.len() + 1);
        let mut env_versions = Vec::with_capacity(previous.len() + 1);
        for (v, k) in previous {
            env_versions.push(v);
            keys.insert(v, Arc::new(k));
        }
        let current_version = match current {
            Some((v, k)) => {
                env_versions.push(v);
                keys.insert(v, Arc::new(k));
                v
            }
            None => 0,
        };
        env_versions.sort_unstable();
        Self {
            current: AtomicU32::new(current_version),
            keys: RwLock::new(keys),
            env_versions,
            custody: OnceLock::new(),
            loading: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    pub fn from_config(config: &Config) -> Self {
        Self::new(
            config
                .master_key
                .clone()
                .map(|k| (config.master_key_version, k)),
            config.master_key_previous.clone(),
        )
    }

    /// Generations this node holds, sorted.
    pub fn known_versions(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.read_keys().keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// The backend new generations go to, if any.
    pub fn primary_backend(&self) -> Option<&'static str> {
        self.custody.get().and_then(|c| c.primary)
    }

    /// Connect the generations table and the configured backends: unwrap
    /// every stored generation a backend is configured for, and, when
    /// `primary` is set, make its newest generation current, creating the
    /// first one if it has none. Runs once per process.
    pub async fn attach(
        &self,
        db: Db,
        wrappers: Vec<Arc<dyn KeyWrapper>>,
        primary: Option<&'static str>,
    ) -> Result<AttachReport, CustodyError> {
        let wrappers: HashMap<&'static str, Arc<dyn KeyWrapper>> =
            wrappers.into_iter().map(|w| (w.backend(), w)).collect();
        if let Some(p) = primary
            && !wrappers.contains_key(p)
        {
            return Err(CustodyError(format!("no wrapper built for `{p}`")));
        }
        self.custody
            .set(Custody {
                db,
                wrappers,
                primary,
            })
            .map_err(|_| CustodyError("key custody is already attached".into()))?;
        let custody = self.custody.get().expect("just set");

        let mut report = AttachReport::default();
        let rows = match generations::all(custody.db.home()).await {
            Ok(rows) => rows,
            // A node without a backend on a schema that predates the table
            // (migrations pending) still starts, on its environment keys.
            Err(err) if primary.is_none() && custody.wrappers.is_empty() => {
                tracing::warn!(error = %err, "master-key generations not read");
                return Ok(report);
            }
            Err(err) => return Err(err.into()),
        };
        for row in &rows {
            let version = row.version as u32;
            if self.env_versions.contains(&version) {
                return Err(CustodyError(format!(
                    "master-key generation {version} is defined both in the environment \
                     (MASTER_KEY_VERSION / MASTER_KEY_PREVIOUS) and in master_key_generations \
                     ({}); give the environment key another version",
                    row.backend
                )));
            }
            match self.unwrap_row(custody, row).await {
                Ok(()) => report.loaded.push(version),
                Err(err) => report.unreadable.push((version, err.to_string())),
            }
        }

        if let Some(primary) = primary {
            let newest = rows
                .iter()
                .filter(|r| r.backend == primary)
                .map(|r| r.version as u32)
                .max();
            let version = match newest {
                Some(v) => v,
                None => {
                    let (v, created) = self.ensure_generation(custody, primary, false).await?;
                    if created {
                        report.created = Some(v);
                    }
                    v
                }
            };
            if !self.read_keys().contains_key(&version) {
                let why = report
                    .unreadable
                    .iter()
                    .find(|(v, _)| *v == version)
                    .map(|(_, e)| e.clone())
                    .unwrap_or_else(|| "not loaded".into());
                return Err(CustodyError(format!(
                    "the current master-key generation {version} ({primary}) cannot be \
                     unwrapped: {why}"
                )));
            }
            self.current.store(version, Ordering::SeqCst);
        }
        Ok(report)
    }

    /// Create a generation under the primary backend, make it current and
    /// return its version. `rotate-master-key --new-generation` then moves
    /// every row onto it.
    pub async fn new_generation(&self) -> Result<u32, CustodyError> {
        let custody = self
            .custody
            .get()
            .ok_or_else(|| CustodyError("key custody is not attached".into()))?;
        let primary = custody.primary.ok_or_else(|| {
            CustodyError("KEY_WRAPPER is not set: generations from the environment are made by changing MASTER_KEY and MASTER_KEY_VERSION".into())
        })?;
        let (version, _) = self.ensure_generation(custody, primary, true).await?;
        self.current.fetch_max(version, Ordering::SeqCst);
        Ok(version)
    }

    /// Adopt generations other nodes created since this one last looked:
    /// load them and move `current` to the newest of the primary backend's.
    /// Cheap (one indexed query) when nothing changed.
    pub async fn refresh(&self) -> Result<(), CustodyError> {
        let Some(custody) = self.custody.get() else {
            return Ok(());
        };
        let seen = self.known_versions().last().copied().unwrap_or(0);
        for version in generations::newer_than(custody.db.home(), seen).await? {
            if let Err(err) = self.key(version).await {
                tracing::warn!(version, error = %err, "new master-key generation not loaded");
            }
        }
        Ok(())
    }

    /// Every generation, from the environment and the table, for status.
    pub async fn describe(&self) -> Result<Vec<GenerationInfo>, CustodyError> {
        let loaded = self.known_versions();
        let mut out: Vec<GenerationInfo> = self
            .env_versions
            .iter()
            .map(|v| GenerationInfo {
                version: *v,
                backend: "env".into(),
                key_ref: None,
                created_at: None,
                loaded: true,
            })
            .collect();
        if let Some(custody) = self.custody.get() {
            for row in generations::all(custody.db.home()).await? {
                let version = row.version as u32;
                out.push(GenerationInfo {
                    version,
                    backend: row.backend,
                    key_ref: Some(row.key_ref),
                    created_at: Some(row.created_at),
                    loaded: loaded.contains(&version),
                });
            }
        }
        out.sort_by_key(|g| g.version);
        Ok(out)
    }

    /// Under the creation lock: the newest generation of `backend`, or a new
    /// one when there is none or `force`. The boolean says one was created.
    async fn ensure_generation(
        &self,
        custody: &Custody,
        backend: &'static str,
        force: bool,
    ) -> Result<(u32, bool), CustodyError> {
        let wrapper = custody
            .wrappers
            .get(backend)
            .ok_or_else(|| CustodyError(format!("no wrapper built for `{backend}`")))?;
        let mut tx = custody.db.home().begin().await?;
        generations::lock(&mut tx).await?;
        let (newest, highest) = generations::latest(&mut tx, backend).await?;
        if let (Some(v), false) = (newest, force) {
            // Another node created it after this one read the table.
            tx.commit().await?;
            self.key(v).await?;
            return Ok((v, false));
        }
        let env_highest = self.env_versions.last().copied().unwrap_or(0);
        let in_use = crate::services::master_key::highest_version_in_use(&custody.db).await?;
        let version = highest.max(env_highest).max(in_use) + 1;
        let mut data_key = Zeroizing::new(vec![0u8; MASTER_KEY_LEN]);
        rand::fill(&mut data_key[..]);
        let context = wrap_context(version);
        let wrapped = wrapper.wrap(&data_key, &context).await?;
        // Prove the backend gives it back before anything is encrypted under
        // it: a generation that cannot be unwrapped would lose every row.
        let back = wrapper
            .unwrap(&wrapped.key_ref, &wrapped.wrapped, &context)
            .await?;
        if back.as_slice() != data_key.as_slice() {
            return Err(CustodyError(format!(
                "{backend} returned a different key than it wrapped"
            )));
        }
        generations::insert(
            &mut tx,
            version,
            backend,
            &wrapped.key_ref,
            &wrapped.wrapped,
        )
        .await?;
        tx.commit().await?;
        self.write_keys()
            .insert(version, Arc::new(SecretBytes::new(data_key.to_vec())));
        tracing::info!(version, backend, "created a master-key generation");
        Ok((version, true))
    }

    async fn unwrap_row(&self, custody: &Custody, row: &GenerationRow) -> Result<(), CustodyError> {
        let version = row.version as u32;
        let wrapper = custody.wrappers.get(row.backend.as_str()).ok_or_else(|| {
            CustodyError(format!(
                "generation {version} is held by `{}`, which is neither KEY_WRAPPER nor in \
                 KEY_WRAPPER_PREVIOUS",
                row.backend
            ))
        })?;
        let key = wrapper
            .unwrap(&row.key_ref, &row.wrapped_key, &wrap_context(version))
            .await?;
        if key.len() != MASTER_KEY_LEN {
            return Err(CustodyError(format!(
                "generation {version} unwrapped to {} bytes, not {MASTER_KEY_LEN}",
                key.len()
            )));
        }
        self.write_keys()
            .insert(version, Arc::new(SecretBytes::new(key.to_vec())));
        if custody.primary == Some(wrapper.backend()) {
            self.current.fetch_max(version, Ordering::SeqCst);
        }
        Ok(())
    }

    /// The key of `version`, loading it from the table on first use (a
    /// generation another node created after this one started).
    async fn key(&self, version: u32) -> Result<Arc<SecretBytes>, ProviderError> {
        if let Some(k) = self.read_keys().get(&version) {
            return Ok(k.clone());
        }
        let unknown = || ProviderError::Rejected(format!("unknown master key version {version}"));
        let Some(custody) = self.custody.get() else {
            return Err(unknown());
        };
        let mut failures = self.loading.lock().await;
        if let Some(k) = self.read_keys().get(&version) {
            return Ok(k.clone());
        }
        if failures
            .get(&version)
            .is_some_and(|at| at.elapsed() < LOAD_RETRY)
        {
            return Err(unknown());
        }
        let loaded = match generations::get(custody.db.home(), version).await {
            Ok(Some(row)) => self
                .unwrap_row(custody, &row)
                .await
                .map_err(|e| ProviderError::Unavailable(e.to_string())),
            Ok(None) => Err(unknown()),
            Err(e) => Err(ProviderError::unavailable(e)),
        };
        match loaded {
            Ok(()) => {
                failures.remove(&version);
                tracing::info!(version, "master-key generation loaded");
                self.read_keys().get(&version).cloned().ok_or_else(unknown)
            }
            Err(err) => {
                if failures.len() >= LOAD_FAILURES_MAX {
                    failures.clear();
                }
                failures.insert(version, Instant::now());
                Err(err)
            }
        }
    }

    fn cipher(key: &SecretBytes) -> Result<XChaCha20Poly1305, ProviderError> {
        XChaCha20Poly1305::new_from_slice(key.expose())
            .map_err(|_| ProviderError::Configuration("master key must be 32 bytes".into()))
    }

    fn read_keys(&self) -> std::sync::RwLockReadGuard<'_, HashMap<u32, Arc<SecretBytes>>> {
        self.keys.read().unwrap_or_else(|p| p.into_inner())
    }

    fn write_keys(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<u32, Arc<SecretBytes>>> {
        self.keys.write().unwrap_or_else(|p| p.into_inner())
    }
}

#[async_trait]
impl KeyEncryptor for EnvelopeEncryptor {
    fn current_version(&self) -> u32 {
        self.current.load(Ordering::SeqCst)
    }

    fn known_versions_hint(&self) -> Option<Vec<u32>> {
        Some(self.known_versions())
    }

    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Encrypted, ProviderError> {
        let version = self.current_version();
        let key = self.read_keys().get(&version).cloned().ok_or_else(|| {
            ProviderError::Configuration(format!(
                "master-key generation {version} is not loaded (no MASTER_KEY, and key \
                 custody has not been attached)"
            ))
        })?;
        let cipher = Self::cipher(&key)?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::fill(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| ProviderError::Rejected("encryption failed".into()))?;
        Ok(Encrypted {
            key_version: version,
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    async fn decrypt(
        &self,
        encrypted: &Encrypted,
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        if encrypted.nonce.len() != NONCE_LEN {
            return Err(ProviderError::Rejected("bad nonce length".into()));
        }
        let key = self.key(encrypted.key_version).await?;
        let cipher = Self::cipher(&key)?;
        let nonce = XNonce::try_from(encrypted.nonce.as_slice())
            .map_err(|_| ProviderError::Rejected("bad nonce".into()))?;
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &encrypted.ciphertext,
                    aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| {
                ProviderError::Rejected(
                    "decryption failed (wrong key, aad, or tampered data)".into(),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SecretBytes {
        SecretBytes::new(vec![b; 32])
    }

    #[tokio::test]
    async fn round_trip_binds_aad_and_detects_tampering() {
        let enc = EnvelopeEncryptor::new(Some((1, key(1))), vec![]);
        let e = enc
            .encrypt(b"private key bytes", b"signing_keys:abc")
            .await
            .unwrap();
        assert_eq!(e.key_version, 1);
        assert_eq!(e.nonce.len(), NONCE_LEN);
        assert_ne!(e.ciphertext, b"private key bytes");
        let pt = enc.decrypt(&e, b"signing_keys:abc").await.unwrap();
        assert_eq!(&*pt, b"private key bytes");
        assert!(enc.decrypt(&e, b"signing_keys:other").await.is_err());
        let mut tampered = e.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(enc.decrypt(&tampered, b"signing_keys:abc").await.is_err());
        // Serialized blob survives the storage format.
        let blob = e.to_bytes();
        let back = Encrypted::from_bytes(&blob).unwrap();
        assert_eq!(
            &*enc.decrypt(&back, b"signing_keys:abc").await.unwrap(),
            b"private key bytes"
        );
    }

    #[tokio::test]
    async fn rotation_keeps_old_generations_readable() {
        let v1 = EnvelopeEncryptor::new(Some((1, key(1))), vec![]);
        let old = v1.encrypt(b"secret", b"a").await.unwrap();
        let v2 = EnvelopeEncryptor::new(Some((2, key(2))), vec![(1, key(1))]);
        assert_eq!(v2.current_version(), 2);
        assert_eq!(v2.known_versions(), vec![1, 2]);
        assert_eq!(&*v2.decrypt(&old, b"a").await.unwrap(), b"secret");
        let fresh = v2.encrypt(b"secret", b"a").await.unwrap();
        assert_eq!(fresh.key_version, 2);
        // A node that only has generation 2 cannot read generation 1 blobs.
        let v2_only = EnvelopeEncryptor::new(Some((2, key(2))), vec![]);
        assert!(v2_only.decrypt(&old, b"a").await.is_err());
        // Wrong key material for the same version fails authentication.
        let wrong = EnvelopeEncryptor::new(Some((1, key(9))), vec![]);
        assert!(wrong.decrypt(&old, b"a").await.is_err());
    }

    #[tokio::test]
    async fn without_any_key_encryption_is_refused_not_panicking() {
        let none = EnvelopeEncryptor::new(None, vec![]);
        assert_eq!(none.current_version(), 0);
        let err = none.encrypt(b"x", b"a").await.unwrap_err();
        assert!(matches!(err, ProviderError::Configuration(_)), "{err}");
    }

    #[test]
    fn contexts_differ_per_generation() {
        assert_ne!(wrap_context(1), wrap_context(2));
    }
}
