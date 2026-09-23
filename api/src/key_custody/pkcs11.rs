//! PKCS#11 (`hsm-pkcs11`): an AES-256 key on an HSM token wraps data keys
//! with AES-GCM, the generation's context as additional authenticated data.
//! The vendor library is loaded at start-up; a static (musl) binary cannot
//! load one, so the released static binaries leave this feature out.
//!
//! PKCS#11 calls block, so each runs on the blocking pool with its own
//! session. They happen at start-up and when a generation is created, never
//! per request.

use std::sync::Arc;

use async_trait::async_trait;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use ridm_core::providers::{KeyWrapper, ProviderError, WrappedKey};
use zeroize::Zeroizing;

use super::config::Pkcs11Config;

const IV_LEN: usize = 12;
const TAG_BITS: u64 = 128;

pub struct Pkcs11Wrapper {
    inner: Arc<Inner>,
}

struct Inner {
    ctx: Pkcs11,
    slot: Slot,
    pin: Zeroizing<String>,
    key_label: String,
}

impl Pkcs11Wrapper {
    /// Load the module, find the token and check the key is there (creating
    /// it when `PKCS11_GENERATE_KEY` says so).
    pub async fn new(config: &Pkcs11Config) -> Result<Self, ProviderError> {
        let config = config.clone();
        let inner = tokio::task::spawn_blocking(move || Inner::open(&config))
            .await
            .map_err(|e| ProviderError::Unavailable(format!("pkcs11: {e}")))??;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Inner, &Session) -> Result<T, ProviderError> + Send + 'static,
    ) -> Result<T, ProviderError> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let session = inner.session()?;
            f(&inner, &session)
        })
        .await
        .map_err(|e| ProviderError::Unavailable(format!("pkcs11: {e}")))?
    }
}

impl Inner {
    fn open(config: &Pkcs11Config) -> Result<Self, ProviderError> {
        let ctx = Pkcs11::new(&config.module).map_err(|e| {
            ProviderError::Configuration(format!("PKCS11_MODULE {}: {e}", config.module.display()))
        })?;
        match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(e) => return Err(ck("initialize", e)),
        }
        let slots = ctx
            .get_slots_with_token()
            .map_err(|e| ck("list slots", e))?;
        let slot = if let Some(label) = &config.token_label {
            slots
                .into_iter()
                .find(|s| {
                    ctx.get_token_info(*s)
                        .is_ok_and(|i| i.label().trim_end() == label.as_str())
                })
                .ok_or_else(|| {
                    ProviderError::Configuration(format!("no PKCS#11 token labelled `{label}`"))
                })?
        } else if let Some(id) = config.slot {
            slots.into_iter().find(|s| s.id() == id).ok_or_else(|| {
                ProviderError::Configuration(format!("no PKCS#11 token in slot {id}"))
            })?
        } else {
            slots
                .into_iter()
                .next()
                .ok_or_else(|| ProviderError::Configuration("no PKCS#11 token present".into()))?
        };
        let inner = Self {
            ctx,
            slot,
            pin: Zeroizing::new(config.pin.expose().to_string()),
            key_label: config.key_label.clone(),
        };
        let session = inner.session()?;
        if inner.find_key(&session, &inner.key_label)?.is_none() {
            if !config.generate_key {
                return Err(ProviderError::Configuration(format!(
                    "no AES key labelled `{}` on the token (create it, or set \
                     PKCS11_GENERATE_KEY=true to let rIDM create it)",
                    inner.key_label
                )));
            }
            inner.generate(&session)?;
            tracing::info!(label = %inner.key_label, "created the PKCS#11 wrapping key");
        }
        Ok(inner)
    }

    fn session(&self) -> Result<Session, ProviderError> {
        let session = self
            .ctx
            .open_rw_session(self.slot)
            .map_err(|e| ck("open session", e))?;
        let pin = AuthPin::from(self.pin.as_str().to_string());
        match session.login(UserType::User, Some(&pin)) {
            // Login is per application, not per session: a second session
            // finds the user logged in already.
            Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(session),
            Err(e) => Err(ck("login", e)),
        }
    }

    fn find_key(
        &self,
        session: &Session,
        label: &str,
    ) -> Result<Option<ObjectHandle>, ProviderError> {
        let found = session
            .find_objects(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Label(label.as_bytes().to_vec()),
            ])
            .map_err(|e| ck("find key", e))?;
        match found.as_slice() {
            [] => Ok(None),
            [one] => Ok(Some(*one)),
            _ => Err(ProviderError::Configuration(format!(
                "more than one AES key is labelled `{label}` on the token"
            ))),
        }
    }

    fn key(&self, session: &Session, label: &str) -> Result<ObjectHandle, ProviderError> {
        self.find_key(session, label)?.ok_or_else(|| {
            ProviderError::Rejected(format!("no AES key labelled `{label}` on the token"))
        })
    }

    fn generate(&self, session: &Session) -> Result<ObjectHandle, ProviderError> {
        session
            .generate_key(
                &Mechanism::AesKeyGen,
                &[
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Encrypt(true),
                    Attribute::Decrypt(true),
                    Attribute::ValueLen(32.into()),
                    Attribute::Label(self.key_label.as_bytes().to_vec()),
                ],
            )
            .map_err(|e| ck("generate key", e))
    }
}

fn ck(what: &str, e: CkError) -> ProviderError {
    let msg = format!("pkcs11 {what}: {e}");
    match e {
        CkError::Pkcs11(
            RvError::DeviceError
            | RvError::DeviceRemoved
            | RvError::DeviceMemory
            | RvError::HostMemory
            | RvError::TokenNotPresent
            | RvError::SessionCount
            | RvError::FunctionFailed,
            _,
        ) => ProviderError::Unavailable(msg),
        CkError::Pkcs11(RvError::EncryptedDataInvalid | RvError::EncryptedDataLenRange, _) => {
            ProviderError::Rejected(msg)
        }
        _ => ProviderError::Configuration(msg),
    }
}

#[async_trait]
impl KeyWrapper for Pkcs11Wrapper {
    fn backend(&self) -> &'static str {
        "pkcs11"
    }

    async fn wrap(&self, key: &[u8], context: &[u8]) -> Result<WrappedKey, ProviderError> {
        let key = Zeroizing::new(key.to_vec());
        let context = context.to_vec();
        self.run(move |inner, session| {
            let handle = inner.key(session, &inner.key_label)?;
            let mut iv = [0u8; IV_LEN];
            rand::fill(&mut iv);
            let mut iv_param = iv;
            let params = GcmParams::new(&mut iv_param, &context, TAG_BITS.into())
                .map_err(|e| ck("gcm parameters", e))?;
            let ciphertext = session
                .encrypt(&Mechanism::AesGcm(params), handle, &key)
                .map_err(|e| ck("encrypt", e))?;
            let mut wrapped = iv.to_vec();
            wrapped.extend_from_slice(&ciphertext);
            Ok(WrappedKey {
                key_ref: inner.key_label.clone(),
                wrapped,
            })
        })
        .await
    }

    async fn unwrap(
        &self,
        key_ref: &str,
        wrapped: &[u8],
        context: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        if wrapped.len() <= IV_LEN {
            return Err(ProviderError::Rejected("wrapped key too short".into()));
        }
        let key_ref = key_ref.to_string();
        let wrapped = wrapped.to_vec();
        let context = context.to_vec();
        self.run(move |inner, session| {
            let handle = inner.key(session, &key_ref)?;
            let (iv, ciphertext) = wrapped.split_at(IV_LEN);
            let mut iv = iv.to_vec();
            let params = GcmParams::new(&mut iv, &context, TAG_BITS.into())
                .map_err(|e| ck("gcm parameters", e))?;
            session
                .decrypt(&Mechanism::AesGcm(params), handle, ciphertext)
                .map(Zeroizing::new)
                .map_err(|e| ck("decrypt", e))
        })
        .await
    }
}
