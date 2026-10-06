//! A registered passkey, stored exactly as webauthn-rs serialised its
//! `Passkey` (`{"cred": {..}}`): passkeys stored before rIDM verified them
//! itself keep working, and a release that still uses webauthn-rs reads the
//! ones stored now. The parts rIDM doesn't interpret (transports, extension
//! states, attestation) are kept as they were written.

use base64urlsafedata::HumanBinaryData;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::cose::CoseKey;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredPasskey {
    pub cred: StoredCredential,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredCredential {
    pub cred_id: HumanBinaryData,
    pub cred: CoseKey,
    pub counter: u32,
    #[serde(default)]
    pub transports: Value,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub registration_policy: Value,
    pub extensions: Value,
    pub attestation: Value,
    pub attestation_format: Value,
}

/// What an assertion that verified reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    pub cred_id: Vec<u8>,
    pub counter: u32,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

impl StoredPasskey {
    /// A new registration, with what webauthn-rs would have stored for it.
    pub(super) fn new(
        cred_id: Vec<u8>,
        key: CoseKey,
        counter: u32,
        flags: Flags,
        format: &str,
        extensions: Value,
    ) -> Self {
        Self {
            cred: StoredCredential {
                cred_id: cred_id.into(),
                cred: key,
                counter,
                transports: Value::Null,
                user_verified: flags.uv,
                backup_eligible: flags.be,
                backup_state: flags.bs,
                registration_policy: json!("required"),
                extensions,
                attestation: json!({"data": "None", "metadata": "None"}),
                attestation_format: json!(format),
            },
        }
    }

    pub fn cred_id(&self) -> &[u8] {
        self.cred.cred_id.as_ref()
    }

    /// Take what an assertion reported: a higher counter, the backup state,
    /// and backup eligibility turning on (never off). `true` when anything
    /// changed and the row needs writing (webauthn-rs's `update_credential`).
    pub fn update(&mut self, a: &Assertion) -> bool {
        if a.cred_id != self.cred_id() {
            return false;
        }
        let mut changed = false;
        if a.counter > self.cred.counter {
            self.cred.counter = a.counter;
            changed = true;
        }
        if a.backup_state != self.cred.backup_state {
            self.cred.backup_state = a.backup_state;
            changed = true;
        }
        if a.backup_eligible && !self.cred.backup_eligible {
            self.cred.backup_eligible = true;
            changed = true;
        }
        changed
    }
}

/// The authenticator data flags rIDM reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Flags {
    pub up: bool,
    pub uv: bool,
    pub be: bool,
    pub bs: bool,
    pub at: bool,
    pub ed: bool,
}

impl From<u8> for Flags {
    fn from(b: u8) -> Self {
        Self {
            up: b & 0x01 != 0,
            uv: b & 0x04 != 0,
            be: b & 0x08 != 0,
            bs: b & 0x10 != 0,
            at: b & 0x40 != 0,
            ed: b & 0x80 != 0,
        }
    }
}
