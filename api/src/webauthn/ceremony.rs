//! The passkey ceremonies (WebAuthn Level 3 §7) for one relying party:
//! creation and request options for the browser, and the checks of its
//! answers. They reproduce webauthn-rs 0.5's passkey behaviour, which rIDM
//! used before (the same options, the same checks in the same order), with
//! two differences:
//!
//! - challenges come from the module's DRBG (aws-lc-rs);
//! - attestation statements aren't verified. rIDM asks for none and trusts
//!   none (WebAuthn §7.1 step 21 lets a relying party treat any statement
//!   as unattested), so a statement format webauthn-rs refused (TPM) now
//!   registers.

use base64urlsafedata::{Base64UrlSafeData, HumanBinaryData};
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use subtle::ConstantTimeEq as _;
use url::Url;
use uuid::Uuid;
use webauthn_rs_proto::{
    AllowCredentials, AttestationConveyancePreference, AuthenticatorSelectionCriteria,
    CreationChallengeResponse, CredProtect, CredentialProtectionPolicy, Mediation,
    PubKeyCredParams, PublicKeyCredential, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions, RegisterPublicKeyCredential,
    RelyingParty as RpEntity, RequestAuthenticationExtensions, RequestChallengeResponse,
    RequestRegistrationExtensions, ResidentKeyRequirement, User, UserVerificationPolicy,
};

use super::cbor::{self, Value};
use super::cose::{CoseAlgorithm, CoseKey};
use super::stored::{Assertion, Flags, StoredPasskey};

/// What registration offers, in order (webauthn-rs's `secure_algs`).
const ALGORITHMS: [CoseAlgorithm; 2] = [CoseAlgorithm::ES256, CoseAlgorithm::RS256];
const TIMEOUT_MS: u32 = 300_000;
const CHALLENGE_LEN: usize = 32;
const ATTESTATION_FORMATS: [&str; 7] = [
    "packed",
    "tpm",
    "android-key",
    "android-safetynet",
    "fido-u2f",
    "apple",
    "none",
];

/// Why a ceremony's answer was refused (logged, never shown to the user).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Rejected(pub &'static str);

/// The relying party: its id (a host), its name, and the origins whose pages
/// may run the ceremonies.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    id: String,
    name: String,
    origins: Vec<Url>,
    id_hash: [u8; 32],
}

/// A registration in progress: what [`RelyingParty::finish_registration`]
/// checks the answer against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationState {
    challenge: HumanBinaryData,
    exclude: Vec<HumanBinaryData>,
}

/// An assertion in progress: the challenge, the credentials it may come from
/// (none for a discoverable sign-in) and whether backup eligibility may turn
/// on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationState {
    challenge: HumanBinaryData,
    allowed: Vec<HumanBinaryData>,
    allow_backup_eligible_upgrade: bool,
}

impl RelyingParty {
    /// `origin`'s host must be `id` or a subdomain of it.
    pub fn new(id: &str, origin: &Url, name: &str) -> Result<Self, Rejected> {
        let host = origin
            .domain()
            .ok_or(Rejected("the origin has no domain"))?;
        let suffix = format!(".{id}");
        if host != id && !host.ends_with(&suffix) {
            return Err(Rejected("the origin is not within the relying party id"));
        }
        Ok(Self {
            id: id.to_string(),
            name: name.to_string(),
            origins: vec![origin.clone()],
            id_hash: ridm_core::crypto::Sha256::digest(id.as_bytes()),
        })
    }

    /// Accept ceremonies from another origin too.
    pub fn allow_origin(mut self, origin: &Url) -> Self {
        self.origins.push(origin.clone());
        self
    }

    fn challenge() -> HumanBinaryData {
        ridm_core::crypto::random_bytes::<CHALLENGE_LEN>()
            .to_vec()
            .into()
    }

    /// Creation options for a passkey of `user_id`, excluding credentials it
    /// already holds.
    pub fn start_registration(
        &self,
        user_id: Uuid,
        user_name: &str,
        display_name: &str,
        exclude: &[Vec<u8>],
    ) -> Result<(CreationChallengeResponse, RegistrationState), Rejected> {
        if user_name.is_empty() || display_name.is_empty() {
            return Err(Rejected("an empty user name"));
        }
        let challenge = Self::challenge();
        let options = PublicKeyCredentialCreationOptions {
            rp: RpEntity {
                name: self.name.clone(),
                id: self.id.clone(),
            },
            user: User {
                id: Base64UrlSafeData::from(user_id.as_bytes().to_vec()),
                name: user_name.to_string(),
                display_name: display_name.to_string(),
            },
            challenge: Base64UrlSafeData::from(challenge.as_ref().to_vec()),
            pub_key_cred_params: ALGORITHMS
                .iter()
                .map(|a| PubKeyCredParams {
                    type_: "public-key".into(),
                    alg: a.id(),
                })
                .collect(),
            timeout: Some(TIMEOUT_MS),
            exclude_credentials: (!exclude.is_empty()).then(|| {
                exclude
                    .iter()
                    .map(|id| PublicKeyCredentialDescriptor {
                        type_: "public-key".into(),
                        id: Base64UrlSafeData::from(id.clone()),
                        transports: None,
                    })
                    .collect()
            }),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: None,
                resident_key: Some(ResidentKeyRequirement::Discouraged),
                require_resident_key: false,
                user_verification: UserVerificationPolicy::Required,
            }),
            hints: None,
            attestation: Some(AttestationConveyancePreference::None),
            attestation_formats: None,
            extensions: Some(RequestRegistrationExtensions {
                cred_protect: Some(CredProtect {
                    credential_protection_policy:
                        CredentialProtectionPolicy::UserVerificationRequired,
                    enforce_credential_protection_policy: Some(false),
                }),
                uvm: Some(true),
                cred_props: Some(true),
                min_pin_length: None,
                hmac_create_secret: None,
            }),
        };
        let state = RegistrationState {
            challenge,
            exclude: exclude.iter().map(|id| id.clone().into()).collect(),
        };
        Ok((
            CreationChallengeResponse {
                public_key: options,
            },
            state,
        ))
    }

    /// Request options for an assertion by one of `credentials`.
    pub fn start_authentication(
        &self,
        credentials: &[StoredPasskey],
    ) -> (RequestChallengeResponse, AuthenticationState) {
        let allowed: Vec<HumanBinaryData> = credentials
            .iter()
            .map(|c| c.cred_id().to_vec().into())
            .collect();
        let allow_list = credentials
            .iter()
            .map(|c| AllowCredentials {
                type_: "public-key".into(),
                id: Base64UrlSafeData::from(c.cred_id().to_vec()),
                transports: serde_json::from_value(c.cred.transports.clone()).unwrap_or(None),
            })
            .collect();
        self.request(allow_list, allowed, None, true, None)
    }

    /// Request options for a passwordless sign-in: no allow list, answered by
    /// whichever discoverable credential the user picks.
    pub fn start_discoverable(&self) -> (RequestChallengeResponse, AuthenticationState) {
        let extensions = RequestAuthenticationExtensions {
            appid: None,
            uvm: Some(true),
            hmac_get_secret: None,
        };
        self.request(
            vec![],
            vec![],
            Some(extensions),
            false,
            Some(Mediation::Conditional),
        )
    }

    fn request(
        &self,
        allow_list: Vec<AllowCredentials>,
        allowed: Vec<HumanBinaryData>,
        extensions: Option<RequestAuthenticationExtensions>,
        allow_backup_eligible_upgrade: bool,
        mediation: Option<Mediation>,
    ) -> (RequestChallengeResponse, AuthenticationState) {
        let challenge = Self::challenge();
        let options = PublicKeyCredentialRequestOptions {
            challenge: Base64UrlSafeData::from(challenge.as_ref().to_vec()),
            timeout: Some(TIMEOUT_MS),
            rp_id: self.id.clone(),
            allow_credentials: allow_list,
            user_verification: UserVerificationPolicy::Required,
            hints: None,
            extensions,
        };
        (
            RequestChallengeResponse {
                public_key: options,
                mediation,
            },
            AuthenticationState {
                challenge,
                allowed,
                allow_backup_eligible_upgrade,
            },
        )
    }

    /// Check a registration's answer (WebAuthn §7.1) and return the passkey
    /// to store.
    pub fn finish_registration(
        &self,
        credential: &RegisterPublicKeyCredential,
        state: &RegistrationState,
    ) -> Result<StoredPasskey, Rejected> {
        let client_data_json = credential.response.client_data_json.as_ref();
        let client = ClientData::parse(client_data_json)?;
        let attestation = cbor::decode_exact(credential.response.attestation_object.as_ref())
            .map_err(|_| Rejected("the attestation object is not CBOR"))?;
        let format = attestation
            .get_text("fmt")
            .and_then(Value::as_text)
            .ok_or(Rejected("the attestation object has no format"))?;
        let auth_data = attestation
            .get_text("authData")
            .and_then(Value::as_bytes)
            .ok_or(Rejected("the attestation object has no authenticator data"))?;
        let data = AuthData::parse(auth_data)?;

        client.check("webauthn.create", state.challenge.as_ref(), &self.origins)?;
        if client.cross_origin.unwrap_or(false) {
            return Err(Rejected("a cross-origin registration"));
        }
        if !bool::from(data.rp_id_hash.ct_eq(&self.id_hash)) {
            return Err(Rejected("the relying party id hash differs"));
        }
        if !data.flags.up {
            return Err(Rejected("the user was not present"));
        }
        if !data.flags.uv {
            return Err(Rejected("the user was not verified"));
        }
        if !ATTESTATION_FORMATS.contains(&format) {
            return Err(Rejected("an unknown attestation format"));
        }
        let (cred_id, key) = data
            .credential
            .ok_or(Rejected("no attested credential data"))?;
        let key =
            CoseKey::from_cbor(&key, &ALGORITHMS).map_err(|_| Rejected("the credential key"))?;
        if data.flags.bs && !data.flags.be {
            return Err(Rejected("backed up but not backup eligible"));
        }
        if state
            .exclude
            .iter()
            .any(|e| e.as_ref() == cred_id.as_slice())
        {
            return Err(Rejected("the credential is excluded"));
        }
        let extensions = registered_extensions(data.extensions.as_ref(), credential)?;
        Ok(StoredPasskey::new(
            cred_id,
            key,
            data.counter,
            data.flags,
            format,
            extensions,
        ))
    }

    /// The user and credential a discoverable assertion names (its user
    /// handle is the user's 16-byte id), before anything is verified.
    pub fn identify_discoverable(
        credential: &PublicKeyCredential,
    ) -> Result<(Uuid, Vec<u8>), Rejected> {
        let handle = credential
            .response
            .user_handle
            .as_ref()
            .ok_or(Rejected("no user handle"))?;
        let user = Uuid::from_slice(handle.as_ref()).map_err(|_| Rejected("the user handle"))?;
        Ok((user, credential.raw_id.as_ref().to_vec()))
    }

    /// Check an assertion (WebAuthn §7.2) by `passkey`, which must be the
    /// credential the answer names.
    pub fn finish_authentication(
        &self,
        credential: &PublicKeyCredential,
        state: &AuthenticationState,
        passkey: &StoredPasskey,
    ) -> Result<Assertion, Rejected> {
        let raw_id = credential.raw_id.as_ref();
        if raw_id != passkey.cred_id() {
            return Err(Rejected("a different credential"));
        }
        if !state.allowed.is_empty() && !state.allowed.iter().any(|a| a.as_ref() == raw_id) {
            return Err(Rejected("the credential was not asked for"));
        }
        let auth_data_raw = credential.response.authenticator_data.as_ref();
        let data = AuthData::parse(auth_data_raw)?;
        let client_data_json = credential.response.client_data_json.as_ref();
        let client = ClientData::parse(client_data_json)?;
        client.check("webauthn.get", state.challenge.as_ref(), &self.origins)?;
        if !bool::from(data.rp_id_hash.ct_eq(&self.id_hash)) {
            return Err(Rejected("the relying party id hash differs"));
        }
        if !data.flags.up {
            return Err(Rejected("the user was not present"));
        }
        if !data.flags.uv {
            return Err(Rejected("the user was not verified"));
        }
        let stored = &passkey.cred;
        if stored.backup_eligible != data.flags.be
            && !(state.allow_backup_eligible_upgrade && !stored.backup_eligible && data.flags.be)
        {
            return Err(Rejected("backup eligibility changed"));
        }
        if data.flags.bs && !stored.backup_eligible {
            return Err(Rejected("backed up but not backup eligible"));
        }
        let mut message = auth_data_raw.to_vec();
        message.extend_from_slice(&ridm_core::crypto::Sha256::digest(client_data_json));
        if !stored
            .cred
            .verify(&message, credential.response.signature.as_ref())
        {
            return Err(Rejected("the signature does not verify"));
        }
        if (data.counter > 0 || stored.counter > 0) && data.counter <= stored.counter {
            return Err(Rejected(
                "the counter did not advance (a cloned credential?)",
            ));
        }
        Ok(Assertion {
            cred_id: raw_id.to_vec(),
            counter: data.counter,
            user_verified: data.flags.uv,
            backup_eligible: data.flags.be,
            backup_state: data.flags.bs,
        })
    }
}

/// `clientDataJSON` (WebAuthn §5.8.1): the fields rIDM checks; others,
/// `topOrigin` and `tokenBinding` among them, are ignored.
#[derive(Debug, Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    type_: String,
    challenge: Base64UrlSafeData,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
}

impl ClientData {
    fn parse(bytes: &[u8]) -> Result<Self, Rejected> {
        serde_json::from_slice(bytes).map_err(|_| Rejected("clientDataJSON is not JSON"))
    }

    fn check(&self, kind: &str, challenge: &[u8], origins: &[Url]) -> Result<(), Rejected> {
        if self.type_ != kind {
            return Err(Rejected("the client data type"));
        }
        if !bool::from(self.challenge.as_ref().ct_eq(challenge)) {
            return Err(Rejected("the challenge differs"));
        }
        let origin = Url::parse(&self.origin).map_err(|_| Rejected("the origin is not a URL"))?;
        if !origins
            .iter()
            .any(|allowed| origins_match(&origin, allowed))
        {
            return Err(Rejected("the origin is not allowed"));
        }
        Ok(())
    }
}

/// The same scheme, host and port (the scheme's default when absent).
/// webauthn-rs's rule with subdomains and other ports refused.
fn origins_match(origin: &Url, allowed: &Url) -> bool {
    if origin == allowed {
        return true;
    }
    origin.scheme() == allowed.scheme()
        && origin.port_or_known_default() == allowed.port_or_known_default()
        && origin.host() == allowed.host()
        && origin.host().is_some()
}

/// Authenticator data (WebAuthn §6.1).
struct AuthData {
    rp_id_hash: [u8; 32],
    flags: Flags,
    counter: u32,
    /// Credential id and COSE key, when attested credential data is present.
    credential: Option<(Vec<u8>, Value)>,
    extensions: Option<Value>,
}

impl AuthData {
    fn parse(bytes: &[u8]) -> Result<Self, Rejected> {
        let bad = || Rejected("malformed authenticator data");
        if bytes.len() < 37 {
            return Err(bad());
        }
        let rp_id_hash: [u8; 32] = bytes[..32].try_into().map_err(|_| bad())?;
        let flags = Flags::from(bytes[32]);
        let counter = u32::from_be_bytes(bytes[33..37].try_into().map_err(|_| bad())?);
        let mut rest = &bytes[37..];
        let credential = if flags.at {
            // aaguid (16) ‖ credential id length (2) ‖ credential id ‖ COSE key
            if rest.len() < 18 {
                return Err(bad());
            }
            let len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
            rest = &rest[18..];
            if rest.len() < len {
                return Err(bad());
            }
            let (id, after) = rest.split_at(len);
            let (key, after) = cbor::decode(after).map_err(|_| bad())?;
            rest = after;
            Some((id.to_vec(), key))
        } else {
            None
        };
        let extensions = if flags.ed {
            Some(cbor::decode(rest).map_err(|_| bad())?.0)
        } else {
            None
        };
        Ok(Self {
            rp_id_hash,
            flags,
            counter,
            credential,
            extensions,
        })
    }
}

/// Every parser an answer reaches, on arbitrary bytes, for the fuzz targets:
/// the attestation object, authenticator data, the credential key and
/// client data. Never panics; the result is whether each one parsed.
#[cfg(feature = "test-support")]
pub fn parse_untrusted(
    attestation_object: &[u8],
    auth_data: &[u8],
    client_data: &[u8],
) -> [bool; 4] {
    let attestation = cbor::decode_exact(attestation_object).ok();
    let data = AuthData::parse(auth_data).ok();
    let key = data
        .as_ref()
        .and_then(|d| d.credential.as_ref())
        .map(|(_, k)| {
            CoseKey::from_cbor(
                k,
                &[
                    CoseAlgorithm::ES256,
                    CoseAlgorithm::RS256,
                    CoseAlgorithm::EdDsa,
                ],
            )
            .is_ok()
        })
        .unwrap_or(false);
    [
        attestation.is_some(),
        data.is_some(),
        key,
        ClientData::parse(client_data).is_ok(),
    ]
}

/// The extension states webauthn-rs records for a new passkey.
fn registered_extensions(
    authenticator: Option<&Value>,
    credential: &RegisterPublicKeyCredential,
) -> Result<Json, Rejected> {
    let cred_protect = match authenticator.and_then(|e| e.get_text("credProtect")) {
        None => json!("Ignored"),
        Some(v) => {
            let policy = match v.as_int() {
                Some(1) => "userVerificationOptional",
                Some(2) => "userVerificationOptionalWithCredentialIDList",
                Some(3) => "userVerificationRequired",
                _ => return Err(Rejected("an invalid credProtect output")),
            };
            json!({"Set": policy})
        }
    };
    let hmac_create_secret = match authenticator.and_then(|e| e.get_text("hmac-secret")) {
        None => json!("NotRequested"),
        Some(Value::Bool(b)) => json!({"Unsolicited": b}),
        Some(_) => return Err(Rejected("an invalid hmac-secret output")),
    };
    let cred_props = match &credential.extensions.cred_props {
        Some(props) => json!({"Unsigned": {"rk": props.rk}}),
        None => json!("Ignored"),
    };
    Ok(json!({
        "cred_protect": cred_protect,
        "hmac_create_secret": hmac_create_secret,
        "appid": "NotRequested",
        "cred_props": cred_props,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn origins_match_on_scheme_host_and_port() {
        let allowed = url("https://id.example.com");
        assert!(origins_match(&url("https://id.example.com"), &allowed));
        assert!(origins_match(&url("https://id.example.com:443"), &allowed));
        assert!(origins_match(
            &url("https://id.example.com/login/"),
            &allowed
        ));
        assert!(!origins_match(&url("http://id.example.com"), &allowed));
        assert!(!origins_match(
            &url("https://id.example.com:8443"),
            &allowed
        ));
        assert!(!origins_match(&url("https://sub.id.example.com"), &allowed));
        assert!(!origins_match(&url("https://example.com"), &allowed));
    }

    #[test]
    fn the_relying_party_id_must_cover_the_origin() {
        assert!(RelyingParty::new("example.com", &url("https://id.example.com"), "x").is_ok());
        assert!(RelyingParty::new("id.example.com", &url("https://id.example.com"), "x").is_ok());
        assert!(RelyingParty::new("other.com", &url("https://id.example.com"), "x").is_err());
        assert!(RelyingParty::new("127.0.0.1", &url("https://127.0.0.1"), "x").is_err());
    }

    #[test]
    fn options_are_what_webauthn_rs_offered() {
        let rp = RelyingParty::new("localhost", &url("http://localhost:3000"), "Acme").unwrap();
        let user = Uuid::now_v7();
        let (ccr, state) = rp
            .start_registration(user, "alice", "Alice", &[vec![1, 2, 3]])
            .unwrap();
        let j = serde_json::to_value(&ccr).unwrap();
        let pk = &j["publicKey"];
        assert_eq!(pk["rp"], json!({"name": "Acme", "id": "localhost"}));
        assert_eq!(pk["user"]["name"], "alice");
        assert_eq!(pk["user"]["displayName"], "Alice");
        assert_eq!(pk["user"]["id"].as_str().unwrap().len(), 22, "16 raw bytes");
        assert_eq!(pk["challenge"].as_str().unwrap().len(), 43, "32 bytes");
        assert_eq!(
            pk["pubKeyCredParams"],
            json!([{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}])
        );
        assert_eq!(pk["timeout"], 300_000);
        assert_eq!(
            pk["excludeCredentials"],
            json!([{"type": "public-key", "id": "AQID"}])
        );
        assert_eq!(
            pk["authenticatorSelection"],
            json!({"residentKey": "discouraged", "requireResidentKey": false, "userVerification": "required"})
        );
        assert_eq!(pk["attestation"], "none");
        assert_eq!(
            pk["extensions"],
            json!({"credentialProtectionPolicy": "userVerificationRequired", "enforceCredentialProtectionPolicy": false, "uvm": true, "credProps": true})
        );
        assert_eq!(state.challenge.as_ref().len(), 32);

        let (rcr, state) = rp.start_discoverable();
        let j = serde_json::to_value(&rcr).unwrap();
        assert_eq!(j["mediation"], "conditional");
        assert_eq!(j["publicKey"]["allowCredentials"], json!([]));
        assert_eq!(j["publicKey"]["userVerification"], "required");
        assert_eq!(j["publicKey"]["extensions"], json!({"uvm": true}));
        assert!(!state.allow_backup_eligible_upgrade);
    }

    #[test]
    fn authenticator_data_is_bounds_checked() {
        assert!(AuthData::parse(&[0; 36]).is_err());
        let mut d = vec![0u8; 37];
        d[32] = 0x45; // UP, UV, AT, but no attested data
        assert!(AuthData::parse(&d).is_err());
        d.extend_from_slice(&[0; 16]);
        d.extend_from_slice(&[0xff, 0xff]); // an id longer than what follows
        assert!(AuthData::parse(&d).is_err());
        let mut ok = vec![7u8; 32];
        ok.push(0x05);
        ok.extend_from_slice(&9u32.to_be_bytes());
        let parsed = AuthData::parse(&ok).unwrap();
        assert_eq!(parsed.counter, 9);
        assert!(parsed.flags.up && parsed.flags.uv && !parsed.flags.at);
    }
}
