//! The FAPI 2.0 Security Profile, as a per-client switch
//! (`security_profile: fapi2`). Registration refuses what the profile rules
//! out (see `services::clients`); the checks here run where requests arrive:
//!
//! * only pushed authorization requests (`/authorize` refuses the rest);
//! * PKCE with S256 on every authorization request;
//! * `private_key_jwt` assertions whose `aud` is the issuer, as a string;
//! * every JWS the client signs (assertions, request objects, DPoP proofs)
//!   and every one rIDM signs for it (ID tokens, access tokens, JARM
//!   responses) uses PS256, ES256 or EdDSA (§5.4.1);
//! * sender-constrained (DPoP) tokens;
//! * refresh tokens that are not rotated (§5.3.2.1).
//!
//! mTLS client authentication and certificate-bound tokens are not offered
//! yet, so DPoP is the only sender constraint and `private_key_jwt` the only
//! client authentication.

use jsonwebtoken::Algorithm;

use crate::models::{SigningAlg, Tenant};

/// Whether a JWS the client signed uses an algorithm the profile allows.
pub fn allows_jws(alg: Algorithm) -> bool {
    matches!(alg, Algorithm::PS256 | Algorithm::ES256 | Algorithm::EdDSA)
}

/// Whether rIDM may sign with `alg` for a FAPI client (rIDM has no PS256
/// keys, so ES256 and EdDSA).
pub fn allows_signing(alg: SigningAlg) -> bool {
    matches!(alg, SigningAlg::ES256 | SigningAlg::EdDSA)
}

/// What rIDM signs with for a FAPI client: the tenant's default algorithm
/// when the profile allows it, ES256 otherwise.
pub fn signing_alg(tenant: &Tenant) -> SigningAlg {
    let default = tenant.settings.keys.default_alg;
    if allows_signing(default) {
        default
    } else {
        SigningAlg::ES256
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_profiles_algorithms_pass() {
        for alg in [Algorithm::PS256, Algorithm::ES256, Algorithm::EdDSA] {
            assert!(allows_jws(alg), "{alg:?}");
        }
        for alg in [
            Algorithm::RS256,
            Algorithm::RS512,
            Algorithm::PS384,
            Algorithm::ES384,
            Algorithm::HS256,
        ] {
            assert!(!allows_jws(alg), "{alg:?}");
        }
        assert!(!allows_signing(SigningAlg::RS256));
        assert!(allows_signing(SigningAlg::EdDSA));
    }
}
