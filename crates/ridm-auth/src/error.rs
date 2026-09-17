//! What can go wrong, and the RFC 6750 response each failure deserves.

#[cfg(feature = "axum")]
use std::fmt;

/// Every way a token can fail to authorise a request.
///
/// The variants separate "the token is not acceptable" (401, `invalid_token`)
/// from "the token is fine but does not carry enough" (403,
/// `insufficient_scope`) from "the key set could not be reached" (503), because
/// a caller that cannot tell them apart cannot retry correctly.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// No `Authorization: Bearer <token>` header was present.
    #[error("no bearer token was presented")]
    Missing,

    /// The token is not a well-formed JWS.
    #[error("the token is not a well-formed JWT")]
    Malformed,

    /// The JOSE header names no `kid`, so no key can be chosen.
    #[error("the token names no signing key (`kid`)")]
    NoKeyId,

    /// `kid` names a key the issuer does not publish (any more).
    #[error("no published key matches `kid` `{0}`")]
    UnknownKey(String),

    /// The signature does not verify under the named key.
    #[error("the token signature does not verify")]
    BadSignature,

    /// `alg` is not one this validator accepts, or does not match the key's.
    #[error("algorithm `{0}` is not accepted for this token")]
    UnacceptableAlgorithm(String),

    /// The JOSE `typ` header is not the expected one (`at+jwt` by default),
    /// which is what stops an ID token being replayed as an access token.
    #[error("token type `{found}` is not `{expected}`")]
    WrongType {
        /// The `typ` this validator was configured to require.
        expected: String,
        /// The `typ` the token carried.
        found: String,
    },

    /// `exp` is in the past, allowing for the configured leeway.
    #[error("the token has expired")]
    Expired,

    /// `nbf` is in the future, allowing for the configured leeway.
    #[error("the token is not valid yet")]
    NotYetValid,

    /// `iss` is not the issuer this validator was built for.
    #[error("the token was issued by `{found}`, not `{expected}`")]
    WrongIssuer {
        /// The issuer this validator accepts.
        expected: String,
        /// What the token claimed instead.
        found: String,
    },

    /// `aud` holds none of the audiences this validator was built for.
    #[error("the token audience does not include {0}")]
    WrongAudience(String),

    /// A claim this validator requires is absent or of the wrong shape.
    #[error("claim `{0}` is missing or malformed")]
    BadClaim(&'static str),

    /// The token is sender-constrained (RFC 9449 `cnf.jkt`) but this validator
    /// does not verify DPoP proofs, so accepting it would drop the binding.
    /// See [`ValidatorBuilder::allow_sender_constrained`].
    ///
    /// [`ValidatorBuilder::allow_sender_constrained`]: crate::ValidatorBuilder::allow_sender_constrained
    #[error("the token is sender-constrained and this validator cannot verify the proof")]
    SenderConstrained,

    /// A scope the route asked for is absent.
    #[error("the token is missing scope `{0}`")]
    MissingScope(String),

    /// A permission the route asked for is absent.
    #[error("the token is missing permission `{0}`")]
    MissingPermission(String),

    /// A role the route asked for is absent.
    #[error("the token is missing role `{0}`")]
    MissingRole(String),

    /// The key set could not be fetched and nothing usable was cached.
    #[error("the key set at {url} could not be read: {message}")]
    Jwks {
        /// The `jwks_uri` that was asked.
        url: String,
        /// Why it could not be read.
        message: String,
    },

    /// The discovery document could not be fetched or did not match the issuer.
    #[error("discovery at {url} failed: {message}")]
    Discovery {
        /// The discovery document that was asked.
        url: String,
        /// Why it could not be used.
        message: String,
    },

    /// The validator was built with an unusable configuration.
    #[error("{0}")]
    Config(String),
}

/// Which family a failure belongs to, and so which status it answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// 401 with no `error` code: nothing was presented.
    Unauthenticated,
    /// 401 `invalid_token`: something was presented and is not acceptable.
    InvalidToken,
    /// 403 `insufficient_scope`: a valid token that does not carry enough.
    InsufficientScope,
    /// 503: the issuer could not be reached; the token was never judged.
    Unavailable,
    /// 500: this side is misconfigured.
    Misconfigured,
}

impl AuthError {
    /// Which family this failure belongs to.
    pub fn kind(&self) -> Kind {
        match self {
            Self::Missing => Kind::Unauthenticated,
            Self::MissingScope(_) | Self::MissingPermission(_) | Self::MissingRole(_) => {
                Kind::InsufficientScope
            }
            Self::Jwks { .. } | Self::Discovery { .. } => Kind::Unavailable,
            Self::Config(_) => Kind::Misconfigured,
            _ => Kind::InvalidToken,
        }
    }

    /// HTTP status for this failure.
    pub fn status(&self) -> u16 {
        match self.kind() {
            Kind::Unauthenticated | Kind::InvalidToken => 401,
            Kind::InsufficientScope => 403,
            Kind::Unavailable => 503,
            Kind::Misconfigured => 500,
        }
    }

    /// The OAuth error code for `WWW-Authenticate` and the body (RFC 6750 §3.1).
    pub fn oauth_code(&self) -> Option<&'static str> {
        match self.kind() {
            Kind::Unauthenticated => None,
            Kind::InvalidToken => Some("invalid_token"),
            Kind::InsufficientScope => Some("insufficient_scope"),
            Kind::Unavailable | Kind::Misconfigured => None,
        }
    }

    /// The `WWW-Authenticate` challenge for a 401/403 (RFC 6750 §3).
    ///
    /// The description is this error's own message with `"` folded to `'`, so
    /// it always fits the quoted-string grammar.
    pub fn www_authenticate(&self, realm: &str) -> String {
        let mut challenge = format!("Bearer realm=\"{}\"", escape(realm));
        if let Some(code) = self.oauth_code() {
            challenge.push_str(&format!(
                ", error=\"{code}\", error_description=\"{}\"",
                escape(&self.to_string())
            ));
        }
        challenge
    }

    /// Did the issuer's key set stay out of reach? Such a request is worth
    /// retrying; every other failure is not.
    pub fn is_transient(&self) -> bool {
        self.kind() == Kind::Unavailable
    }
}

/// `"` and control characters have no place in a quoted-string.
fn escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '"' | '\\' => '\'',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect()
}

/// The problem body served alongside the challenge.
#[cfg(feature = "axum")]
pub(crate) struct Body<'a>(pub(crate) &'a AuthError);

#[cfg(feature = "axum")]
impl fmt::Display for Body<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let body = match self.0.oauth_code() {
            Some(code) => serde_json::json!({
                "error": code,
                "error_description": self.0.to_string(),
            }),
            None => serde_json::json!({ "error_description": self.0.to_string() }),
        };
        write!(f, "{body}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_family_answers_with_its_own_status_and_code() {
        let cases = [
            (AuthError::Missing, 401, None),
            (AuthError::Expired, 401, Some("invalid_token")),
            (
                AuthError::MissingPermission("orders:read".into()),
                403,
                Some("insufficient_scope"),
            ),
            (
                AuthError::Jwks {
                    url: "https://idp/jwks".into(),
                    message: "timeout".into(),
                },
                503,
                None,
            ),
        ];
        for (error, status, code) in cases {
            assert_eq!(error.status(), status, "{error}");
            assert_eq!(error.oauth_code(), code, "{error}");
        }
    }

    #[test]
    fn a_challenge_never_breaks_out_of_its_quoted_string() {
        let error = AuthError::WrongIssuer {
            expected: "https://idp/t/acme".into(),
            found: "https://evil\", scope=\"admin".into(),
        };
        let challenge = error.www_authenticate("api");
        assert_eq!(challenge.matches('"').count() % 2, 0, "{challenge}");
        assert!(!challenge.contains("scope=\""), "{challenge}");
        assert!(challenge.contains("error=\"invalid_token\""));
    }

    #[test]
    fn only_an_unreachable_key_set_is_worth_a_retry() {
        assert!(
            AuthError::Jwks {
                url: "https://idp/jwks".into(),
                message: "connect".into()
            }
            .is_transient()
        );
        assert!(!AuthError::BadSignature.is_transient());
        assert!(!AuthError::Missing.is_transient());
    }
}
