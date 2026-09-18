//! The protocol half: building the authorization request, spending the code,
//! refreshing, and reading a logout token.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::config::Config;
use crate::session::random_token;

/// What the token endpoint answers with.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
}

impl TokenResponse {
    pub fn expires_at(&self) -> DateTime<Utc> {
        Utc::now() + Duration::seconds(self.expires_in.unwrap_or(300))
    }
}

/// The PKCE challenge for a verifier (RFC 7636, `S256`).
///
/// A confidential client is not required to use PKCE — it has a secret — but
/// it costs nothing and it closes code injection, so rIDM's own console
/// clients do it and so does this one.
pub fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// A verifier of the length RFC 7636 asks for.
pub fn code_verifier() -> String {
    random_token()
}

/// Where to send the browser to sign in.
pub fn authorization_url(config: &Config, state: &str, nonce: &str, verifier: &str) -> String {
    let query = [
        ("response_type", "code"),
        ("client_id", &config.client_id),
        ("redirect_uri", &config.redirect_uri()),
        ("scope", &config.scopes),
        ("state", state),
        ("nonce", nonce),
        ("code_challenge", &code_challenge(verifier)),
        ("code_challenge_method", "S256"),
        // RFC 8707: which API the access token should be good for. Without it
        // the token is audienced to this client and the orders API refuses it.
        ("resource", &config.api_audience),
    ];
    format!(
        "{}?{}",
        config.endpoints.authorization_endpoint,
        encode_query(&query)
    )
}

/// Spend the authorization code. The client secret goes in the Authorization
/// header (`client_secret_basic`), never in the query string.
pub async fn exchange_code(
    http: &reqwest::Client,
    config: &Config,
    code: &str,
    verifier: &str,
) -> Result<TokenResponse, String> {
    post_token(
        http,
        config,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &config.redirect_uri()),
            ("code_verifier", verifier),
        ],
    )
    .await
}

/// Trade a refresh token for a fresh access token. rIDM rotates the refresh
/// token on every use, so the answer's `refresh_token` replaces the old one —
/// and presenting the old one again ends the whole family.
pub async fn refresh(
    http: &reqwest::Client,
    config: &Config,
    refresh_token: &str,
) -> Result<TokenResponse, String> {
    post_token(
        http,
        config,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("resource", &config.api_audience),
        ],
    )
    .await
}

/// Give a refresh token back at sign-out instead of leaving it live until it
/// expires (RFC 7009).
pub async fn revoke(http: &reqwest::Client, config: &Config, refresh_token: &str) {
    let Some(endpoint) = &config.endpoints.revocation_endpoint else {
        return;
    };
    let sent = http
        .post(endpoint)
        .basic_auth(&config.client_id, Some(&config.client_secret))
        .form(&[
            ("token", refresh_token),
            ("token_type_hint", "refresh_token"),
        ])
        .send()
        .await;
    // Revocation answers 200 whatever it finds, so there is nothing to check;
    // a failure here must not stop the user signing out.
    if let Err(e) = sent {
        tracing::warn!(error = %e, "could not revoke the refresh token");
    }
}

/// Where to send the browser to sign out (OIDC RP-Initiated Logout 1.0).
pub fn end_session_url(config: &Config, id_token: &str) -> String {
    let query = [
        ("id_token_hint", id_token),
        (
            "post_logout_redirect_uri",
            &config.post_logout_redirect_uri(),
        ),
        ("client_id", &config.client_id),
    ];
    format!(
        "{}?{}",
        config.endpoints.end_session_endpoint,
        encode_query(&query)
    )
}

async fn post_token(
    http: &reqwest::Client,
    config: &Config,
    form: &[(&str, &str)],
) -> Result<TokenResponse, String> {
    let response = http
        .post(&config.endpoints.token_endpoint)
        .basic_auth(&config.client_id, Some(&config.client_secret))
        .form(form)
        .send()
        .await
        .map_err(|e| format!("the token endpoint could not be reached: {e}"))?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        // The body is an OAuth error object; show it rather than the status,
        // since `invalid_grant` and `invalid_client` mean very different things.
        return Err(format!("the token endpoint refused: {status} {body}"));
    }
    serde_json::from_str(&body).map_err(|e| format!("the token response did not parse: {e}"))
}

/// `application/x-www-form-urlencoded`, which is what a query string is.
fn encode_query(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Everything outside the unreserved set is escaped (RFC 3986 §2.3).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_matches_the_rfc_vector() {
        // RFC 7636 appendix B.
        assert_eq!(
            code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn a_verifier_fits_the_grammar() {
        let verifier = code_verifier();
        assert!((43..=128).contains(&verifier.len()), "{verifier}");
        assert!(
            verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')),
            "{verifier}"
        );
    }

    #[test]
    fn a_redirect_uri_survives_being_put_in_a_query_string() {
        let encoded = encode_query(&[
            ("redirect_uri", "http://localhost:3200/callback?a=b&c=d"),
            ("scope", "openid profile"),
        ]);
        assert_eq!(
            encoded,
            "redirect_uri=http%3A%2F%2Flocalhost%3A3200%2Fcallback%3Fa%3Db%26c%3Dd\
             &scope=openid%20profile"
        );
    }
}
