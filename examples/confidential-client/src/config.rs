//! What the app is told at startup.

/// Everything read from the environment, plus the endpoints discovery found.
#[derive(Debug, Clone)]
pub struct Config {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// Where this app is reachable, for the redirect URIs it registers.
    pub base_url: String,
    pub bind: String,
    /// The resource server this app calls with the access token it is given.
    pub api_url: String,
    pub api_audience: String,
    pub scopes: String,
    pub allow_http: bool,
    pub endpoints: Endpoints,
}

/// The four endpoints this app uses, read from the discovery document rather
/// than assembled from the issuer by hand.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Endpoints {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub end_session_endpoint: String,
    pub revocation_endpoint: Option<String>,
}

impl Config {
    /// Read the environment, then ask the issuer where its endpoints are.
    pub async fn load(http: &reqwest::Client) -> Result<Self, String> {
        let issuer = env("RIDM_ISSUER")?.trim_end_matches('/').to_string();
        let url = format!("{issuer}/.well-known/openid-configuration");
        let endpoints: Endpoints = http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("discovery at {url}: {e}"))?
            .error_for_status()
            .map_err(|e| format!("discovery at {url}: {e}"))?
            .json()
            .await
            .map_err(|e| format!("discovery at {url}: {e}"))?;
        // The document has to claim the issuer it was fetched from, or someone
        // else is telling us where to send our users (OIDC Discovery §4.3).
        if endpoints.issuer.trim_end_matches('/') != issuer {
            return Err(format!(
                "discovery at {url} names issuer `{}`",
                endpoints.issuer
            ));
        }

        Ok(Self {
            client_id: env("RIDM_CLIENT_ID")?,
            client_secret: env("RIDM_CLIENT_SECRET")?,
            base_url: var("BASE_URL", "http://localhost:3200")
                .trim_end_matches('/')
                .to_string(),
            bind: var("BIND_ADDR", "127.0.0.1:3200"),
            api_url: var("API_URL", "http://localhost:8081")
                .trim_end_matches('/')
                .to_string(),
            api_audience: var("API_AUDIENCE", "https://orders.example"),
            // `offline_access` is what asks for a refresh token; without it the
            // session ends when the access token does.
            scopes: var(
                "SCOPES",
                "openid profile email offline_access orders:read orders:write",
            ),
            allow_http: std::env::var("RIDM_ALLOW_HTTP").is_ok_and(|v| v == "true"),
            issuer,
            endpoints,
        })
    }

    pub fn redirect_uri(&self) -> String {
        format!("{}/callback", self.base_url)
    }

    pub fn post_logout_redirect_uri(&self) -> String {
        format!("{}/", self.base_url)
    }
}

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is required (see the README)"))
}

fn var(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}
