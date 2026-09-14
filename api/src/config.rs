//! Typed configuration loaded from environment variables (12-factor).
//!
//! Every deployment (bare metal, docker-compose, Kubernetes, any cloud) uses the
//! same image and configures it through the variables documented in `.env.example`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use ipnet::IpNet;
use url::Url;

use crate::util::secret::SecretBytes;

/// Length in bytes of the master key used to encrypt secrets at rest.
pub const MASTER_KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("invalid value for {name}: {reason}")]
    Invalid { name: &'static str, reason: String },
    #[error("failed to read {name} from {path}: {source}")]
    Io {
        name: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

impl FromStr for LogFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "pretty" | "text" => Ok(Self::Pretty),
            other => Err(format!("expected `json` or `pretty`, got `{other}`")),
        }
    }
}

/// Native TLS termination. When absent, TLS is expected to be terminated by the
/// operator's reverse proxy or load balancer.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Postgres connection string.
    pub database_url: String,
    /// Redis / Valkey connection string.
    pub redis_url: String,
    /// Externally visible base URL, e.g. `https://id.example.com`. Issuer URLs
    /// are derived from it: `{PUBLIC_URL}/t/{tenant_slug}`.
    pub public_url: Url,
    /// 32-byte key that encrypts secrets at rest.
    pub master_key: SecretBytes,
    /// Socket address the HTTP(S) listener binds to.
    pub bind_addr: SocketAddr,
    pub log_format: LogFormat,
    /// Serve Swagger UI at `/docs`. Disable in production.
    pub docs_enabled: bool,
    /// Set the `Secure` attribute on cookies. Only disable for plain-HTTP local dev.
    pub cookie_secure: bool,
    /// Peers whose `X-Forwarded-For` / `Forwarded` headers are trusted.
    pub trusted_proxies: Vec<IpNet>,
    pub tls: Option<TlsConfig>,
    pub db_pool_min: u32,
    pub db_pool_max: u32,
    /// Apply pending migrations at startup.
    pub migrate_on_start: bool,
}

impl Config {
    /// Load configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url = required("DATABASE_URL")?;
        let redis_url = required("REDIS_URL")?;
        let public_url = parse("PUBLIC_URL", required("PUBLIC_URL")?, |v| {
            Url::parse(&v).map_err(|e| e.to_string()).and_then(|u| {
                if !matches!(u.scheme(), "http" | "https") {
                    return Err("scheme must be http or https".into());
                }
                Ok(u)
            })
        })?;
        let master_key = load_master_key()?;
        let bind_addr = parse(
            "BIND_ADDR",
            optional("BIND_ADDR").unwrap_or_else(|| "0.0.0.0:8080".to_string()),
            |v| v.parse::<SocketAddr>().map_err(|e| e.to_string()),
        )?;
        let log_format = parse(
            "LOG_FORMAT",
            optional("LOG_FORMAT").unwrap_or_else(|| "json".to_string()),
            |v| v.parse::<LogFormat>(),
        )?;
        let docs_enabled = parse_bool("DOCS_ENABLED", false)?;
        let cookie_secure = parse_bool("COOKIE_SECURE", true)?;
        let trusted_proxies = parse(
            "TRUSTED_PROXIES",
            optional("TRUSTED_PROXIES").unwrap_or_default(),
            |v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        s.parse::<IpNet>().or_else(|_| {
                            s.parse::<std::net::IpAddr>()
                                .map(IpNet::from)
                                .map_err(|e| format!("`{s}`: {e}"))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            },
        )?;
        let tls = match (optional("TLS_CERT"), optional("TLS_KEY")) {
            (Some(cert), Some(key)) => Some(TlsConfig {
                cert_path: PathBuf::from(cert),
                key_path: PathBuf::from(key),
            }),
            (None, None) => None,
            _ => {
                return Err(ConfigError::Invalid {
                    name: "TLS_CERT",
                    reason: "TLS_CERT and TLS_KEY must be set together".into(),
                });
            }
        };
        let db_pool_min = parse_u32("DB_POOL_MIN", 2)?;
        let db_pool_max = parse_u32("DB_POOL_MAX", 20)?;
        if db_pool_min > db_pool_max {
            return Err(ConfigError::Invalid {
                name: "DB_POOL_MIN",
                reason: "must not exceed DB_POOL_MAX".into(),
            });
        }
        let migrate_on_start = parse_bool("MIGRATE_ON_START", false)?;

        Ok(Self {
            database_url,
            redis_url,
            public_url,
            master_key,
            bind_addr,
            log_format,
            docs_enabled,
            cookie_secure,
            trusted_proxies,
            tls,
            db_pool_min,
            db_pool_max,
            migrate_on_start,
        })
    }

    /// Issuer URL for a tenant: `{PUBLIC_URL}/t/{slug}` (no trailing slash).
    pub fn issuer_for(&self, tenant_slug: &str) -> String {
        format!(
            "{}/t/{tenant_slug}",
            self.public_url.as_str().trim_end_matches('/')
        )
    }
}

fn optional(name: &'static str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    optional(name).ok_or(ConfigError::Missing(name))
}

fn parse<T, E: ToString>(
    name: &'static str,
    raw: String,
    f: impl FnOnce(String) -> Result<T, E>,
) -> Result<T, ConfigError> {
    f(raw).map_err(|e| ConfigError::Invalid {
        name,
        reason: e.to_string(),
    })
}

fn parse_bool(name: &'static str, default: bool) -> Result<bool, ConfigError> {
    match optional(name) {
        None => Ok(default),
        Some(v) => match v.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(ConfigError::Invalid {
                name,
                reason: format!("expected a boolean, got `{other}`"),
            }),
        },
    }
}

fn parse_u32(name: &'static str, default: u32) -> Result<u32, ConfigError> {
    match optional(name) {
        None => Ok(default),
        Some(v) => v.parse::<u32>().map_err(|e| ConfigError::Invalid {
            name,
            reason: e.to_string(),
        }),
    }
}

/// `MASTER_KEY` (hex or base64 of 32 bytes) or `MASTER_KEY_FILE` (raw 32 bytes,
/// or the same textual encodings). The env var takes precedence.
fn load_master_key() -> Result<SecretBytes, ConfigError> {
    if let Some(v) = optional("MASTER_KEY") {
        return decode_master_key("MASTER_KEY", v.trim().as_bytes());
    }
    if let Some(path) = optional("MASTER_KEY_FILE") {
        let path = PathBuf::from(path);
        let bytes = std::fs::read(&path).map_err(|source| ConfigError::Io {
            name: "MASTER_KEY_FILE",
            path: path.clone(),
            source,
        })?;
        if bytes.len() == MASTER_KEY_LEN {
            return Ok(SecretBytes::new(bytes));
        }
        let trimmed = bytes.trim_ascii();
        return decode_master_key("MASTER_KEY_FILE", trimmed);
    }
    Err(ConfigError::Missing("MASTER_KEY or MASTER_KEY_FILE"))
}

fn decode_master_key(name: &'static str, raw: &[u8]) -> Result<SecretBytes, ConfigError> {
    use base64::Engine as _;

    let decoded = hex::decode(raw)
        .ok()
        .or_else(|| base64::engine::general_purpose::STANDARD.decode(raw).ok())
        .or_else(|| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(raw)
                .ok()
        })
        .ok_or_else(|| ConfigError::Invalid {
            name,
            reason: "expected hex or base64".into(),
        })?;
    if decoded.len() != MASTER_KEY_LEN {
        return Err(ConfigError::Invalid {
            name,
            reason: format!(
                "must decode to {MASTER_KEY_LEN} bytes, got {}",
                decoded.len()
            ),
        });
    }
    Ok(SecretBytes::new(decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_accepts_hex_and_base64() {
        let hex_key = "00".repeat(MASTER_KEY_LEN);
        assert!(decode_master_key("MASTER_KEY", hex_key.as_bytes()).is_ok());
        let b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert!(decode_master_key("MASTER_KEY", b64.as_bytes()).is_ok());
        assert!(decode_master_key("MASTER_KEY", b"tooshort").is_err());
    }

    #[test]
    fn log_format_parses() {
        assert_eq!("JSON".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert_eq!("pretty".parse::<LogFormat>().unwrap(), LogFormat::Pretty);
        assert!("xml".parse::<LogFormat>().is_err());
    }
}
