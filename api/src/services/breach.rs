//! Breached-password check against a Have I Been Pwned compatible range
//! API (`GET {base}/{first five SHA-1 hex digits}` answering
//! `SUFFIX:COUNT` lines). Only the five-digit prefix leaves the server; the
//! match happens here. Pluggable through [`BreachChecker`]; the deployment
//! switches it off entirely for air-gapped installs, and tenants opt in with
//! `password.check_breached`.

use std::time::Duration;

use async_trait::async_trait;
use ridm_core::providers::{BreachChecker, ProviderError};
use url::Url;

/// The public Have I Been Pwned range endpoint.
pub const HIBP_RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";

pub struct HibpChecker {
    base: Url,
    http: reqwest::Client,
}

impl HibpChecker {
    pub fn new(base: Url) -> Self {
        Self {
            base,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .user_agent(concat!("rIDM/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("reqwest client"),
        }
    }
}

/// Count of `suffix` in a range response (`SUFFIX:COUNT` per line; padded
/// responses carry zero-count lines that must not match).
fn count_in(body: &str, suffix: &str) -> u64 {
    body.lines()
        .filter_map(|line| line.trim().split_once(':'))
        .filter(|(s, _)| s.eq_ignore_ascii_case(suffix))
        .filter_map(|(_, n)| n.trim().parse::<u64>().ok())
        .sum()
}

#[async_trait]
impl BreachChecker for HibpChecker {
    async fn count(&self, sha1_hex: &str) -> Result<u64, ProviderError> {
        if sha1_hex.len() != 40 || !sha1_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ProviderError::rejected("not a SHA-1 hex digest"));
        }
        let (prefix, suffix) = sha1_hex.split_at(5);
        let url = self
            .base
            .join(prefix)
            .map_err(ProviderError::configuration)?;
        let res = self
            .http
            .get(url)
            // Every answer then has the same shape, so its size reveals nothing.
            .header("Add-Padding", "true")
            .send()
            .await
            .map_err(ProviderError::unavailable)?;
        if !res.status().is_success() {
            return Err(ProviderError::Unavailable(format!(
                "range API answered {}",
                res.status()
            )));
        }
        let body = res.text().await.map_err(ProviderError::unavailable)?;
        Ok(count_in(&body, suffix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_the_matching_suffix_only() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n011053FD0102E94D6AE2F8B83D76FAF94F6:0\r\n";
        assert_eq!(count_in(body, "00D4F6E8FA6EECAD2A3AA415EEC418D38EC"), 2);
        assert_eq!(count_in(body, "00d4f6e8fa6eecad2a3aa415eec418d38ec"), 2);
        assert_eq!(count_in(body, "011053FD0102E94D6AE2F8B83D76FAF94F6"), 0);
        assert_eq!(count_in(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 0);
    }
}
