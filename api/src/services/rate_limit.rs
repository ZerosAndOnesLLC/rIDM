//! Request ceilings on the OAuth and sign-in endpoints.
//!
//! Every limit is a fixed window counted in Valkey, so all nodes share one
//! view. One request touches up to four buckets (deployment-wide address,
//! tenant address, tenant client, tenant total); one Lua round trip per
//! Valkey they live on (one, without regional Valkeys) increments them all
//! and reports each count with the time left in its window. A request that exceeds any bucket is refused with `429`,
//! `Retry-After` and the `RateLimit-*` headers of the tightest bucket.
//!
//! Valkey being unreachable fails open with a warning: the limiter protects
//! against abuse, it is not an authorization control.

use std::sync::LazyLock;

use uuid::Uuid;

use crate::cache::keys;
use crate::error::{AppError, AppResult};
use crate::models::{RateLimitPolicy, Tenant};
use crate::state::AppState;

/// Which family of endpoints a request belongs to (each has its own per-address limit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// `/token`, `/introspect`, `/revoke`, `/userinfo`, `/device_authorization`.
    Token,
    /// `/authorize`, `/par`, dynamic client registration.
    Authorize,
    /// The browser flow API and its neighbours.
    Flows,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Authorize => "authorize",
            Self::Flows => "flows",
        }
    }

    fn per_ip(self, policy: &RateLimitPolicy) -> u32 {
        match self {
            Self::Token => policy.token_per_ip,
            Self::Authorize => policy.authorize_per_ip,
            Self::Flows => policy.flows_per_ip,
        }
    }
}

/// One bucket's state after the request was counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bucket {
    pub limit: u32,
    /// Requests left in the window (0 when this request was over the limit).
    pub remaining: u32,
    /// Seconds until the window resets.
    pub reset_secs: u64,
    pub exceeded: bool,
}

/// The outcome for a request: the tightest bucket (for headers) and whether
/// any bucket refused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub tightest: Option<Bucket>,
    pub retry_after_secs: Option<u64>,
}

impl Decision {
    pub const UNLIMITED: Self = Self {
        tightest: None,
        retry_after_secs: None,
    };

    pub fn allowed(&self) -> bool {
        self.retry_after_secs.is_none()
    }
}

/// One bucket: count `KEYS[1]` in a window of `ARGV[1]` milliseconds and
/// return `count, pttl`. One key per call keeps it valid on a cluster.
static HIT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r#"
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {n, ttl}
"#,
    )
});

/// [`HIT`] over several keys at once: `KEYS[i]` with window `ARGV[i]`,
/// answering `{n1, ttl1, n2, ttl2, …}`.
static HIT_MANY: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r#"
local out = {}
for i, key in ipairs(KEYS) do
  local n = redis.call('INCR', key)
  if n == 1 then redis.call('PEXPIRE', key, ARGV[i]) end
  local ttl = redis.call('PTTL', key)
  if ttl < 0 then
    redis.call('PEXPIRE', key, ARGV[i])
    ttl = tonumber(ARGV[i])
  end
  out[#out + 1] = n
  out[#out + 1] = ttl
end
return out
"#,
    )
});

struct Want {
    key: String,
    limit: u32,
    window_ms: u64,
}

/// Count this request against the address and tenant buckets of `category`
/// (`ip` is `None` when the address is unknown: only the tenant total applies).
pub async fn hit(
    state: &AppState,
    tenant: Option<&Tenant>,
    category: Category,
    ip: Option<&str>,
) -> Decision {
    let region = tenant.and_then(|t| t.data_region.as_deref());
    run(state, region, buckets(state, tenant, category, ip)).await
}

/// Count a request against one client's bucket (`token_per_client`); the
/// address and tenant buckets were already charged by the route's layer.
pub async fn hit_client(state: &AppState, tenant: &Tenant, client: Uuid) -> Decision {
    let policy = &tenant.settings.rate_limits;
    if !state.config.rate_limits.enabled || !policy.enabled || policy.token_per_client == 0 {
        return Decision::UNLIMITED;
    }
    run(
        state,
        tenant.data_region.as_deref(),
        vec![Want {
            key: keys::tenant_rate_limit(tenant.id, &format!("client:{client}")),
            limit: policy.token_per_client,
            window_ms: window_ms(policy),
        }],
    )
    .await
}

async fn run(state: &AppState, region: Option<&str>, wants: Vec<Want>) -> Decision {
    if wants.is_empty() {
        return Decision::UNLIMITED;
    }
    match count(state, region, &wants).await {
        Ok(counts) => decide(&wants, &counts),
        Err(err) => {
            tracing::warn!(error = %err, "rate limiter unavailable; allowing request");
            Decision::UNLIMITED
        }
    }
}

fn window_ms(policy: &RateLimitPolicy) -> u64 {
    u64::from(policy.window_secs.clamp(1, 3600)) * 1000
}

fn buckets(
    state: &AppState,
    tenant: Option<&Tenant>,
    category: Category,
    ip: Option<&str>,
) -> Vec<Want> {
    let cfg = &state.config.rate_limits;
    if !cfg.enabled {
        return vec![];
    }
    let mut wants = Vec::with_capacity(4);
    if cfg.ip_per_minute > 0
        && let Some(ip) = ip
    {
        wants.push(Want {
            key: keys::rate_limit(&format!("ip:{ip}")),
            limit: cfg.ip_per_minute,
            window_ms: 60_000,
        });
    }
    let Some(tenant) = tenant else {
        return wants;
    };
    let policy = &tenant.settings.rate_limits;
    if !policy.enabled {
        return wants;
    }
    let window_ms = window_ms(policy);
    let tid = tenant.id;
    let per_ip = category.per_ip(policy);
    if per_ip > 0
        && let Some(ip) = ip
    {
        wants.push(Want {
            key: keys::tenant_rate_limit(tid, &format!("{}:ip:{ip}", category.as_str())),
            limit: per_ip,
            window_ms,
        });
    }
    if policy.tenant_total > 0 {
        wants.push(Want {
            key: keys::tenant_rate_limit(tid, "all"),
            limit: policy.tenant_total,
            window_ms,
        });
    }
    wants
}

/// Count every bucket, one script call per Valkey the buckets live on: the
/// deployment-wide ones on the home Valkey, a tenant's on its region's (the
/// same one without regional Valkeys). A cluster may keep a request's keys on
/// different nodes, so there each bucket is its own call.
async fn count(
    state: &AppState,
    region: Option<&str>,
    wants: &[Want],
) -> AppResult<Vec<(u64, u64)>> {
    if matches!(
        state.redis.topology(),
        crate::cache::Topology::Cluster { .. }
    ) {
        return count_each(state, wants).await;
    }
    let is_tenant = |w: &Want| crate::cache::key_tenant(w.key.as_bytes()).is_some();
    let groups: Vec<Vec<usize>> = if state.redis.same_backend(None, region) {
        vec![(0..wants.len()).collect()]
    } else {
        let (tenant, global): (Vec<usize>, Vec<usize>) =
            (0..wants.len()).partition(|&i| is_tenant(&wants[i]));
        [global, tenant]
            .into_iter()
            .filter(|g| !g.is_empty())
            .collect()
    };
    let mut out = vec![(0, 0); wants.len()];
    let mut conn = state.redis.get().await?;
    for group in groups {
        let mut call = HIT_MANY.prepare_invoke();
        for &i in &group {
            call.key(&wants[i].key).arg(wants[i].window_ms);
        }
        let flat: Vec<i64> = call
            .invoke_async(&mut conn)
            .await
            .map_err(|e| AppError::Cache(e.to_string()))?;
        for (slot, &i) in group.iter().enumerate() {
            out[i] = pair_of(flat.get(slot * 2).copied(), flat.get(slot * 2 + 1).copied());
        }
    }
    Ok(out)
}

/// A count and the milliseconds left in its window, as the scripts return them.
fn pair_of(n: Option<i64>, ttl: Option<i64>) -> (u64, u64) {
    (
        n.map(|n| u64::try_from(n).unwrap_or(u64::MAX)).unwrap_or(0),
        ttl.unwrap_or(0).max(0) as u64,
    )
}

/// One call per bucket (a cluster's keys may be on different nodes).
async fn count_each(state: &AppState, wants: &[Want]) -> AppResult<Vec<(u64, u64)>> {
    let mut conn = state.redis.get().await?;
    let mut out = Vec::with_capacity(wants.len());
    for w in wants {
        let pair: Vec<i64> = HIT
            .key(&w.key)
            .arg(w.window_ms)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| AppError::Cache(e.to_string()))?;
        out.push(pair_of(pair.first().copied(), pair.get(1).copied()));
    }
    Ok(out)
}

fn decide(wants: &[Want], counts: &[(u64, u64)]) -> Decision {
    let mut tightest: Option<Bucket> = None;
    let mut retry_after: Option<u64> = None;
    for (w, (n, ttl_ms)) in wants.iter().zip(counts) {
        let reset_secs = ttl_ms.div_ceil(1000).max(1);
        let exceeded = *n > u64::from(w.limit);
        let remaining = u64::from(w.limit).saturating_sub(*n);
        let bucket = Bucket {
            limit: w.limit,
            remaining: u32::try_from(remaining).unwrap_or(u32::MAX),
            reset_secs,
            exceeded,
        };
        if exceeded {
            retry_after = Some(retry_after.map_or(reset_secs, |r| r.max(reset_secs)));
        }
        let tighter = match tightest {
            None => true,
            Some(t) => bucket.remaining < t.remaining,
        };
        if tighter {
            tightest = Some(bucket);
        }
    }
    if retry_after.is_some() {
        metrics::counter!("ridm_rate_limit_rejections_total").increment(1);
    }
    Decision {
        tightest,
        retry_after_secs: retry_after,
    }
}

/// Reject when the policy's numbers are out of range (settings PATCH).
pub fn validate_policy(p: &RateLimitPolicy) -> AppResult<()> {
    if !(1..=3600).contains(&p.window_secs) {
        return Err(AppError::BadRequest(
            "rate_limits.window_secs must be between 1 and 3600".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn want(limit: u32) -> Want {
        Want {
            key: "k".into(),
            limit,
            window_ms: 60_000,
        }
    }

    #[test]
    fn tightest_bucket_and_retry_after() {
        let wants = [want(10), want(5), want(100)];
        let d = decide(&wants, &[(3, 30_000), (5, 12_000), (50, 59_999)]);
        assert!(d.allowed());
        let t = d.tightest.unwrap();
        assert_eq!((t.limit, t.remaining, t.reset_secs), (5, 0, 12));

        let d = decide(&wants, &[(11, 30_000), (6, 12_000), (50, 1)]);
        assert_eq!(d.retry_after_secs, Some(30));
        let t = d.tightest.unwrap();
        assert_eq!(t.remaining, 0);
        assert!(t.exceeded);
    }

    #[test]
    fn no_buckets_means_unlimited() {
        assert_eq!(decide(&[], &[]), Decision::UNLIMITED);
    }
}
