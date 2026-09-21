//! Risk-based adaptive authentication (Phase 12.3).
//!
//! Every sign-in is measured against what the user has done before. Each
//! signal it raises contributes its weight, and the tenant's two thresholds
//! decide what happens to the score: nothing, a second factor this sign-in
//! must pass, or a refusal.
//!
//! The signals are deliberately cheap and derived from state rIDM already
//! keeps: the trusted-device cookie and the user's session history for
//! *new device*, `user_login_locations` for *new country* and *impossible
//! travel*, and `login_attempts` for *velocity*. A signal that cannot be
//! computed — no geo source, no history yet, no address — is not raised,
//! so a tenant that turns the policy on does not step up every user at once
//! and a deployment without a geo source still gets the other signals.
//!
//! The evaluation happens twice: when a first factor passes, and when a live
//! SSO session is reused at `/authorize` (a silent sign-in from somewhere
//! new is judged like any other). A trusted device does not waive it — the
//! device cookie says which browser this is, not who is holding it.

use chrono::Utc;
use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
use uuid::Uuid;

use crate::db;
use crate::error::AppResult;
use crate::models::{LoginLocation, RiskAction, RiskAssessment, RiskSignal, Tenant};
use crate::repos;
use crate::services::geoip::{self, Location};
use crate::state::AppState;

/// How many of a user's countries are considered. A user with more than this
/// many is well travelled enough that the signal says little either way.
const HISTORY_LIMIT: i64 = 50;

/// Two points closer than this are the same place as far as travel is
/// concerned: city-level coordinates move around without the user doing so.
const TRAVEL_MIN_KM: f64 = 100.0;

/// What one evaluation looks at, besides the tenant's policy and the user's
/// history.
#[derive(Debug, Default, Clone)]
pub struct Inputs<'a> {
    /// The address the request came from, for the velocity signal.
    pub ip: Option<&'a str>,
    /// Where that address is, when a geo source could say.
    pub location: Option<&'a Location>,
    /// The browser is neither a trusted device nor one this user has signed
    /// in from before. The caller decides this, because only it knows about
    /// the device cookie; a user's very first sign-in is not "new".
    pub new_device: bool,
}

/// Score a sign-in. An assessment is always returned, even for a policy that
/// is off — it is then empty and allows, which keeps the call sites free of
/// branches.
pub async fn evaluate(
    state: &AppState,
    tenant: &Tenant,
    user_id: Uuid,
    inputs: &Inputs<'_>,
) -> AppResult<RiskAssessment> {
    let policy = &tenant.settings.risk;
    let country = inputs.location.map(|l| l.country.clone());
    if !policy.enabled {
        return Ok(RiskAssessment {
            country,
            ..RiskAssessment::default()
        });
    }
    let mut signals = Vec::new();
    if inputs.new_device {
        signals.push(RiskSignal::NewDevice);
    }
    if let Some(location) = inputs.location {
        let history = history(state, tenant.id, user_id).await?;
        // With no history there is nothing to be new to.
        if !history.is_empty() {
            if !history.iter().any(|l| l.country == location.country) {
                signals.push(RiskSignal::NewCountry);
            }
            if travelled_impossibly(policy.impossible_travel_kmh, &history, location) {
                signals.push(RiskSignal::ImpossibleTravel);
            }
        }
    }
    if let Some(ip) = inputs.ip
        && policy.velocity_max_failures > 0
        && recent_failures(state, tenant.id, ip, policy.velocity_window_minutes).await?
            >= i64::from(policy.velocity_max_failures)
    {
        signals.push(RiskSignal::Velocity);
    }

    let weights = &policy.weights;
    let score = signals
        .iter()
        .map(|s| match s {
            RiskSignal::NewDevice => weights.new_device,
            RiskSignal::NewCountry => weights.new_country,
            RiskSignal::ImpossibleTravel => weights.impossible_travel,
            RiskSignal::Velocity => weights.velocity,
        })
        .sum();
    let action = if policy.block_at > 0 && score >= policy.block_at {
        RiskAction::Block
    } else if policy.step_up_at > 0 && score >= policy.step_up_at {
        RiskAction::StepUp
    } else {
        RiskAction::Allow
    };
    Ok(RiskAssessment {
        score,
        signals,
        action,
        country,
    })
}

/// Could the user have got from where they were last seen to here?
///
/// Measured against the most recent location that has coordinates: the last
/// place we actually know. Distances under [`TRAVEL_MIN_KM`] never raise the
/// signal, and neither does a policy with no speed limit.
fn travelled_impossibly(max_kmh: u32, history: &[LoginLocation], now_at: &Location) -> bool {
    if max_kmh == 0 {
        return false;
    }
    let Some(here) = now_at.coordinates() else {
        return false;
    };
    let Some((last, there)) = history
        .iter()
        .find_map(|l| Some((l, (l.latitude?, l.longitude?))))
    else {
        return false;
    };
    let km = geoip::distance_km(there, here);
    if km < TRAVEL_MIN_KM {
        return false;
    }
    // A minute's floor: two sign-ins in the same second from opposite sides
    // of the world must not divide by zero.
    let hours =
        ((Utc::now() - last.last_seen_at).num_seconds().max(0) as f64 / 3600.0).max(1.0 / 60.0);
    km / hours > f64::from(max_kmh)
}

async fn history(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
) -> AppResult<Vec<LoginLocation>> {
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let rows =
        repos::user_login_locations::recent(&mut *tx, tenant_id, user_id, HISTORY_LIMIT).await?;
    tx.commit().await?;
    Ok(rows)
}

async fn recent_failures(
    state: &AppState,
    tenant_id: Uuid,
    ip: &str,
    window_minutes: u32,
) -> AppResult<i64> {
    let since = Utc::now() - chrono::Duration::minutes(i64::from(window_minutes.max(1)));
    let mut tx = db::tenant_tx(&state.db, tenant_id).await?;
    let n = repos::login_attempts::failures_from_ip(&mut *tx, tenant_id, ip, since).await?;
    tx.commit().await?;
    Ok(n)
}

/// Remember where a sign-in came from, so the next one can be judged against
/// it. Only called once a sign-in is allowed to proceed: a refused attempt
/// must not teach the history that its country is normal.
pub async fn record_location(
    state: &AppState,
    tenant: &Tenant,
    user_id: Uuid,
    location: Option<&Location>,
) -> AppResult<()> {
    let (Some(location), true) = (location, tenant.settings.risk.enabled) else {
        return Ok(());
    };
    let mut tx = db::tenant_tx(&state.db, tenant.id).await?;
    repos::user_login_locations::record(
        &mut *tx,
        tenant.id,
        user_id,
        &location.country,
        location.latitude,
        location.longitude,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Put a step-up or a block in the audit log (and through it, on the
/// tenant's webhooks). An assessment that allows says nothing: a sign-in
/// that raised no signal is an ordinary sign-in.
pub fn announce(
    state: &AppState,
    tenant_id: Uuid,
    user_id: Uuid,
    assessment: &RiskAssessment,
    ip: Option<String>,
    user_agent: Option<String>,
) {
    let kind = match assessment.action {
        RiskAction::Allow => return,
        RiskAction::StepUp => EventKind::RiskStepUp {
            user_id,
            score: assessment.score,
            signals: assessment.signal_names(),
            country: assessment.country.clone(),
        },
        RiskAction::Block => EventKind::RiskBlocked {
            user_id,
            score: assessment.score,
            signals: assessment.signal_names(),
            country: assessment.country.clone(),
        },
    };
    metrics::counter!(
        "ridm_risk_decisions_total",
        "action" => match assessment.action {
            RiskAction::Block => "block",
            _ => "step_up",
        }
    )
    .increment(1);
    state.events.publish(
        Event::new(Some(tenant_id), Actor::User { id: user_id }, kind).with_request(ip, user_agent),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Duration};

    fn seen(lat: f64, lon: f64, ago: Duration) -> LoginLocation {
        LoginLocation {
            tenant_id: Uuid::nil(),
            user_id: Uuid::nil(),
            country: "GB".into(),
            latitude: Some(lat),
            longitude: Some(lon),
            logins: 1,
            first_seen_at: DateTime::<Utc>::MIN_UTC,
            last_seen_at: Utc::now() - ago,
        }
    }

    fn at(lat: f64, lon: f64) -> Location {
        Location {
            country: "AU".into(),
            latitude: Some(lat),
            longitude: Some(lon),
        }
    }

    #[test]
    fn london_to_sydney_in_an_hour_is_impossible_but_in_a_day_is_not() {
        let london = seen(51.5074, -0.1278, Duration::hours(1));
        assert!(travelled_impossibly(
            900,
            &[london],
            &at(-33.8688, 151.2093)
        ));
        let london = seen(51.5074, -0.1278, Duration::hours(23));
        assert!(!travelled_impossibly(
            900,
            &[london],
            &at(-33.8688, 151.2093)
        ));
    }

    #[test]
    fn the_same_city_is_never_impossible() {
        let earlier = seen(51.5074, -0.1278, Duration::seconds(1));
        assert!(!travelled_impossibly(900, &[earlier], &at(51.52, -0.13)));
    }

    #[test]
    fn nothing_to_measure_raises_nothing() {
        let known = seen(51.5074, -0.1278, Duration::hours(1));
        // No speed limit.
        assert!(!travelled_impossibly(
            0,
            std::slice::from_ref(&known),
            &at(-33.8688, 151.2093)
        ));
        // No coordinates here.
        let nowhere = Location {
            country: "AU".into(),
            latitude: None,
            longitude: None,
        };
        assert!(!travelled_impossibly(
            900,
            std::slice::from_ref(&known),
            &nowhere
        ));
        // No coordinates there.
        let mut blind = seen(0.0, 0.0, Duration::hours(1));
        blind.latitude = None;
        blind.longitude = None;
        assert!(!travelled_impossibly(
            900,
            &[blind],
            &at(-33.8688, 151.2093)
        ));
        // No history at all.
        assert!(!travelled_impossibly(900, &[], &at(-33.8688, 151.2093)));
    }

    #[test]
    fn the_most_recent_located_row_is_the_one_measured_from() {
        // The newest row has no coordinates, so the one behind it decides.
        let mut newest = seen(0.0, 0.0, Duration::minutes(30));
        newest.latitude = None;
        newest.longitude = None;
        let older = seen(51.5074, -0.1278, Duration::hours(1));
        assert!(travelled_impossibly(
            900,
            &[newest, older],
            &at(-33.8688, 151.2093)
        ));
    }
}
