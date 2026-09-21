//! Phase 12.7: the risk policy as a matrix. Every combination of the four
//! signals' inputs (a new device; where the sign-in comes from; an address
//! behind many failures) is scored under several policies, and the outcome
//! must be exactly the sum of the raised signals' weights measured against
//! the two thresholds — with a threshold of 0 switching its outcome off, and
//! a disabled policy raising nothing at all. `risk_policy.rs` covers the
//! sign-in paths that act on the outcome; this pins the scoring itself.

mod common;

use common::TestApp;
use ridm_api::models::{NewUser, RiskAction, RiskPolicy, RiskSignal, RiskWeights, Tenant};
use ridm_api::services::geoip::Location;
use ridm_api::services::risk::{self, Inputs};
use ridm_api::services::{tenants, users};
use ridm_core::events::Actor;
use uuid::Uuid;

const FAILING_IP: &str = "198.51.100.66";
const CLEAN_IP: &str = "198.51.100.7";

fn at(country: &str, coords: Option<(f64, f64)>) -> Location {
    Location {
        country: country.into(),
        latitude: coords.map(|c| c.0),
        longitude: coords.map(|c| c.1),
    }
}

fn with_policy(tenant: &Tenant, policy: RiskPolicy) -> Tenant {
    let mut t = tenant.clone();
    t.settings.0.risk = policy;
    t
}

fn expected_action(score: u32, policy: &RiskPolicy) -> RiskAction {
    if policy.block_at > 0 && score >= policy.block_at {
        RiskAction::Block
    } else if policy.step_up_at > 0 && score >= policy.step_up_at {
        RiskAction::StepUp
    } else {
        RiskAction::Allow
    }
}

fn weight(w: &RiskWeights, s: &RiskSignal) -> u32 {
    match s {
        RiskSignal::NewDevice => w.new_device,
        RiskSignal::NewCountry => w.new_country,
        RiskSignal::ImpossibleTravel => w.impossible_travel,
        RiskSignal::Velocity => w.velocity,
    }
}

async fn new_user(app: &TestApp) -> Uuid {
    users::create(
        &app.state,
        app.tenant.id,
        Actor::System,
        NewUser {
            username: format!("r-{}", &Uuid::new_v4().simple().to_string()[..10]),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .id
}

#[tokio::test]
async fn every_signal_combination_under_every_policy() {
    let app = TestApp::spawn().await;
    let base = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let on = RiskPolicy {
        enabled: true,
        ..RiskPolicy::default()
    };
    // The user was last seen in London a moment ago.
    let user = new_user(&app).await;
    let london = at("GB", Some((51.5074, -0.1278)));
    risk::record_location(
        &app.state,
        &with_policy(&base, on.clone()),
        user,
        Some(&london),
    )
    .await
    .unwrap();
    // Ten failures from one address, the default velocity threshold.
    let mut tx = ridm_api::db::tenant_tx(&app.state.db, base.id)
        .await
        .unwrap();
    for _ in 0..on.velocity_max_failures {
        ridm_api::repos::login_attempts::record(
            &mut *tx,
            base.id,
            "someone",
            Some(FAILING_IP),
            false,
            Some("bad_password"),
        )
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();

    // Where the sign-in comes from, and what that alone must raise.
    let places: Vec<(&str, Option<Location>, Vec<RiskSignal>)> = vec![
        ("no location", None, vec![]),
        ("London again", Some(london.clone()), vec![]),
        (
            // 260 km in no time, but the same country.
            "Manchester now",
            Some(at("GB", Some((53.4808, -2.2426)))),
            vec![RiskSignal::ImpossibleTravel],
        ),
        (
            "Paris now",
            Some(at("FR", Some((48.8566, 2.3522)))),
            vec![RiskSignal::NewCountry, RiskSignal::ImpossibleTravel],
        ),
        (
            // A country-only source cannot measure travel.
            "France, no coordinates",
            Some(at("FR", None)),
            vec![RiskSignal::NewCountry],
        ),
    ];
    let policies: Vec<(&str, RiskPolicy)> = vec![
        ("default", on.clone()),
        (
            "no step-up",
            RiskPolicy {
                step_up_at: 0,
                ..on.clone()
            },
        ),
        (
            "no block",
            RiskPolicy {
                block_at: 0,
                ..on.clone()
            },
        ),
        (
            "custom weights",
            RiskPolicy {
                weights: RiskWeights {
                    new_device: 10,
                    new_country: 30,
                    impossible_travel: 70,
                    velocity: 25,
                },
                step_up_at: 35,
                block_at: 80,
                ..on.clone()
            },
        ),
        (
            "velocity off",
            RiskPolicy {
                velocity_max_failures: 0,
                ..on.clone()
            },
        ),
    ];

    let mut checks = 0;
    let mut failures = vec![];
    let mut outcomes = std::collections::BTreeMap::<String, u32>::new();
    for (pname, policy) in &policies {
        let tenant = with_policy(&base, policy.clone());
        for new_device in [false, true] {
            for (place, location, place_signals) in &places {
                for failing in [false, true] {
                    let mut want: Vec<RiskSignal> = vec![];
                    if new_device {
                        want.push(RiskSignal::NewDevice);
                    }
                    want.extend(place_signals.iter().cloned());
                    if failing && policy.velocity_max_failures > 0 {
                        want.push(RiskSignal::Velocity);
                    }
                    let score: u32 = want.iter().map(|s| weight(&policy.weights, s)).sum();
                    let action = expected_action(score, policy);
                    let got = risk::evaluate(
                        &app.state,
                        &tenant,
                        user,
                        &Inputs {
                            ip: Some(if failing { FAILING_IP } else { CLEAN_IP }),
                            location: location.as_ref(),
                            new_device,
                        },
                    )
                    .await
                    .unwrap();
                    checks += 1;
                    let mut got_signals = got.signals.clone();
                    let mut want_sorted = want.clone();
                    got_signals.sort();
                    want_sorted.sort();
                    *outcomes.entry(format!("{:?}", got.action)).or_insert(0) += 1;
                    if got_signals != want_sorted || got.score != score || got.action != action {
                        failures.push(format!(
                            "{pname} / device new={new_device} / {place} / failing ip={failing}: \
                             expected {want_sorted:?} = {score} → {action:?}, \
                             got {got_signals:?} = {} → {:?}",
                            got.score, got.action
                        ));
                    }
                }
            }
        }
    }

    // A disabled policy raises nothing whatever the inputs, but still says
    // where the sign-in came from.
    let off = with_policy(&base, RiskPolicy::default());
    for (_, location, _) in &places {
        let got = risk::evaluate(
            &app.state,
            &off,
            user,
            &Inputs {
                ip: Some(FAILING_IP),
                location: location.as_ref(),
                new_device: true,
            },
        )
        .await
        .unwrap();
        checks += 1;
        if !got.signals.is_empty() || got.score != 0 || got.action != RiskAction::Allow {
            failures.push(format!("disabled policy raised {got:?}"));
        }
        if got.country != location.as_ref().map(|l| l.country.clone()) {
            failures.push(format!("disabled policy lost the country: {got:?}"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {checks} checks failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert_eq!(checks, 5 * 2 * 5 * 2 + 5);
    // The matrix reaches every outcome, so it cannot pass by allowing all.
    for action in ["Allow", "StepUp", "Block"] {
        assert!(
            outcomes.get(action).copied().unwrap_or(0) > 0,
            "{outcomes:?}"
        );
    }
}

#[tokio::test]
async fn a_user_with_no_history_is_new_to_nothing() {
    let app = TestApp::spawn().await;
    let base = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let tenant = with_policy(
        &base,
        RiskPolicy {
            enabled: true,
            ..RiskPolicy::default()
        },
    );
    let user = new_user(&app).await;
    let got = risk::evaluate(
        &app.state,
        &tenant,
        user,
        &Inputs {
            ip: Some(CLEAN_IP),
            location: Some(&at("JP", Some((35.68, 139.69)))),
            new_device: false,
        },
    )
    .await
    .unwrap();
    assert!(got.signals.is_empty(), "{got:?}");
    assert_eq!(got.action, RiskAction::Allow);
}
