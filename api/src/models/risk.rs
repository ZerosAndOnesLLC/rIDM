//! What a risk evaluation looks at and what it concludes (Phase 12.3).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A country (and, when the source knows it, a point) a user has signed in
/// from before. One row per user and country; the coordinates are those of
/// the most recent sign-in from it.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct LoginLocation {
    #[serde(skip)]
    pub tenant_id: Uuid,
    #[serde(skip)]
    pub user_id: Uuid,
    /// ISO 3166-1 alpha-2, upper case.
    pub country: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub logins: i64,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

/// One reason a sign-in scored. The names are part of the audit and webhook
/// payload and must not change once shipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskSignal {
    NewDevice,
    NewCountry,
    ImpossibleTravel,
    Velocity,
}

impl RiskSignal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NewDevice => "new_device",
            Self::NewCountry => "new_country",
            Self::ImpossibleTravel => "impossible_travel",
            Self::Velocity => "velocity",
        }
    }
}

impl std::fmt::Display for RiskSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the policy decided to do about a score.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAction {
    /// Nothing unusual, or nothing the policy cares about.
    #[default]
    Allow,
    /// Demand a second factor for this sign-in, whatever the MFA policy says.
    StepUp,
    /// Refuse the sign-in.
    Block,
}

/// The outcome of one evaluation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub score: u32,
    pub signals: Vec<RiskSignal>,
    pub action: RiskAction,
    /// The country the request was located in, when a geo source could say.
    pub country: Option<String>,
}

impl RiskAssessment {
    pub fn signal_names(&self) -> Vec<String> {
        self.signals
            .iter()
            .map(|s| s.as_str().to_string())
            .collect()
    }

    pub fn is_blocked(&self) -> bool {
        self.action == RiskAction::Block
    }

    pub fn steps_up(&self) -> bool {
        self.action == RiskAction::StepUp
    }
}
