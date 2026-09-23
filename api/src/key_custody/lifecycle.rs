//! Attaching key custody to a process, and keeping a long-running node on
//! the newest generation.

use std::time::Duration;

use super::envelope::{AttachReport, CustodyError};
use super::wrappers;
use crate::state::AppState;

/// How often a server node looks for a generation another process created.
const REFRESH_EVERY: Duration = Duration::from_secs(60);

/// Build the configured wrappers and attach them and the database to the
/// state's encryptor (see [`super::EnvelopeEncryptor::attach`]). Every
/// process that reads or writes secrets calls this once, after building its
/// [`AppState`]: the server, `rotate-master-key`, `bootstrap`.
pub async fn attach(state: &AppState) -> Result<AttachReport, CustodyError> {
    let config = &state.config.key_custody;
    let built = wrappers::build(config).await?;
    let primary = config.wrapper.map(|b| b.as_str());
    let report = state
        .master_keys
        .attach(state.db.clone(), built, primary)
        .await?;
    if let Some(v) = report.created {
        tracing::info!(
            version = v,
            backend = primary.unwrap_or_default(),
            "first master-key generation created; run `ridm-api rotate-master-key` to move \
             existing secrets onto it"
        );
    }
    for (version, why) in &report.unreadable {
        tracing::warn!(version, error = %why, "master-key generation cannot be unwrapped by this node");
    }
    if !report.loaded.is_empty() {
        tracing::info!(generations = ?report.loaded, "master-key generations unwrapped");
    }
    Ok(report)
}

/// Record the generation [`attach`] created, if it created one, in the
/// global audit chain. Called once the process's audit writer runs, which it
/// does not yet when `attach` must happen.
pub fn record_created(state: &AppState, report: &AttachReport) {
    use ridm_core::events::{Actor, Event, EventKind, EventSink as _};
    if let (Some(version), Some(backend)) = (report.created, state.master_keys.primary_backend()) {
        state.events.publish(Event::new(
            None,
            Actor::System,
            EventKind::MasterKeyGenerationCreated {
                version,
                backend: backend.to_string(),
            },
        ));
    }
}

/// With a custody backend, look for new generations every minute so a node
/// starts encrypting under one created by `rotate-master-key --new-generation`
/// elsewhere without a restart.
pub fn spawn_refresh(state: AppState) -> Option<tokio::task::JoinHandle<()>> {
    state.master_keys.primary_backend()?;
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(REFRESH_EVERY);
        tick.tick().await;
        loop {
            tick.tick().await;
            if let Err(err) = state.master_keys.refresh().await {
                tracing::warn!(error = %err, "master-key generation refresh failed");
            }
        }
    }))
}
