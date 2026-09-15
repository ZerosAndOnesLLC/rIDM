//! In-process scheduler: runs each job on its interval with a small random
//! jitter so several nodes do not contend for the leader lock at once.

use std::time::Duration;

use crate::jobs::key_rotation;
use crate::state::AppState;

/// Spawn the background jobs. The returned handles are aborted on shutdown.
pub fn spawn_all(state: AppState) -> Vec<tokio::task::JoinHandle<()>> {
    vec![
        spawn_periodic(
            state.clone(),
            "key_rotation",
            Duration::from_secs(3600),
            |s| async move { key_rotation::run_once(&s).await.map(|_| ()) },
        ),
        spawn_periodic(
            state.clone(),
            "audit_retention",
            Duration::from_secs(24 * 3600),
            |s| async move { crate::jobs::audit_retention::run_once(&s).await.map(|_| ()) },
        ),
        spawn_periodic(
            state.clone(),
            "webhook_delivery",
            Duration::from_secs(30),
            |s| async move {
                crate::jobs::webhook_delivery::run_once(&s)
                    .await
                    .map(|_| ())
            },
        ),
        spawn_periodic(
            state,
            "message_delivery",
            Duration::from_secs(30),
            |s| async move {
                crate::jobs::message_delivery::run_once(&s)
                    .await
                    .map(|_| ())
            },
        ),
    ]
}

fn spawn_periodic<F, Fut>(
    state: AppState,
    name: &'static str,
    every: Duration,
    job: F,
) -> tokio::task::JoinHandle<()>
where
    F: Fn(AppState) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = crate::error::AppResult<()>> + Send,
{
    tokio::spawn(async move {
        // Initial delay lets the node finish starting and spreads nodes out.
        let jitter = Duration::from_millis(rand::random_range(0..5_000));
        tokio::time::sleep(Duration::from_secs(30) + jitter).await;
        loop {
            match job(state.clone()).await {
                Ok(()) => tracing::debug!(job = name, "job pass complete"),
                Err(err) => tracing::error!(job = name, error = %err, "job failed"),
            }
            let jitter = Duration::from_millis(rand::random_range(0..30_000));
            tokio::time::sleep(every + jitter).await;
        }
    })
}
