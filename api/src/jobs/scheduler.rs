//! In-process scheduler: runs each job on its interval with a small random
//! jitter so several nodes do not contend for the leader lock at once. Every
//! pass is counted and timed (`ridm_job_runs_total`, `ridm_job_duration_seconds`)
//! and its outcome recorded as the job's last run (`jobs::status`).

use std::time::{Duration, Instant};

use crate::jobs::key_rotation;
use crate::jobs::status::{self, LastRun};
use crate::state::AppState;

/// Spawn the background jobs. The returned handles are aborted on shutdown.
pub fn spawn_all(state: AppState) -> Vec<tokio::task::JoinHandle<()>> {
    let sink = crate::jobs::audit_sink::spawn(state.clone());
    let mut jobs = vec![
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
            "audit_verify",
            Duration::from_secs(24 * 3600),
            |s| async move { crate::jobs::audit_verify::run_once(&s).await.map(|_| ()) },
        ),
        spawn_periodic(
            state.clone(),
            "user_purge",
            Duration::from_secs(24 * 3600),
            |s| async move { crate::jobs::user_purge::run_once(&s).await.map(|_| ()) },
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
            state.clone(),
            "message_delivery",
            Duration::from_secs(30),
            |s| async move {
                crate::jobs::message_delivery::run_once(&s)
                    .await
                    .map(|_| ())
            },
        ),
        spawn_periodic(
            state,
            "cleanup",
            Duration::from_secs(3600),
            |s| async move { crate::jobs::cleanup::run_once(&s).await.map(|_| ()) },
        ),
    ];
    jobs.extend(sink);
    jobs
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
            let started = Instant::now();
            let outcome = job(state.clone()).await;
            let elapsed = started.elapsed();
            let (ok, error) = match &outcome {
                Ok(()) => {
                    tracing::debug!(job = name, "job pass complete");
                    (true, None)
                }
                Err(err) => {
                    tracing::error!(job = name, error = %err, "job failed");
                    (false, Some(err.to_string()))
                }
            };
            metrics::counter!("ridm_job_runs_total", "job" => name, "outcome" => if ok { "ok" } else { "error" })
                .increment(1);
            metrics::histogram!("ridm_job_duration_seconds", "job" => name)
                .record(elapsed.as_secs_f64());
            let run = LastRun {
                job: name.to_string(),
                at: chrono::Utc::now(),
                ok,
                duration_ms: elapsed.as_millis() as u64,
                error,
            };
            if let Err(err) = status::record(&state, &run).await {
                tracing::warn!(job = name, error = %err, "could not record the job's last run");
            }
            let jitter = Duration::from_millis(rand::random_range(0..30_000));
            tokio::time::sleep(every + jitter).await;
        }
    })
}
