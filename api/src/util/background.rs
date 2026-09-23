//! Work a request starts but does not wait for: sending the message it just
//! queued, delivering the webhooks its events queued. Every task is counted,
//! so shutdown (and a test) can wait for what is in flight, and at most
//! `limit` run at a time, so a burst queues up here instead of opening a
//! connection per task.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Semaphore, watch};

#[derive(Clone)]
pub struct Background {
    permits: Arc<Semaphore>,
    in_flight: Arc<watch::Sender<usize>>,
}

/// Counts as in flight while alive: [`Background::spawn`]'s tasks hold one,
/// and so does a long-lived consumer (the audit writer, the webhook
/// dispatcher) while it works on what it took off its queue. Decrements the
/// count when dropped, however the work ends.
pub struct Running(Arc<watch::Sender<usize>>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n -= 1);
    }
}

impl Background {
    pub fn new(limit: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(limit.max(1))),
            in_flight: Arc::new(watch::Sender::new(0)),
        }
    }

    /// Mark work done outside [`Background::spawn`] as in flight until the
    /// guard is dropped (no slot is taken).
    pub fn busy(&self) -> Running {
        self.in_flight.send_modify(|n| *n += 1);
        Running(self.in_flight.clone())
    }

    /// Run `task` once a slot is free. It counts as in flight from now on,
    /// waiting included.
    pub fn spawn<F>(&self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let running = self.busy();
        let permits = self.permits.clone();
        tokio::spawn(async move {
            let _running = running;
            // The semaphore is never closed.
            let Ok(_permit) = permits.acquire_owned().await else {
                return;
            };
            task.await;
        });
    }

    /// Tasks spawned and not yet finished.
    pub fn in_flight(&self) -> usize {
        *self.in_flight.borrow()
    }

    /// Wait until nothing is in flight.
    pub async fn idle(&self) {
        let mut rx = self.in_flight.subscribe();
        // The sender lives as long as `self`, so this cannot fail.
        let _ = rx.wait_for(|n| *n == 0).await;
    }

    /// [`Background::idle`], giving up after `limit`. `false`: tasks were
    /// still running.
    pub async fn idle_within(&self, limit: Duration) -> bool {
        tokio::time::timeout(limit, self.idle()).await.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn runs_at_most_limit_at_once_and_reports_idle() {
        let bg = Background::new(2);
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        for _ in 0..6 {
            let running = running.clone();
            let peak = peak.clone();
            bg.spawn(async move {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                running.fetch_sub(1, Ordering::SeqCst);
            });
        }
        assert_eq!(bg.in_flight(), 6);
        assert!(bg.idle_within(Duration::from_secs(5)).await);
        assert_eq!(bg.in_flight(), 0);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_panicking_task_still_counts_as_finished() {
        let bg = Background::new(1);
        bg.spawn(async { panic!("boom") });
        assert!(bg.idle_within(Duration::from_secs(5)).await);
    }
}
