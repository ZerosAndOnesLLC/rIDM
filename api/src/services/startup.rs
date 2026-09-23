//! One-time work every node does as it starts: the first-run bootstrap from
//! the environment, then bringing every tenant's built-in console clients in
//! line with `UI_URL`.
//!
//! Nodes of a fresh deployment start together (a Deployment's replicas, a
//! rolling restart), and each of these steps checks and then writes: two
//! nodes both finding no administrator both create one, and the loser fails
//! on the unique username and exits. [`prepare`] holds a Postgres advisory
//! lock for the whole of it, so nodes take turns and the second finds the
//! work done. The lock is transaction-scoped: a node that dies or fails
//! mid-way releases it with its rollback.

use crate::config::BootstrapConfig;
use crate::error::AppResult;
use crate::services::{account_console, admin_console, bootstrap};
use crate::state::AppState;

/// Key of the advisory lock (`hashtext` of it), shared by every node.
const LOCK: &str = "ridm:startup";

/// Bootstrap and the built-in clients, under the start-up lock.
pub async fn prepare(state: &AppState, bootstrap: Option<BootstrapConfig>) -> AppResult<()> {
    serialized(state, async {
        if let Some(b) = bootstrap {
            let outcome = bootstrap::run(
                state,
                bootstrap::BootstrapRequest {
                    admin_email: b.admin_email,
                    admin_username: b.admin_username,
                    admin_password: zeroize::Zeroizing::new(b.admin_password.expose().to_string()),
                    must_change_password: true,
                },
            )
            .await?;
            if outcome == bootstrap::BootstrapOutcome::AlreadyBootstrapped {
                tracing::debug!("bootstrap: already done, skipping");
            }
            if b.sample_client && !bootstrap::ensure_sample_client(state).await? {
                tracing::debug!(
                    client_id = bootstrap::SAMPLE_CLIENT_ID,
                    "bootstrap: sample client exists"
                );
            }
        }
        // Every tenant carries the consoles' clients; their redirect URIs follow UI_URL.
        admin_console::ensure_all(state).await?;
        account_console::ensure_all(state).await?;
        Ok(())
    })
    .await
}

/// Run `work` while holding the start-up lock: one node at a time across
/// the deployment. `work` must not take the lock itself.
pub async fn serialized<T>(
    state: &AppState,
    work: impl Future<Output = AppResult<T>>,
) -> AppResult<T> {
    let mut lock = state.db.home().begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(LOCK)
        .execute(&mut *lock)
        .await?;
    let out = work.await?;
    lock.commit().await?;
    Ok(out)
}
