//! Sessions and the half-finished sign-ins waiting for a callback.
//!
//! Both live in memory, which is the one thing a real deployment would change:
//! put them in Redis or a database and every replica shares them, and a restart
//! does not sign everybody out.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};

/// A sign-in that has been sent to rIDM and is waiting for the callback.
#[derive(Debug, Clone)]
pub struct Pending {
    pub nonce: String,
    pub code_verifier: String,
    pub started_at: DateTime<Utc>,
    /// Where to land the user once they are back.
    pub next: String,
}

/// A signed-in user.
#[derive(Debug, Clone)]
pub struct Session {
    pub subject: String,
    pub name: Option<String>,
    pub email: Option<String>,
    /// The rIDM session (`sid`), which back-channel logout names.
    pub sid: Option<String>,
    pub id_token: String,
    pub access_token: String,
    pub access_token_expires_at: DateTime<Utc>,
    pub refresh_token: Option<String>,
    pub permissions: Vec<String>,
}

impl Session {
    /// Treat a token about to expire as expired: a token that passes here and
    /// fails at the API a moment later helps nobody.
    pub fn access_token_is_usable(&self) -> bool {
        self.access_token_expires_at > Utc::now() + chrono::Duration::seconds(10)
    }
}

/// The store. `Arc` because axum hands each request a clone of the state.
#[derive(Clone, Default)]
pub struct Store {
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    pending: Arc<Mutex<HashMap<String, Pending>>>,
}

/// How long a user has to finish signing in before the pending request is
/// swept. Also the ceiling on how long a `state` value is worth replaying.
const PENDING_TTL_MINUTES: i64 = 10;

impl Store {
    /// Remember a sign-in in flight, keyed by the `state` that will come back.
    pub fn start(&self, state: String, pending: Pending) {
        let mut all = self.pending.lock().expect("pending");
        let cutoff = Utc::now() - chrono::Duration::minutes(PENDING_TTL_MINUTES);
        all.retain(|_, p| p.started_at > cutoff);
        all.insert(state, pending);
    }

    /// Take the sign-in that `state` names. One use only: a callback replayed
    /// with the same `state` finds nothing, which is the point of storing it.
    pub fn take(&self, state: &str) -> Option<Pending> {
        let pending = self.pending.lock().expect("pending").remove(state)?;
        (pending.started_at > Utc::now() - chrono::Duration::minutes(PENDING_TTL_MINUTES))
            .then_some(pending)
    }

    pub fn create(&self, session: Session) -> String {
        let id = random_token();
        self.sessions
            .lock()
            .expect("sessions")
            .insert(id.clone(), session);
        id
    }

    pub fn get(&self, id: &str) -> Option<Session> {
        self.sessions.lock().expect("sessions").get(id).cloned()
    }

    pub fn put(&self, id: &str, session: Session) {
        self.sessions
            .lock()
            .expect("sessions")
            .insert(id.to_string(), session);
    }

    pub fn remove(&self, id: &str) -> Option<Session> {
        self.sessions.lock().expect("sessions").remove(id)
    }

    /// End every session rIDM's `sid` names — what a back-channel logout asks
    /// for. Returns how many were ended.
    pub fn remove_by_sid(&self, sid: &str) -> usize {
        let mut sessions = self.sessions.lock().expect("sessions");
        let before = sessions.len();
        sessions.retain(|_, s| s.sid.as_deref() != Some(sid));
        before - sessions.len()
    }

    /// End every session of a subject, for a logout token that names `sub`
    /// without a `sid`.
    pub fn remove_by_subject(&self, subject: &str) -> usize {
        let mut sessions = self.sessions.lock().expect("sessions");
        let before = sessions.len();
        sessions.retain(|_, s| s.subject != subject);
        before - sessions.len()
    }
}

/// 32 random bytes, base64url. Used for the session id, `state`, `nonce` and
/// the PKCE verifier — all of which are unguessable-or-nothing.
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(age_minutes: i64) -> Pending {
        Pending {
            nonce: "n".into(),
            code_verifier: "v".into(),
            started_at: Utc::now() - chrono::Duration::minutes(age_minutes),
            next: "/".into(),
        }
    }

    #[test]
    fn a_state_can_be_spent_once() {
        let store = Store::default();
        store.start("abc".into(), pending(0));
        assert!(store.take("abc").is_some());
        assert!(
            store.take("abc").is_none(),
            "a replayed callback finds nothing"
        );
    }

    #[test]
    fn a_sign_in_left_open_too_long_is_not_finished() {
        let store = Store::default();
        store.start("abc".into(), pending(PENDING_TTL_MINUTES + 1));
        assert!(store.take("abc").is_none());
    }

    #[test]
    fn a_logout_ends_the_sessions_it_names_and_no_others() {
        let store = Store::default();
        let session = |subject: &str, sid: &str| Session {
            subject: subject.into(),
            name: None,
            email: None,
            sid: Some(sid.into()),
            id_token: String::new(),
            access_token: String::new(),
            access_token_expires_at: Utc::now(),
            refresh_token: None,
            permissions: vec![],
        };
        let kept = store.create(session("alice", "s2"));
        store.create(session("alice", "s1"));
        store.create(session("bob", "s1"));

        assert_eq!(store.remove_by_sid("s1"), 2);
        assert!(store.get(&kept).is_some());
        assert_eq!(store.remove_by_subject("alice"), 1);
        assert!(store.get(&kept).is_none());
    }

    #[test]
    fn a_token_about_to_expire_counts_as_expired() {
        let mut session = Session {
            subject: "alice".into(),
            name: None,
            email: None,
            sid: None,
            id_token: String::new(),
            access_token: String::new(),
            access_token_expires_at: Utc::now() + chrono::Duration::seconds(5),
            refresh_token: None,
            permissions: vec![],
        };
        assert!(!session.access_token_is_usable());
        session.access_token_expires_at = Utc::now() + chrono::Duration::minutes(5);
        assert!(session.access_token_is_usable());
    }
}
