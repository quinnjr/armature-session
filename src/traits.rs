//! Session store trait definition.

use crate::error::{SessionError, SessionResult};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Session data structure.
///
/// Contains all session information including metadata and user data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier
    pub id: String,
    /// Session data as key-value pairs
    pub data: HashMap<String, serde_json::Value>,
    /// Session creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last access timestamp
    pub last_accessed_at: DateTime<Utc>,
    /// Session expiration timestamp (sliding: moved by [`Session::extend`]).
    pub expires_at: DateTime<Utc>,
    /// Absolute expiration timestamp.
    ///
    /// Fixed when the session is created and never moved by
    /// [`Session::extend`], [`Session::touch`] or
    /// [`SessionStore::regenerate`]: a session cannot outlive it no matter
    /// how active it is. [`Session::expires_at`] is clamped to it.
    pub absolute_expires_at: DateTime<Utc>,
    /// User agent (optional)
    pub user_agent: Option<String>,
    /// IP address (optional)
    pub ip_address: Option<String>,
}

/// Convert a std `Duration` to a chrono one, saturating instead of failing.
fn chrono_duration(d: Duration) -> chrono::Duration {
    chrono::Duration::from_std(d).unwrap_or(chrono::Duration::MAX)
}

/// `now + d`, saturating at the maximum representable timestamp.
fn add_saturating(now: DateTime<Utc>, d: Duration) -> DateTime<Utc> {
    now.checked_add_signed(chrono_duration(d))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

impl Session {
    /// Create a new session with the given ID and TTL.
    ///
    /// The absolute lifetime defaults to `ttl` as well, i.e. the session can
    /// not be extended past its initial expiry. Use
    /// [`with_absolute_lifetime`](Self::with_absolute_lifetime) to allow a
    /// sliding expiry up to a longer hard cap (the stores do this with
    /// [`SessionConfig::max_ttl`](crate::SessionConfig::max_ttl)).
    pub fn new(id: impl Into<String>, ttl: Duration) -> Self {
        let now = Utc::now();
        let expires_at = add_saturating(now, ttl);
        Self {
            id: id.into(),
            data: HashMap::new(),
            created_at: now,
            last_accessed_at: now,
            expires_at,
            absolute_expires_at: expires_at,
            user_agent: None,
            ip_address: None,
        }
    }

    /// Set the absolute lifetime, measured from [`Session::created_at`].
    ///
    /// The current sliding expiry is clamped to the new absolute expiry.
    pub fn with_absolute_lifetime(mut self, lifetime: Duration) -> Self {
        self.absolute_expires_at = add_saturating(self.created_at, lifetime);
        if self.expires_at > self.absolute_expires_at {
            self.expires_at = self.absolute_expires_at;
        }
        self
    }

    /// Check if the session has expired (sliding or absolute expiry).
    pub fn is_expired(&self) -> bool {
        let now = Utc::now();
        now > self.expires_at || now > self.absolute_expires_at
    }

    /// Check if the session has been idle for longer than `idle_timeout`
    /// (time since [`Session::last_accessed_at`]).
    pub fn is_idle(&self, idle_timeout: Duration) -> bool {
        Utc::now() > add_saturating(self.last_accessed_at, idle_timeout)
    }

    /// Get a value from the session data.
    pub fn get<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Option<T> {
        self.data
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Set a value in the session data.
    pub fn set<T: Serialize>(&mut self, key: &str, value: T) -> SessionResult<()> {
        let json_value = serde_json::to_value(value)
            .map_err(|e| crate::error::SessionError::Serialization(e.to_string()))?;
        self.data.insert(key.to_string(), json_value);
        Ok(())
    }

    /// Remove a value from the session data.
    pub fn remove(&mut self, key: &str) -> Option<serde_json::Value> {
        self.data.remove(key)
    }

    /// Check if a key exists in the session data.
    pub fn contains(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }

    /// Get all keys in the session data.
    pub fn keys(&self) -> Vec<&String> {
        self.data.keys().collect()
    }

    /// Clear all session data.
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Update the last accessed timestamp.
    pub fn touch(&mut self) {
        self.last_accessed_at = Utc::now();
    }

    /// Extend the session expiration.
    ///
    /// The new expiry is clamped to [`Session::absolute_expires_at`], so an
    /// active session still ends at its absolute lifetime.
    pub fn extend(&mut self, ttl: Duration) {
        self.expires_at = add_saturating(Utc::now(), ttl).min(self.absolute_expires_at);
    }

    /// Set user agent.
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Set IP address.
    pub fn with_ip_address(mut self, ip_address: impl Into<String>) -> Self {
        self.ip_address = Some(ip_address.into());
        self
    }
}

/// Session store trait for different storage backends.
///
/// # ⚠️ Important: Prefer Stateless Architecture
///
/// **Armature strongly recommends stateless architecture using JWT tokens
/// instead of server-side sessions.** This module is provided for cases
/// where sessions are absolutely necessary (e.g., legacy system integration,
/// specific compliance requirements).
///
/// For most applications, use JWT-based authentication:
///
/// ```ignore
/// // Preferred: Stateless JWT
/// use armature_jwt::JwtManager;
///
/// let token = jwt_manager.create_token(user_claims)?;
/// // Client stores token, server validates on each request
/// ```
///
/// See the [Stateless Architecture Guide](../docs/stateless-architecture.md)
/// for why stateless is preferred.
///
/// # When to Use Sessions
///
/// Sessions may be appropriate when:
/// - Integrating with legacy systems that require sessions
/// - Compliance requirements mandate server-side session tracking
/// - You need immediate session invalidation (logout)
/// - Storing large amounts of user-specific data
///
/// # Examples
///
/// ```ignore
/// use armature_session::{SessionStore, SessionConfig, Session};
///
/// async fn example(store: &impl SessionStore) -> SessionResult<()> {
///     // Create a new session
///     let session = store.create(None).await?;
///
///     // Store data in session
///     let mut session = session;
///     session.set("user_id", 123)?;
///     store.save(&session).await?;
///
///     // Retrieve session
///     let session = store.get(&session.id).await?;
///
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Create a new session.
    ///
    /// # Arguments
    ///
    /// * `ttl` - Optional custom TTL (uses default if None)
    ///
    /// # Returns
    ///
    /// Returns a new session with a unique ID.
    async fn create(&self, ttl: Option<Duration>) -> SessionResult<Session>;

    /// Get a session by ID.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID to retrieve
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(session))` if found, `Ok(None)` if not found or expired.
    async fn get(&self, session_id: &str) -> SessionResult<Option<Session>>;

    /// Save/update a session.
    ///
    /// # Arguments
    ///
    /// * `session` - The session to save
    async fn save(&self, session: &Session) -> SessionResult<()>;

    /// Delete a session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID to delete
    async fn delete(&self, session_id: &str) -> SessionResult<()>;

    /// Check if a session exists and is valid.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID to check
    async fn exists(&self, session_id: &str) -> SessionResult<bool>;

    /// Extend a session's TTL.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID to extend
    /// * `ttl` - The new TTL duration
    async fn extend(&self, session_id: &str, ttl: Duration) -> SessionResult<()>;

    /// Touch a session (update last accessed time).
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID to touch
    async fn touch(&self, session_id: &str) -> SessionResult<()>;

    /// Clear all sessions (use with caution!).
    ///
    /// **Warning:** This will invalidate all user sessions.
    async fn clear_all(&self) -> SessionResult<()>;

    /// Get the number of active sessions.
    async fn count(&self) -> SessionResult<usize>;

    /// Cleanup expired sessions.
    ///
    /// This is called automatically by some backends, but can be
    /// called manually for maintenance.
    async fn cleanup_expired(&self) -> SessionResult<usize>;

    /// Regenerate a session's ID, invalidating the old one.
    ///
    /// Call this whenever the session's privilege level changes — most
    /// importantly right after login — to defeat session fixation: an
    /// attacker who planted or observed `old_id` is left holding a dead ID.
    ///
    /// The session's data, `created_at` and absolute expiry are carried over
    /// unchanged (regenerating never lengthens a session's absolute
    /// lifetime); `last_accessed_at` is refreshed. The new session is written
    /// before the old one is deleted, so a crash in between leaves at worst an
    /// orphan that expires on its own, never a logged-out user.
    ///
    /// Returns [`SessionError::NotFound`] if `old_id` does not name a live
    /// session.
    async fn regenerate(&self, old_id: &str) -> SessionResult<Session> {
        let mut session = self
            .get(old_id)
            .await?
            .ok_or_else(|| SessionError::NotFound("session to regenerate".to_string()))?;

        session.id = generate_session_id();
        session.touch();
        self.save(&session).await?;
        self.delete(old_id).await?;

        Ok(session)
    }

    // ========== Convenience Methods ==========

    /// Get a session value by key.
    async fn get_value<T: for<'de> Deserialize<'de>>(
        &self,
        session_id: &str,
        key: &str,
    ) -> SessionResult<Option<T>> {
        if let Some(session) = self.get(session_id).await? {
            Ok(session.get(key))
        } else {
            Ok(None)
        }
    }

    /// Set a session value by key.
    async fn set_value<T: Serialize + Send>(
        &self,
        session_id: &str,
        key: &str,
        value: T,
    ) -> SessionResult<()> {
        if let Some(mut session) = self.get(session_id).await? {
            session.set(key, value)?;
            self.save(&session).await?;
        }
        Ok(())
    }

    /// Remove a session value by key.
    async fn remove_value(&self, session_id: &str, key: &str) -> SessionResult<()> {
        if let Some(mut session) = self.get(session_id).await? {
            session.remove(key);
            self.save(&session).await?;
        }
        Ok(())
    }
}

/// Number of random bytes in a session ID (256 bits).
pub const SESSION_ID_BYTES: usize = 32;

/// Length of an encoded session ID: [`SESSION_ID_BYTES`] as lowercase hex.
pub const SESSION_ID_LEN: usize = SESSION_ID_BYTES * 2;

/// Generate a new unique session ID.
///
/// 256 bits read directly from the operating system's CSPRNG, encoded as 64
/// lowercase hex characters. The alphabet is safe in cookies, URLs, CouchDB
/// document IDs and memcached's ASCII protocol without further escaping.
///
/// # Panics
///
/// Panics if the OS random source is unavailable. Continuing with weaker
/// randomness would make sessions guessable, so failing loudly is the only
/// safe behavior.
pub fn generate_session_id() -> String {
    let mut bytes = [0u8; SESSION_ID_BYTES];
    getrandom::fill(&mut bytes).expect("OS random number generator unavailable");

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut id = String::with_capacity(SESSION_ID_LEN);
    for b in bytes {
        id.push(HEX[(b >> 4) as usize] as char);
        id.push(HEX[(b & 0x0f) as usize] as char);
    }
    id
}

/// Validate that `session_id` has the exact shape produced by
/// [`generate_session_id`]: [`SESSION_ID_LEN`] lowercase hex characters.
///
/// Every store calls this before a session ID reaches a backend command, so
/// a client-supplied ID can never carry CR/LF, spaces or other control
/// characters into memcached's line-based ASCII protocol, path segments into
/// a CouchDB URL, or glob characters into a Redis key pattern. The rejected
/// value is deliberately not echoed in the error (it may be a secret, or log
/// injection payload).
pub fn validate_session_id(session_id: &str) -> SessionResult<()> {
    let well_formed = session_id.len() == SESSION_ID_LEN
        && session_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));

    if well_formed {
        Ok(())
    } else {
        Err(SessionError::InvalidSessionId(format!(
            "expected {SESSION_ID_LEN} lowercase hex characters"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generated_ids_are_256_bit_hex() {
        let id = generate_session_id();
        assert_eq!(id.len(), 64);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        validate_session_id(&id).unwrap();
    }

    #[test]
    fn generated_ids_are_unique() {
        let ids: HashSet<String> = (0..1000).map(|_| generate_session_id()).collect();
        assert_eq!(ids.len(), 1000);
    }

    #[test]
    fn validate_rejects_malformed_ids() {
        let valid = generate_session_id();
        let bad = [
            String::new(),
            "a\r\nset x".to_string(),
            "a\r\nset x 0 0 1\r\n".to_string(),
            format!("{} ", &valid[..63]),
            format!("{}\n", &valid[..63]),
            format!("{}\0", &valid[..63]),
            valid.to_uppercase(),
            format!("{valid}0"),
            valid[..63].to_string(),
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
            "../_all_dbs".to_string(),
            "*".repeat(64),
        ];
        for id in bad {
            assert!(
                matches!(
                    validate_session_id(&id),
                    Err(SessionError::InvalidSessionId(_))
                ),
                "expected rejection for {id:?}"
            );
        }
    }

    #[test]
    fn invalid_id_error_does_not_echo_input() {
        let err = validate_session_id("evil\r\npayload").unwrap_err();
        assert!(!err.to_string().contains("evil"));
    }

    #[test]
    fn extend_is_clamped_to_absolute_lifetime() {
        let mut session = Session::new("x", Duration::from_secs(60))
            .with_absolute_lifetime(Duration::from_secs(120));
        session.extend(Duration::from_secs(3600));
        assert_eq!(session.expires_at, session.absolute_expires_at);
        assert!(!session.is_expired());
    }

    #[test]
    fn new_session_cannot_be_extended_past_initial_ttl_by_default() {
        let mut session = Session::new("x", Duration::from_secs(60));
        let initial = session.expires_at;
        session.extend(Duration::from_secs(3600));
        assert_eq!(session.expires_at, initial);
    }

    #[test]
    fn absolute_expiry_wins_over_sliding_expiry() {
        let mut session = Session::new("x", Duration::from_secs(3600))
            .with_absolute_lifetime(Duration::from_secs(7200));
        // Simulate a session created long ago whose sliding expiry was kept
        // fresh: the absolute cap has passed.
        session.absolute_expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert!(session.is_expired());
    }

    #[test]
    fn idle_detection() {
        let mut session = Session::new("x", Duration::from_secs(3600));
        assert!(!session.is_idle(Duration::from_secs(60)));
        session.last_accessed_at = Utc::now() - chrono::Duration::seconds(120);
        assert!(session.is_idle(Duration::from_secs(60)));
        session.touch();
        assert!(!session.is_idle(Duration::from_secs(60)));
    }

    /// Minimal in-memory store exercising the trait's default methods.
    #[derive(Default)]
    struct MemoryStore {
        config: crate::SessionConfig,
        sessions: std::sync::Mutex<HashMap<String, Session>>,
    }

    #[async_trait]
    impl SessionStore for MemoryStore {
        async fn create(&self, ttl: Option<Duration>) -> SessionResult<Session> {
            let session = self.config.new_session(ttl);
            self.save(&session).await?;
            Ok(session)
        }
        async fn get(&self, id: &str) -> SessionResult<Option<Session>> {
            validate_session_id(id)?;
            let found = self.sessions.lock().unwrap().get(id).cloned();
            match found {
                Some(s) if self.config.is_live(&s) => Ok(Some(s)),
                Some(_) => {
                    self.delete(id).await?;
                    Ok(None)
                }
                None => Ok(None),
            }
        }
        async fn save(&self, session: &Session) -> SessionResult<()> {
            validate_session_id(&session.id)?;
            self.sessions
                .lock()
                .unwrap()
                .insert(session.id.clone(), session.clone());
            Ok(())
        }
        async fn delete(&self, id: &str) -> SessionResult<()> {
            self.sessions.lock().unwrap().remove(id);
            Ok(())
        }
        async fn exists(&self, id: &str) -> SessionResult<bool> {
            Ok(self.get(id).await?.is_some())
        }
        async fn extend(&self, _id: &str, _ttl: Duration) -> SessionResult<()> {
            Ok(())
        }
        async fn touch(&self, _id: &str) -> SessionResult<()> {
            Ok(())
        }
        async fn clear_all(&self) -> SessionResult<()> {
            self.sessions.lock().unwrap().clear();
            Ok(())
        }
        async fn count(&self) -> SessionResult<usize> {
            Ok(self.sessions.lock().unwrap().len())
        }
        async fn cleanup_expired(&self) -> SessionResult<usize> {
            Ok(0)
        }
    }

    #[tokio::test]
    async fn regenerate_moves_data_and_invalidates_old_id() {
        let store = MemoryStore::default();
        let mut session = store.create(None).await.unwrap();
        session.set("user_id", 42).unwrap();
        store.save(&session).await.unwrap();

        let fresh = store.regenerate(&session.id).await.unwrap();

        assert_ne!(fresh.id, session.id);
        validate_session_id(&fresh.id).unwrap();
        assert_eq!(fresh.get::<i32>("user_id"), Some(42));
        // Regeneration never lengthens the absolute lifetime.
        assert_eq!(fresh.created_at, session.created_at);
        assert_eq!(fresh.absolute_expires_at, session.absolute_expires_at);

        assert!(store.get(&session.id).await.unwrap().is_none());
        assert!(!store.exists(&session.id).await.unwrap());
        assert!(store.get(&fresh.id).await.unwrap().is_some());
        assert_eq!(store.count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn regenerate_unknown_session_is_not_found() {
        let store = MemoryStore::default();
        let err = store.regenerate(&generate_session_id()).await.unwrap_err();
        assert!(matches!(err, SessionError::NotFound(_)));

        let err = store.regenerate("a\r\nset x").await.unwrap_err();
        assert!(matches!(err, SessionError::InvalidSessionId(_)));
    }

    #[tokio::test]
    async fn idle_session_is_dropped_on_load() {
        let store = MemoryStore {
            config: crate::SessionConfig::default().with_idle_timeout(Duration::from_secs(60)),
            ..Default::default()
        };
        let mut session = store.create(None).await.unwrap();
        session.last_accessed_at = Utc::now() - chrono::Duration::seconds(120);
        store.save(&session).await.unwrap();

        assert!(store.get(&session.id).await.unwrap().is_none());
        assert_eq!(
            store.count().await.unwrap(),
            0,
            "idle session must be deleted"
        );
    }

    #[tokio::test]
    async fn absolutely_expired_session_is_dropped_on_load() {
        let store = MemoryStore::default();
        let mut session = store.create(None).await.unwrap();
        session.absolute_expires_at = Utc::now() - chrono::Duration::seconds(1);
        store.save(&session).await.unwrap();

        assert!(store.get(&session.id).await.unwrap().is_none());
        assert_eq!(store.count().await.unwrap(), 0);
    }
}
