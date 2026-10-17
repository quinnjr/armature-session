//! Memcached session storage implementation.
//!
//! This module requires the `memcached` feature flag.

use crate::config::SessionConfig;
use crate::error::{SessionError, SessionResult};
use crate::traits::{Session, SessionStore};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Memcached-backed session store.
///
/// # ⚠️ Important: Prefer Stateless Architecture
///
/// **Armature strongly recommends stateless architecture using JWT tokens.**
/// Use sessions only when absolutely necessary.
///
/// # Feature Flag
///
/// This requires the `memcached` feature:
///
/// ```toml
/// [dependencies]
/// armature-session = { version = "0.1", features = ["memcached"] }
/// ```
///
/// # Examples
///
/// ```ignore
/// use armature_session::{MemcachedSessionStore, SessionConfig, SessionStore};
/// use std::time::Duration;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = SessionConfig::memcached("memcache://localhost:11211")?
///         .with_namespace("myapp:session")
///         .with_default_ttl(Duration::from_secs(3600));
///
///     let store = MemcachedSessionStore::new(config).await?;
///
///     // Create a session
///     let mut session = store.create(None).await?;
///     session.set("user_id", 123)?;
///     store.save(&session).await?;
///
///     Ok(())
/// }
/// ```
pub struct MemcachedSessionStore {
    client: Arc<Mutex<memcache::Client>>,
    config: SessionConfig,
}

impl MemcachedSessionStore {
    /// Create a new Memcached session store.
    ///
    /// # Arguments
    ///
    /// * `config` - Session configuration
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use armature_session::{MemcachedSessionStore, SessionConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = SessionConfig::memcached("memcache://localhost:11211")?;
    /// let store = MemcachedSessionStore::new(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(config: SessionConfig) -> SessionResult<Self> {
        config.validate()?;
        let client = memcache::connect(config.url.as_str())
            .map_err(|e| SessionError::Connection(e.to_string()))?;

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            config,
        })
    }

    /// Get the validated session key for a given session ID
    /// (see [`SessionConfig::checked_session_key`]).
    fn session_key(&self, session_id: &str) -> SessionResult<String> {
        self.config.checked_session_key(session_id)
    }
}

#[async_trait]
impl SessionStore for MemcachedSessionStore {
    async fn create(&self, ttl: Option<Duration>) -> SessionResult<Session> {
        // Random 256-bit ID, sliding TTL clamped to `max_ttl`, absolute
        // lifetime `max_ttl`.
        let session = self.config.new_session(ttl);

        // Save the session
        self.save(&session).await?;

        Ok(session)
    }

    async fn get(&self, session_id: &str) -> SessionResult<Option<Session>> {
        let key = self.session_key(session_id)?;
        let client = self.client.lock().await;

        let data: Option<String> = client
            .get(&key)
            .map_err(|e| SessionError::Other(e.to_string()))?;

        match data {
            Some(json) => {
                let session: Session = serde_json::from_str(&json)
                    .map_err(|e| SessionError::Deserialization(e.to_string()))?;

                // Expired (sliding/absolute), idle too long, or not the
                // document we asked for: treat as missing and drop it.
                if !self.config.is_live(&session) || session.id != session_id {
                    drop(client); // Release lock before calling delete
                    self.delete(session_id).await?;
                    return Ok(None);
                }

                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn save(&self, session: &Session) -> SessionResult<()> {
        let key = self.session_key(&session.id)?;
        let client = self.client.lock().await;

        let json = serde_json::to_string(session)
            .map_err(|e| SessionError::Serialization(e.to_string()))?;

        // Calculate remaining TTL. Memcached treats an expiry above 30 days
        // as an absolute Unix timestamp, so cap the relative value there.
        const MEMCACHED_MAX_RELATIVE_TTL: i64 = 60 * 60 * 24 * 30;
        let now = chrono::Utc::now();
        let remaining = (session.expires_at.min(session.absolute_expires_at) - now)
            .num_seconds()
            .clamp(0, MEMCACHED_MAX_RELATIVE_TTL) as u32;

        // Like the Redis store: an already-expired session cannot be saved,
        // and saying so beats a silent no-op that `create()` would turn into
        // a session that was never persisted.
        if remaining == 0 {
            return Err(SessionError::Expired("session already expired".to_string()));
        }

        client
            .set(&key, json.as_str(), remaining)
            .map_err(|e| SessionError::Other(e.to_string()))?;

        Ok(())
    }

    async fn delete(&self, session_id: &str) -> SessionResult<()> {
        let key = self.session_key(session_id)?;
        let client = self.client.lock().await;

        // Memcached delete returns false if key doesn't exist, which is fine
        let _ = client.delete(&key);

        Ok(())
    }

    async fn exists(&self, session_id: &str) -> SessionResult<bool> {
        Ok(self.get(session_id).await?.is_some())
    }

    async fn extend(&self, session_id: &str, ttl: Duration) -> SessionResult<()> {
        if let Some(mut session) = self.get(session_id).await? {
            // `Session::extend` clamps to the absolute expiry (`max_ttl`
            // from creation); extending is activity, so it also resets the
            // idle clock.
            session.extend(ttl.min(self.config.max_ttl));
            session.touch();
            self.save(&session).await?;
        }

        Ok(())
    }

    async fn touch(&self, session_id: &str) -> SessionResult<()> {
        if let Some(mut session) = self.get(session_id).await? {
            session.touch();
            self.save(&session).await?;
        }

        Ok(())
    }

    async fn clear_all(&self) -> SessionResult<()> {
        let client = self.client.lock().await;

        client
            .flush()
            .map_err(|e| SessionError::Other(e.to_string()))?;

        Ok(())
    }

    async fn count(&self) -> SessionResult<usize> {
        // Memcached doesn't support counting keys with a prefix
        // This is a limitation of the protocol
        Err(SessionError::Other(
            "Memcached does not support counting sessions by prefix".to_string(),
        ))
    }

    async fn cleanup_expired(&self) -> SessionResult<usize> {
        // Memcached automatically expires keys
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_key_generation() {
        let config = SessionConfig::memcached("memcache://localhost:11211").unwrap();
        assert!(config.session_key("test-id").starts_with("session:"));
    }

    #[test]
    fn protocol_injection_ids_are_rejected_before_reaching_memcached() {
        let config = SessionConfig::memcached("memcache://localhost:11211").unwrap();
        for bad in [
            "a\r\nset x",
            "a\r\nset x 0 0 1\r\nX\r\n",
            "a b",
            "a\0b",
            "\u{7f}",
            &"a".repeat(300),
        ] {
            assert!(
                matches!(
                    config.checked_session_key(bad),
                    Err(SessionError::InvalidSessionId(_))
                ),
                "expected rejection for {bad:?}"
            );
        }
        let good = crate::generate_session_id();
        let key = config.checked_session_key(&good).unwrap();
        assert!(key.len() <= crate::config::MEMCACHED_MAX_KEY_LEN);
        assert!(!key.bytes().any(|b| b.is_ascii_control() || b == b' '));
    }
}
