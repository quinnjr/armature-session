//! Session configuration.

use crate::error::{SessionError, SessionResult};
use crate::traits::{SESSION_ID_LEN, Session, generate_session_id};
use std::fmt;
use std::time::Duration;

/// Longest key memcached accepts (bytes).
pub const MEMCACHED_MAX_KEY_LEN: usize = 250;

/// Session backend type.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionBackend {
    /// Redis backend
    Redis,
    /// Memcached backend
    Memcached,
    /// CouchDB backend
    CouchDb,
}

/// Session configuration.
///
/// `Debug` is implemented by hand: [`password`](Self::password) and any
/// credentials embedded in [`url`](Self::url) (`redis://user:pass@host`) are
/// printed as `<redacted>`. The type is not `Serialize`.
#[derive(Clone)]
pub struct SessionConfig {
    /// Backend type
    pub backend: SessionBackend,
    /// Connection URL (secret: userinfo redacted from `Debug`)
    pub url: String,
    /// Session namespace/prefix
    pub namespace: String,
    /// Default (initial, sliding) session TTL
    pub default_ttl: Duration,
    /// Absolute session lifetime, measured from creation.
    ///
    /// No amount of activity, [`SessionStore::extend`](crate::SessionStore::extend)
    /// or [`SessionStore::regenerate`](crate::SessionStore::regenerate) keeps a
    /// session alive past this.
    pub max_ttl: Duration,
    /// Idle timeout: a session not accessed (see
    /// [`SessionStore::touch`](crate::SessionStore::touch)) for longer than
    /// this is treated as missing and deleted on load.
    pub idle_timeout: Duration,
    /// CouchDB database name (only for CouchDB backend)
    pub database: Option<String>,
    /// CouchDB username (only for CouchDB backend)
    pub username: Option<String>,
    /// CouchDB password (only for CouchDB backend; secret: redacted from `Debug`)
    pub password: Option<String>,
}

impl fmt::Debug for SessionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionConfig")
            .field("backend", &self.backend)
            .field("url", &redact_url(&self.url))
            .field("namespace", &self.namespace)
            .field("default_ttl", &self.default_ttl)
            .field("max_ttl", &self.max_ttl)
            .field("idle_timeout", &self.idle_timeout)
            .field("database", &self.database)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Replace the userinfo (`user:password@`) of a URL with `<redacted>`.
fn redact_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let rest = &url[scheme_end + 3..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => format!("{}<redacted>@{}", &url[..scheme_end + 3], &rest[at + 1..]),
        None => url.to_string(),
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            backend: SessionBackend::Redis,
            url: "redis://localhost:6379".to_string(),
            namespace: "session".to_string(),
            default_ttl: Duration::from_secs(3600),  // 1 hour
            max_ttl: Duration::from_secs(86400 * 7), // 7 days
            idle_timeout: Duration::from_secs(3600), // 1 hour
            database: None,
            username: None,
            password: None,
        }
    }
}

impl SessionConfig {
    /// Create a Redis session configuration.
    ///
    /// # Arguments
    ///
    /// * `url` - Redis connection URL (e.g., "redis://localhost:6379")
    ///
    /// # Examples
    ///
    /// ```
    /// use armature_session::SessionConfig;
    ///
    /// let config = SessionConfig::redis("redis://localhost:6379").unwrap();
    /// ```
    pub fn redis(url: &str) -> SessionResult<Self> {
        if !url.starts_with("redis://") && !url.starts_with("rediss://") {
            return Err(SessionError::InvalidUrl(
                "Redis URL must start with redis:// or rediss://".to_string(),
            ));
        }

        Ok(Self {
            backend: SessionBackend::Redis,
            url: url.to_string(),
            ..Default::default()
        })
    }

    /// Create a Memcached session configuration.
    ///
    /// # Arguments
    ///
    /// * `url` - Memcached connection URL (e.g., "memcache://localhost:11211")
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use armature_session::SessionConfig;
    ///
    /// let config = SessionConfig::memcached("memcache://localhost:11211").unwrap();
    /// ```
    pub fn memcached(url: &str) -> SessionResult<Self> {
        if !url.starts_with("memcache://") {
            return Err(SessionError::InvalidUrl(
                "Memcached URL must start with memcache://".to_string(),
            ));
        }

        Ok(Self {
            backend: SessionBackend::Memcached,
            url: url.to_string(),
            ..Default::default()
        })
    }

    /// Create a CouchDB session configuration.
    ///
    /// # Arguments
    ///
    /// * `url` - CouchDB connection URL (e.g., "http://localhost:5984")
    /// * `database` - Database name for sessions
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use armature_session::SessionConfig;
    ///
    /// let config = SessionConfig::couchdb("http://localhost:5984", "sessions").unwrap();
    /// ```
    pub fn couchdb(url: &str, database: &str) -> SessionResult<Self> {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(SessionError::InvalidUrl(
                "CouchDB URL must start with http:// or https://".to_string(),
            ));
        }

        Ok(Self {
            backend: SessionBackend::CouchDb,
            url: url.to_string(),
            database: Some(database.to_string()),
            ..Default::default()
        })
    }

    /// Set the session namespace/prefix.
    ///
    /// # Arguments
    ///
    /// * `namespace` - Namespace to use for session keys
    pub fn with_namespace(mut self, namespace: &str) -> Self {
        self.namespace = namespace.to_string();
        self
    }

    /// Set the default session TTL.
    ///
    /// # Arguments
    ///
    /// * `ttl` - Default time-to-live for sessions
    pub fn with_default_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = ttl;
        self
    }

    /// Set the maximum session TTL.
    ///
    /// # Arguments
    ///
    /// * `ttl` - Maximum time-to-live for sessions
    pub fn with_max_ttl(mut self, ttl: Duration) -> Self {
        self.max_ttl = ttl;
        self
    }

    /// Set the idle timeout.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum time between accesses before a session is dropped
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set CouchDB authentication credentials.
    ///
    /// # Arguments
    ///
    /// * `username` - CouchDB username
    /// * `password` - CouchDB password
    pub fn with_auth(mut self, username: &str, password: &str) -> Self {
        self.username = Some(username.to_string());
        self.password = Some(password.to_string());
        self
    }

    /// Build the session key with namespace.
    pub fn session_key(&self, session_id: &str) -> String {
        format!("{}:{}", self.namespace, session_id)
    }

    /// Validate `session_id` (see
    /// [`validate_session_id`](crate::validate_session_id)) and build its
    /// namespaced key. Every store's command path funnels through this, so a
    /// client-supplied ID such as `"a\r\nset x …"` can never inject extra
    /// commands into memcached's line-based ASCII protocol (or glob/path
    /// characters into Redis/CouchDB keys).
    pub fn checked_session_key(&self, session_id: &str) -> SessionResult<String> {
        crate::traits::validate_session_id(session_id)?;
        Ok(self.session_key(session_id))
    }

    /// Validate the configuration. Every store calls this from its
    /// constructor.
    ///
    /// The namespace becomes part of every backend key, so it must be
    /// non-empty, free of whitespace and control characters (memcached's
    /// ASCII protocol is line- and space-delimited), and short enough that
    /// `namespace:<session id>` fits memcached's 250-byte key limit. Lifetimes
    /// must be non-zero and `default_ttl` may not exceed `max_ttl`.
    pub fn validate(&self) -> SessionResult<()> {
        if self.namespace.is_empty()
            || self
                .namespace
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(SessionError::Config(
                "session namespace must be non-empty and contain no whitespace or control characters"
                    .to_string(),
            ));
        }
        if self.namespace.len() + 1 + SESSION_ID_LEN > MEMCACHED_MAX_KEY_LEN {
            return Err(SessionError::Config(format!(
                "session namespace too long: keys must fit in {MEMCACHED_MAX_KEY_LEN} bytes"
            )));
        }
        if self.default_ttl.is_zero() || self.max_ttl.is_zero() || self.idle_timeout.is_zero() {
            return Err(SessionError::Config(
                "default_ttl, max_ttl and idle_timeout must be non-zero".to_string(),
            ));
        }
        if self.default_ttl > self.max_ttl {
            return Err(SessionError::Config(
                "default_ttl must not exceed max_ttl (the absolute lifetime)".to_string(),
            ));
        }
        Ok(())
    }

    /// Build a fresh session with a new random ID, sliding expiry
    /// `min(ttl, max_ttl)` and absolute lifetime `max_ttl`.
    pub fn new_session(&self, ttl: Option<Duration>) -> Session {
        let ttl = ttl.unwrap_or(self.default_ttl).min(self.max_ttl);
        Session::new(generate_session_id(), ttl).with_absolute_lifetime(self.max_ttl)
    }

    /// Whether a loaded session is still usable: neither its sliding nor its
    /// absolute expiry has passed and it has not been idle longer than
    /// [`idle_timeout`](Self::idle_timeout).
    pub fn is_live(&self, session: &Session) -> bool {
        !session.is_expired() && !session.is_idle(self.idle_timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_password_and_url_credentials() {
        let config = SessionConfig::couchdb("https://admin:hunter2@db.example.com:5984/x", "s")
            .unwrap()
            .with_auth("admin", "s3cr3t-pw");
        let debug = format!("{config:?}");
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(!debug.contains("s3cr3t-pw"), "{debug}");
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("db.example.com:5984"));
        // Username is not a secret.
        assert!(debug.contains("admin"));
    }

    #[test]
    fn debug_redacts_redis_url_password() {
        let config = SessionConfig::redis("rediss://:topsecret@cache.internal:6380/0").unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains("topsecret"), "{debug}");
        assert!(debug.contains("rediss://<redacted>@cache.internal:6380/0"));
    }

    #[test]
    fn redact_url_leaves_credential_free_urls_alone() {
        assert_eq!(
            redact_url("redis://localhost:6379"),
            "redis://localhost:6379"
        );
        assert_eq!(
            redact_url("http://host/path@notuserinfo"),
            "http://host/path@notuserinfo"
        );
        assert_eq!(redact_url("not a url"), "not a url");
    }

    #[test]
    fn validate_rejects_bad_namespaces_and_lifetimes() {
        let base = SessionConfig::redis("redis://localhost:6379").unwrap();
        base.validate().unwrap();

        for ns in ["", "has space", "line\r\nbreak", "tab\t"] {
            assert!(
                base.clone().with_namespace(ns).validate().is_err(),
                "{ns:?}"
            );
        }
        let long = "n".repeat(MEMCACHED_MAX_KEY_LEN - SESSION_ID_LEN);
        assert!(base.clone().with_namespace(&long).validate().is_err());
        let fits = "n".repeat(MEMCACHED_MAX_KEY_LEN - SESSION_ID_LEN - 1);
        base.clone().with_namespace(&fits).validate().unwrap();

        assert!(
            base.clone()
                .with_idle_timeout(Duration::ZERO)
                .validate()
                .is_err()
        );
        assert!(
            base.clone()
                .with_default_ttl(Duration::from_secs(10))
                .with_max_ttl(Duration::from_secs(5))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn new_session_uses_absolute_lifetime_and_clamps_ttl() {
        let config = SessionConfig::redis("redis://localhost:6379")
            .unwrap()
            .with_default_ttl(Duration::from_secs(60))
            .with_max_ttl(Duration::from_secs(600));
        let s = config.new_session(Some(Duration::from_secs(10_000)));
        assert_eq!(s.expires_at, s.absolute_expires_at);
        assert_eq!((s.absolute_expires_at - s.created_at).num_seconds(), 600);
        crate::traits::validate_session_id(&s.id).unwrap();

        let s = config.new_session(None);
        assert_eq!((s.expires_at - s.created_at).num_seconds(), 60);
        assert!(config.is_live(&s));
    }

    #[test]
    fn is_live_enforces_idle_timeout() {
        let config = SessionConfig::redis("redis://localhost:6379")
            .unwrap()
            .with_idle_timeout(Duration::from_secs(60));
        let mut s = config.new_session(None);
        s.last_accessed_at = chrono::Utc::now() - chrono::Duration::seconds(61);
        assert!(!config.is_live(&s));
    }
}
