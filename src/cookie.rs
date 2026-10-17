//! Hardened session cookie helper.
//!
//! [`SessionCookie`] builds the `Set-Cookie` header value that carries a
//! session ID to the browser, with secure defaults:
//!
//! - `Secure` (cookie is never sent over plain HTTP),
//! - `HttpOnly` (not readable from JavaScript),
//! - `SameSite=Lax` (not sent on cross-site subresource requests / POSTs),
//! - `Path=/`,
//! - `Max-Age` taken from the session configuration.
//!
//! The optional `__Host-` prefix ([`SessionCookie::host_prefix`]) additionally
//! makes the browser refuse the cookie unless it is `Secure`, has `Path=/` and
//! carries no `Domain` attribute — which pins it to the exact host that set
//! it, so a sibling subdomain cannot overwrite (fixate) it.
//!
//! ```
//! use armature_session::{SessionConfig, SessionCookie, generate_session_id};
//!
//! let config = SessionConfig::default();
//! let cookie = SessionCookie::new("sid").host_prefix(true).max_age_from(&config);
//!
//! let value = cookie.to_header_value(&generate_session_id()).unwrap();
//! assert!(value.starts_with("__Host-sid="));
//! assert!(value.contains("; Secure"));
//! assert!(value.contains("; HttpOnly"));
//! assert!(value.contains("; SameSite=Lax"));
//!
//! // On logout, overwrite the cookie with an immediately-expiring one.
//! assert!(cookie.clear_header_value().unwrap().contains("Max-Age=0"));
//! ```

use crate::config::SessionConfig;
use crate::error::{SessionError, SessionResult};
use std::fmt;
use std::time::Duration;

/// The `SameSite` cookie attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SameSite {
    /// Sent only on same-site requests.
    Strict,
    /// Sent on same-site requests and top-level cross-site navigations (default).
    #[default]
    Lax,
    /// Sent on all requests. Browsers require `Secure` for this value, so
    /// [`SessionCookie`] refuses to build a `SameSite=None` cookie without it.
    None,
}

impl fmt::Display for SameSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        })
    }
}

/// Builder for a hardened session `Set-Cookie` header value.
#[derive(Debug, Clone)]
pub struct SessionCookie {
    name: String,
    host_prefix: bool,
    secure: bool,
    http_only: bool,
    same_site: SameSite,
    path: String,
    domain: Option<String>,
    max_age: Option<Duration>,
}

impl SessionCookie {
    /// Prefix that pins a cookie to the host that set it.
    pub const HOST_PREFIX: &'static str = "__Host-";

    /// Create a cookie builder with secure defaults: `Secure`, `HttpOnly`,
    /// `SameSite=Lax`, `Path=/`, no `Domain`, no `Max-Age` (session cookie).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            host_prefix: false,
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            path: "/".to_string(),
            domain: None,
            max_age: None,
        }
    }

    /// Use the `__Host-` name prefix.
    ///
    /// When enabled, building the cookie forces `Secure`, `Path=/` and no
    /// `Domain` regardless of the other settings, since browsers reject
    /// `__Host-` cookies that do not meet those rules.
    pub fn host_prefix(mut self, enabled: bool) -> Self {
        self.host_prefix = enabled;
        self
    }

    /// Set the `Secure` attribute (default `true`).
    ///
    /// Only turn this off for local plain-HTTP development. Ignored when the
    /// `__Host-` prefix is enabled.
    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Set the `HttpOnly` attribute (default `true`).
    pub fn http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    /// Set the `SameSite` attribute (default [`SameSite::Lax`]).
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    /// Set the `Path` attribute (default `/`). Ignored with the `__Host-` prefix.
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// Set the `Domain` attribute (default: none, i.e. host-only).
    /// Ignored with the `__Host-` prefix.
    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Set `Max-Age` explicitly.
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Set `Max-Age` to the configuration's absolute session lifetime
    /// ([`SessionConfig::max_ttl`]); the server-side store enforces the
    /// shorter sliding and idle expiries.
    pub fn max_age_from(self, config: &SessionConfig) -> Self {
        self.max_age(config.max_ttl)
    }

    /// The cookie name as sent to the browser (including any `__Host-` prefix).
    pub fn cookie_name(&self) -> String {
        if self.host_prefix {
            format!("{}{}", Self::HOST_PREFIX, self.name)
        } else {
            self.name.clone()
        }
    }

    /// Build the `Set-Cookie` header value carrying `session_id`.
    ///
    /// Fails if the name, value, path or domain contain characters that are
    /// not allowed in a cookie (which also rules out header injection), or if
    /// `SameSite=None` is requested without `Secure`.
    pub fn to_header_value(&self, session_id: &str) -> SessionResult<String> {
        self.render(session_id, self.max_age)
    }

    /// Build a `Set-Cookie` header value that deletes the cookie
    /// (empty value, `Max-Age=0`), for logout.
    pub fn clear_header_value(&self) -> SessionResult<String> {
        self.render("", Some(Duration::ZERO))
    }

    /// Extract this cookie's value from a request `Cookie` header.
    pub fn value_from_cookie_header<'a>(&self, cookie_header: &'a str) -> Option<&'a str> {
        let name = self.cookie_name();
        cookie_header.split(';').find_map(|pair| {
            let (k, v) = pair.trim().split_once('=')?;
            (k == name).then_some(v)
        })
    }

    fn render(&self, value: &str, max_age: Option<Duration>) -> SessionResult<String> {
        let (secure, path, domain) = if self.host_prefix {
            (true, "/", None)
        } else {
            (self.secure, self.path.as_str(), self.domain.as_deref())
        };

        if self.name.is_empty() || !self.name.bytes().all(is_token_byte) {
            return Err(SessionError::Config(
                "cookie name must be a non-empty RFC 6265 token".to_string(),
            ));
        }
        if !value.bytes().all(is_cookie_octet) {
            return Err(SessionError::Config(
                "cookie value contains characters not allowed in a cookie".to_string(),
            ));
        }
        if !is_attr_value(path) || domain.is_some_and(|d| d.is_empty() || !is_attr_value(d)) {
            return Err(SessionError::Config(
                "cookie path/domain contains characters not allowed in a cookie".to_string(),
            ));
        }
        if self.same_site == SameSite::None && !secure {
            return Err(SessionError::Config(
                "SameSite=None requires the Secure attribute".to_string(),
            ));
        }

        let mut out = format!("{}={}; Path={}", self.cookie_name(), value, path);
        if let Some(domain) = domain {
            out.push_str("; Domain=");
            out.push_str(domain);
        }
        if let Some(max_age) = max_age {
            out.push_str(&format!("; Max-Age={}", max_age.as_secs()));
        }
        if secure {
            out.push_str("; Secure");
        }
        if self.http_only {
            out.push_str("; HttpOnly");
        }
        out.push_str(&format!("; SameSite={}", self.same_site));
        Ok(out)
    }
}

/// RFC 6265 `cookie-octet`.
fn is_cookie_octet(b: u8) -> bool {
    matches!(b, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E)
}

/// RFC 7230 `tchar` (cookie names are tokens).
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Attribute values may not contain CTLs or `;`.
fn is_attr_value(s: &str) -> bool {
    s.bytes().all(|b| (0x20..0x7F).contains(&b) && b != b';')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_session_id;

    #[test]
    fn defaults_are_hardened() {
        let id = generate_session_id();
        let value = SessionCookie::new("sid").to_header_value(&id).unwrap();
        assert_eq!(
            value,
            format!("sid={id}; Path=/; Secure; HttpOnly; SameSite=Lax")
        );
    }

    #[test]
    fn host_prefix_forces_secure_root_path_and_no_domain() {
        let value = SessionCookie::new("sid")
            .host_prefix(true)
            .secure(false)
            .path("/app")
            .domain("example.com")
            .to_header_value("abc")
            .unwrap();
        assert!(value.starts_with("__Host-sid=abc; Path=/;"), "{value}");
        assert!(value.contains("; Secure"));
        assert!(!value.contains("Domain"));
        assert!(!value.contains("/app"));
    }

    #[test]
    fn max_age_from_config() {
        let config = SessionConfig::default().with_max_ttl(Duration::from_secs(7200));
        let value = SessionCookie::new("sid")
            .max_age_from(&config)
            .to_header_value("abc")
            .unwrap();
        assert!(value.contains("; Max-Age=7200"), "{value}");
    }

    #[test]
    fn clear_expires_immediately() {
        let value = SessionCookie::new("sid")
            .host_prefix(true)
            .clear_header_value()
            .unwrap();
        assert!(value.starts_with("__Host-sid=; Path=/; Max-Age=0; Secure"));
    }

    #[test]
    fn opt_outs_and_strict() {
        let value = SessionCookie::new("sid")
            .secure(false)
            .http_only(false)
            .same_site(SameSite::Strict)
            .domain("example.com")
            .to_header_value("abc")
            .unwrap();
        assert_eq!(
            value,
            "sid=abc; Path=/; Domain=example.com; SameSite=Strict"
        );
    }

    #[test]
    fn rejects_injection_and_insecure_none() {
        let c = SessionCookie::new("sid");
        assert!(c.to_header_value("abc\r\nSet-Cookie: x=y").is_err());
        assert!(c.to_header_value("a;b").is_err());
        assert!(c.to_header_value("a b").is_err());
        assert!(SessionCookie::new("s id").to_header_value("a").is_err());
        assert!(SessionCookie::new("").to_header_value("a").is_err());
        assert!(
            c.clone()
                .domain("x.com; Secure")
                .to_header_value("a")
                .is_err()
        );
        assert!(c.clone().path("/\r\n").to_header_value("a").is_err());
        assert!(
            c.clone()
                .secure(false)
                .same_site(SameSite::None)
                .to_header_value("a")
                .is_err()
        );
        assert!(c.same_site(SameSite::None).to_header_value("a").is_ok());
    }

    #[test]
    fn reads_value_from_cookie_header() {
        let c = SessionCookie::new("sid").host_prefix(true);
        assert_eq!(
            c.value_from_cookie_header("a=1; __Host-sid=xyz; b=2"),
            Some("xyz")
        );
        // The unprefixed name is a different cookie (could be set by a subdomain).
        assert_eq!(c.value_from_cookie_header("sid=evil"), None);
    }
}
