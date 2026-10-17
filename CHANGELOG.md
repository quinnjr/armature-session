# Changelog — `armature-session`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

## [0.4.0] - 2026-10-17

### Security

- **Session fixation:** new `SessionStore::regenerate(old_id)` (default trait method) issues a fresh ID for an existing session, carries its data over, and deletes the old ID. Call it after login or any privilege change.
- **Session IDs are now 256 bits from the OS CSPRNG** (`getrandom`), encoded as 64 lowercase hex characters, instead of UUIDv4 (122 random bits).
- **Every backend validates session IDs** (`validate_session_id`: exactly 64 lowercase hex characters) before any backend command. A client-supplied ID such as `"a\r\nset x …"` can no longer inject commands into memcached's ASCII protocol. Redis and memcached go through `SessionConfig::checked_session_key`, and CouchDB through the same validator. The rejected value is never echoed in the error.
- **Absolute and idle lifetimes are enforced on load.** `Session::absolute_expires_at` is fixed at creation (`max_ttl`), and `extend`, `touch` and `regenerate` never move it. `SessionConfig::idle_timeout` (default 1 h) drops sessions not accessed recently. A session that is expired, idle, or stored under a different ID is deleted and treated as missing. `exists()` now applies the same rules; on Redis it no longer uses a bare `EXISTS`.
- **Hardened cookie helper** `SessionCookie`. Defaults: `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`. It has an optional `__Host-` prefix, which forces Secure, `Path=/` and no `Domain`, and takes `Max-Age` from config. It rejects cookie/header-injection characters and refuses `SameSite=None` without `Secure`.
- **Credential redaction:** `SessionConfig`'s `Debug` prints `password` and any `user:pass@` userinfo in `url` as `<redacted>`.
- `SessionConfig::validate()` runs in every store constructor. It rejects empty namespaces and namespaces containing whitespace or control characters, namespaces too long for memcached's 250-byte key limit, zero lifetimes, and `default_ttl > max_ttl`.

### Changed

- **Breaking:** `Session` has a new required field `absolute_expires_at`. Sessions stored by earlier versions (UUID IDs, no field) are no longer readable, so users must log in again after upgrading. Migration: none needed beyond accepting the one-time logout.
- **Breaking:** `generate_session_id()` returns 64 hex chars, and UUID-format IDs are rejected with `SessionError::InvalidSessionId`. This now applies on Redis and memcached too, not just CouchDB.
- **Breaking:** `SessionConfig` has a new public field `idle_timeout`. Migration: struct literals need `..Default::default()`, or set it with `with_idle_timeout`.
- **Breaking:** `Session::new(id, ttl)` now caps the absolute lifetime at `ttl`. Migration: chain `.with_absolute_lifetime(d)` to allow sliding beyond it. `Session::extend` clamps to the absolute expiry.
- Memcached `save()` of an already-expired session now returns `SessionError::Expired` instead of silently doing nothing, matching Redis. TTLs above memcached's 30-day relative limit are capped.
- `SessionError::Expired` no longer carries the session ID (it is a bearer secret).
- `tokio` no longer uses `features = ["full"]`: only `sync` at runtime, plus `macros`/`rt-multi-thread`/`test-util` for tests.
- `memcached-tls` is documented as an **opt-in OpenSSL exception**: `memcache` 0.21 has no rustls backend. It is excluded from `full`, and it now implies `memcached`.

### Removed

- Unused `uuid` and `futures` dependencies.


## [0.3.1] - 2026-09-15

### Changed

- Dependencies bumped to their latest releases: `memcache` 0.19 → 0.21, `redis` 1.0 → 1.7, `reqwest` 0.12 → 0.13, `tokio` 1.35 → 1.53, `uuid` 1.11 → 1.26, `tokio` 1.35 → 1.53.

## [0.3.0] - 2026-08-04

### Fixed

- **Breaking:** `RedisSessionStore::save` returns an error when the computed TTL is not positive, instead of skipping the write and returning `Ok(())` — `create()` could hand back a session that was never persisted.

