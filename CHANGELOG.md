# Changelog — `armature-session`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

## [0.3.1] - 2026-09-15

### Changed

- Dependencies bumped to their latest releases: `memcache` 0.19 → 0.21, `redis` 1.0 → 1.7, `reqwest` 0.12 → 0.13, `tokio` 1.35 → 1.53, `uuid` 1.11 → 1.26, `tokio` 1.35 → 1.53.

## [0.3.0] - 2026-08-04

### Fixed

- **Breaking:** `RedisSessionStore::save` returns an error when the computed TTL is not positive, instead of skipping the write and returning `Ok(())` — `create()` could hand back a session that was never persisted.

