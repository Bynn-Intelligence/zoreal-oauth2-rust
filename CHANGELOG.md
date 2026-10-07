# Changelog

Every push to `main` publishes the next patch version to crates.io and
creates a GitHub release with the same number; the release notes list the
commits since the previous one.

## 0.1.0

First release of the Rust server SDK for Sign in with ZOREAL: the `Client`
builder with the four client auth methods, `authenticate` returning a `Login`,
the separate `exchange`, `verify_id_token` and `userinfo` steps, ES256-only ID
token verification and a JWKS cache with shared refresh and a bounded stale
fallback.
