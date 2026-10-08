# Changelog

Every push to `main` publishes the next patch version to crates.io and
creates a GitHub release with the same number; the release notes list the
commits since the previous one.

## 0.1.2

- `client_secret_basic` form-urlencodes the client id and secret before
  base64, as RFC 6749 section 2.3.1 requires. Issued `ast_` and `zcs_`
  values are unchanged by it.
- The HTTP client refuses plain `http` when the issuer is `https`.
- A refused or malformed `Login::userinfo()` answer is repeated from memory
  for two seconds (`USERINFO_RETRY_AFTER`), so the field accessors called one
  after another make one request between them. An immediate retry after such
  an answer no longer reaches the provider. A transport failure is not
  remembered and is retried at once, as before.

## 0.1.0

First release of the Rust server SDK for Sign in with ZOREAL: the `Client`
builder with the four client auth methods, `authenticate` returning a `Login`,
the separate `exchange`, `verify_id_token` and `userinfo` steps, ES256-only ID
token verification and a JWKS cache with shared refresh and a bounded stale
fallback.
