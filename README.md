# zoreal-oauth2

[![Crates.io](https://img.shields.io/crates/v/zoreal-oauth2)](https://crates.io/crates/zoreal-oauth2) [![docs.rs](https://img.shields.io/docsrs/zoreal-oauth2)](https://docs.rs/zoreal-oauth2) [![CI](https://img.shields.io/github/actions/workflow/status/Bynn-Intelligence/zoreal-oauth2-rust/ci.yml?branch=main&label=CI)](https://github.com/Bynn-Intelligence/zoreal-oauth2-rust/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Bynn-Intelligence/zoreal-oauth2-rust/badge)](https://scorecard.dev/viewer/?uri=github.com/Bynn-Intelligence/zoreal-oauth2-rust) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Sign in with ZOREAL for Rust backends: the relying-party half of the flow that
[`@zoreal/oauth2-react`](https://github.com/Bynn-Intelligence/zoreal-oauth2-react)
starts in the browser.

The browser SDK runs the pairing (QR code or app link), and hands your frontend
an authorization `code` plus the `code_verifier` and `nonce` it generated. Your
frontend posts all three to your backend, and this crate does the rest: the
code exchange with your client authentication, ES256 verification of the ID
token against the provider's JWKS, and the `/userinfo` read for personal
claims.

```
zoreal-oauth2 (this crate)   your backend: exchange, verify, userinfo
@zoreal/oauth2-react         your frontend: the "Continue with ZOREAL" button, the QR, the polling
```

## Install

```sh
cargo add zoreal-oauth2
```

Rust >= 1.89. Async on tokio, HTTP through `reqwest` with rustls (no OpenSSL,
no default features), and no web framework: it works the same behind axum,
actix-web, warp or anything else. ES256 is verified with the RustCrypto `p256`
crate; the provider signs with EC P-256 keys and nothing else, so that is the
whole grammar this crate parses.

## Getting your credentials

Everything the builder needs comes from a ZOREAL **asset**.

1. Create an account at **https://zoreal.com** and open **Assets**.
2. **Create an asset**: a *website* (a domain you own) or an *app bundle* (a
   reverse-DNS bundle id). An asset is the thing users sign in to; its token is
   your `client_id` and it looks like `ast_...`.
3. On the asset, open the **OAuth2** tab and set:
   - the **JavaScript origins** that show the button (a pairing started from an
     origin that is not registered is rejected: this is the core control).
     Nothing in the flow redirects, so redirect URIs are optional,
   - the **scopes** the client is allowed to request (see the catalogue below),
   - your **client authentication**: generate a **client secret**
     (`client_secret_basic`), or register a **JWKS** for `private_key_jwt`. A
     public client authenticates with PKCE alone and no secret.
4. A website asset must **verify its domain** (a DNS or meta-tag proof, shown in
   the dashboard) before it can sign users in; the verified domain is what your
   users' `sub` is pairwise against.

The `client_id` is public (it ships in your frontend). The client secret is
not: keep it in your server's secret store (an environment variable, a secrets
manager), never in the browser. This crate holds it in a
[`secrecy::SecretString`](https://docs.rs/secrecy), so it never appears in
`Debug` output or in an error.

### There is no test-identity sandbox, and that is deliberate

ZOREAL **never issues fake or sandbox humans**: a pool of test identities would
be a fraud vector against the exact thing the product proves. So you always
authenticate **real** ZOREAL IDs.

To develop and test, **create a free ZOREAL ID for yourself** (enrol in the
ZOREAL ID app) and sign in with it. Mark your asset's environment **sandbox**
in the dashboard while building (a sandbox asset may register `http://localhost`
origins that a production asset may not) and flip it to production when you
ship. The identities are real either way; only the allowed origins differ.

## Quick start

Build one client at startup and share it. `Client` is `Clone + Send + Sync`,
and clones share the JWKS cache and the connection pool.

```rust
use zoreal_oauth2::Client;

let zoreal = Client::builder(std::env::var("ZOREAL_CLIENT_ID")?) // ast_...
    .client_secret(std::env::var("ZOREAL_CLIENT_SECRET")?)
    // .issuer(...) defaults to https://id.zoreal.com
    .build()?;
```

The endpoint your frontend posts to:

```rust
let login = zoreal
    .authenticate(
        &body.code,
        &body.code_verifier, // PKCE is mandatory; the SDK hands it over
        &body.nonce,         // mandatory: binds the ID token to this login
        None,                // or Some(Acr::Live) for a step-up login
    )
    .await?;

login.sub();          // "TC5X-JN7G-YTSE-6E63": pairwise, stable for YOUR domain
login.acr();          // Some("zoreal.device"): what happened, never what was requested
login.assurance();    // uniqueness basis, verification month, chip liveness, trust tier
login.email().await?; // from /userinfo, when your client has the email scope
login.email_verified().await?;
login.name().await?;  // from /userinfo, profile.name scope
```

Account matching, the shape that works: look the user up by (`"zoreal"`,
`login.sub()`) first; only when that misses, and only when
`login.email_verified().await?` is true, claim an existing account by its
email, then store the provider and `sub` on it. Claim, don't collide.

## Assurance levels: `acr`, and requiring a liveness check

### What `acr` is

`acr` is an OpenID Connect standard claim, *Authentication Context Class
Reference*. It is a single string in the ID token that says **how this
particular login was authenticated**. Every ZOREAL login carries one. Read it
with `login.acr()` (the raw string) or `login.acr_level()` (an `Acr`).

It answers a question the `sub` cannot. `login.sub()` tells you *who* (a
stable, pairwise identifier for this person at your site). `login.acr()` tells
you *how the person was authenticated for this login*. A stolen, unlocked phone
can still produce a `sub`; it cannot produce a fresh `zoreal.live`.

### The three levels

Ordered weakest to strongest. Each is what actually happened, never what was
requested: a login that could only reach a weaker level says so rather than
claiming the level you asked for.

| `acr` | `Acr` | What the holder did | `amr` | What it shows | What it does **not** show |
|---|---|---|---|---|---|
| `zoreal.session` | `Acr::Session` | Nothing: a returning holder, resumed silently from an existing session, no phone interaction | `[]` | Continuity with a session ZOREAL already knew | That the holder is present |
| `zoreal.device` | `Acr::Device` | Approved the login on their enrolled phone: a signature from a hardware-backed key, released by a local biometric or passcode unlock | `["hwk","user"]` | Possession of the enrolled device **and** a local unlock on it | That a face was captured for *this* login; an unlocked phone in the wrong hands still signs |
| `zoreal.live` | `Acr::Live` | All of the above **plus** a fresh face capture for this login, scored for presentation attacks and screen replay, and matched 1:1 against the document read at enrolment | `["hwk","face","user"]` | That the enrolled person was in front of the phone **at the moment of this login** | Anything about the person at the *browser* (see below) |

`amr` (*Authentication Methods References*, `login.amr()`) lists the factors
used: `hwk` a hardware key, `user` a user-presence or unlock gesture, `face` a
face capture. `zoreal.live` is exactly `zoreal.device` with `face` added.

The **default is `zoreal.device`**, never `zoreal.session`: a login that asks
for nothing still requires the enrolled phone and a local unlock. Silence has
to be explicitly asked for (`prompt=none`).

### When to require which

- **`Acr::Session`**: you never *require* this.
- **`Acr::Device`** (the default): a forum, a community, a normal account
  login. Possession of the enrolled phone plus a local unlock is a high bar
  already; most sites want exactly this and should pass no floor at all.
- **`Acr::Live`**: a high-value transaction, an age-gated purchase, a "confirm
  it is really you" step before a sensitive action. Anywhere a fresh face
  capture is worth the few seconds it costs.

### Requesting versus verifying: the one rule that matters

Requesting a level and verifying it are **two separate steps, and only the
second is security**:

1. **Request** it on the wire, in the frontend, with the SDK's
   `acr_values: 'zoreal.live'`. This is what makes the holder's ZOREAL ID app
   run the face capture before it will approve. It is **advisory**: it shapes
   what the holder is asked to do, nothing more. A browser is
   attacker-controlled; a value that only travels through it proves nothing.
2. **Verify** it here, at token exchange, by passing a floor. The signed `acr`
   claim in the ID token, minted by ZOREAL and not by the browser, is the
   proof.

```rust
use zoreal_oauth2::Acr;

let login = zoreal
    .authenticate(&code, &code_verifier, &nonce, Some(Acr::Live)) // Error::Verification unless the signed token says so
    .await?;

login.acr();                       // Some("zoreal.live"): what actually happened
login.is_live();                   // convenience: acr_level() == Some(Acr::Live)
login.satisfies_acr(Acr::Device);  // true: live is stronger than device
```

**A relying party that requests `zoreal.live` on the wire but never passes the
floor here has checked nothing**: it has only asked the holder nicely and then
trusted a value it never validated.

### How the check behaves

Verification satisfies **upward**: `Acr::Session < Acr::Device < Acr::Live`
(`Acr` implements `Ord`), so a floor of `Acr::Device` accepts a `zoreal.live`
token. A token whose `acr` is below the floor, missing, or outside the
vocabulary is refused with `Error::Verification`.

The floor is typed, so a typo cannot compile. When it comes from
configuration, parse it with `str::parse::<Acr>()`: an unknown value such as
`"zoreal.liveness"` is an `Error::Configuration`, because that is a bug in your
configuration, not a bad token, and failing every login silently would be
worse than saying so.

If you prefer to branch rather than have verification refuse the token, pass
no floor and inspect the result:

```rust
let login = zoreal.authenticate(&code, &code_verifier, &nonce, None).await?;
if !login.satisfies_acr(Acr::Live) {
    // step the user up, or refuse the sensitive action
}
```

### `acr` versus the assurance block

Do not confuse `login.acr()` with `login.assurance()`. `acr` grades *this login
event*. The **assurance block** describes the *identity behind it*: how the
person was verified at enrolment (uniqueness basis, verification month, whether
chip liveness was proven, the trust tier, the device's key protection). One is
about now; the other is about the identity. A high-value flow usually wants
both: `Some(Acr::Live)` for presence, and the assurance block for the strength
of the underlying identity proofing. The block's schema is
[below](#the-assurance-block).

## What each call does

| Call | What happens |
|---|---|
| `authenticate(code, code_verifier, nonce, acr_floor)` | `exchange` + `verify_id_token`, returns a `Login` |
| `exchange(code, code_verifier)` | `POST {issuer}/token` with your client authentication, returns a `TokenResponse` |
| `verify_id_token(jwt, nonce, acr_floor)` | ES256 against `{issuer}/jwks`; checks `iss` exactly, `aud`, `exp` (30 s leeway), `nbf` and `iat` when present, the `nonce` (mandatory), and the floor. Returns the `IdTokenClaims` |
| `userinfo(&access_token)` | `GET {issuer}/userinfo` with the Bearer token, returns `Userinfo` |
| `Login::userinfo()` | the above, once, kept; empty when there is no access token; refused if its `sub` differs from the ID token's |

Tier A claims read straight off the `Login`: `sub()`, `acr()`, `acr_level()`,
`amr()`, `assurance()`, `age_over(n)`, `nationality()`, `iat()`, `exp()`,
`auth_time()`. The Tier B and C accessors are `async` and read `/userinfo` on
first use: `email()`, `email_verified()`, `name()`, `given_name()`,
`family_name()`, `birthdate()`, `document_type()`, `document_number()`,
`issuing_country()`, `document_expires_on()` and `portrait()`.

The JWKS is cached in process for ten minutes (`JWKS_TTL`, the provider's own
cache lifetime). A token whose `kid` the cache does not hold triggers one
refetch, so a key rotation never strands a login; forced refetches are limited
to one per ten seconds, so forged `kid` values cannot turn verification into a
stream of JWKS requests.

## Client authentication

| Method | Configuration | Notes |
|---|---|---|
| `none` | `ClientAuth::None` (the default) | Public client: PKCE is the only proof, Tier A scopes only |
| `client_secret_basic` | `.client_secret(secret)` or `ClientAuth::client_secret_basic(secret)` | The secret travels as HTTP Basic, never as a form field |
| `private_key_jwt` | `ClientAuth::PrivateKeyJwt(PrivateKey::from_pem(pem)?.with_kid("..."))` | The crate signs a fresh RFC 7523 assertion per exchange: ES256 with a P-256 key, `iss` = `sub` = client id, `aud` = `{issuer}/token`, 60-second lifetime, single-use `jti`. The key never travels |
| `tls_client_auth` | `ClientAuth::TlsClientAuth(TlsIdentity::from_pem(cert_chain, &key)?)` | The certificate rides the TLS handshake on every request. The provider accepts the method at registration but answers 501 at the token endpoint today, which surfaces as the `Error::Exchange` it is |

`PrivateKey::from_pem` reads PKCS #8 (`BEGIN PRIVATE KEY`) and SEC1
(`BEGIN EC PRIVATE KEY`) keys; `PrivateKey::from_pkcs8_der` reads DER. The key
must be on P-256 (RSA client keys are not supported by this crate). Whatever the
method, the form always carries `client_id`.

```rust
use zoreal_oauth2::{Client, ClientAuth, PrivateKey};

let key = PrivateKey::from_pem(&std::env::var("ZOREAL_PRIVATE_KEY_PEM")?)?.with_kid("rp-2026");
let zoreal = Client::builder(std::env::var("ZOREAL_CLIENT_ID")?)
    .auth(ClientAuth::PrivateKeyJwt(key))
    .build()?;
```

## Scopes and claims

Scopes are requested in the **frontend** (the SDK's `scope` string, always
starting with `openid`), consented to by the holder, and pre-authorized on your
asset. What each grants and where it is delivered:

| Scope | Claims | Delivered in | Tier | Requires |
|---|---|---|---|---|
| `openid` | `sub`, `iss`, `aud`, `exp`, `iat`, `nonce`, `auth_time`, `acr`, `amr`, and the assurance block | ID token | A | any client |
| `zoreal.age` | `age_over_13/16/18/21/65` booleans, only the thresholds you registered, never an age or birthdate | ID token | A | any client |
| `zoreal.nationality` | `nationality` (ISO 3166-1 alpha-3) | ID token | A | any client |
| `email` | `email`, `email_verified` | `/userinfo` | B | confidential client + verified domain |
| `profile.name` | `name`, `given_name`, `family_name` | `/userinfo` | B | confidential client + verified domain |
| `profile.birthdate` | `birthdate` (full ISO 8601 date) | `/userinfo` | B | confidential client + verified domain |
| `profile.document` | `document_type`, `document_number`, `issuing_country`, `document_expires_on` | `/userinfo` | B | confidential client + verified domain |
| `profile.portrait` | `portrait` (the chip's facial image; special-category data under the GDPR) | `/userinfo` | C | confidential client + verified domain; *registrable but not served yet* |

- **Tier A** rides in the ID token and is available to every client.
- **Tier B and C** are personal data, served only from `/userinfo` to a
  confidential client on a domain you have verified, and never placed in a
  browser token.
- **A claim the document did not carry is absent, never empty.** Every
  accessor returns an `Option`: `nationality` is missing on some travel
  documents, `document_expires_on` on cards that do not expire, `email` when the
  holder enrolled without one, and `uniqueness: personal_number` when the chip
  carries no personal number.
- **Age thresholds are a fixed set** (13, 16, 18, 21, 65) that you register on
  the asset. `login.age_over(n)` returns `None` for a threshold you did not
  register (no claim was minted), which is a different fact from
  `Some(false)`.

## Error reference

Every call returns `zoreal_oauth2::Error`, one enum with four variants. Each
carries its underlying error as `source()` where there is one, and no token,
code, secret or key value ever appears in its message.

| Variant | Means |
|---|---|
| `Error::Configuration { message, .. }` | You built the client wrong (no client id, an issuer that is not `https`, a key that does not parse), or parsed an `Acr` outside the vocabulary. A bug in your code, not a bad token |
| `Error::Exchange { oauth_error, description, status, .. }` | The code exchange at `/token` failed. `oauth_error` and `description` are the provider's, verbatim; `status` is `None` when no response arrived (a timeout, a refused connection) |
| `Error::Verification { reason, .. }` | The ID token did not verify: signature, algorithm, `iss`, `aud`, `exp`, the `nonce`, or the floor. A JWKS that could not be fetched lands here too, because a token that cannot be checked is a token that did not verify |
| `Error::Userinfo { description, status, .. }` | The `/userinfo` read failed. A returning user matched on `sub` can survive it; a signup that needs the email cannot. A failure is not cached, so a later call retries |

`err.oauth_error()`, `err.status()` and `err.is_configuration()` /
`is_exchange()` / `is_verification()` / `is_userinfo()` save a `match` where
you only need one fact.

What you will see in `Error::Exchange::oauth_error`:

| `oauth_error` | Cause | Retryable? |
|---|---|---|
| `invalid_grant` | The code is spent: unknown, expired (60 s), already used, PKCE mismatch, or the asset's domain verification lapsed mid-flow | No. Start a **new** login; the code cannot be reused |
| `invalid_request` | Client authentication failed (wrong secret, a bad `private_key_jwt` assertion, or `tls_client_auth`, not accepted at `/token` yet), or a code or verifier was missing | No. Fix your client configuration |
| `unsupported_grant_type` | Something other than `authorization_code` reached `/token` | No. A bug |

Errors that surface in the **frontend** instead, before your backend is
involved (from the SDK's `onError` / `onNonOAuthError` callbacks), so handle
them there:

| Where | Code | Meaning |
|---|---|---|
| `/pair` | `invalid_scope` | A scope not on the asset's allowed list, or a Tier B scope from a public client |
| `/pair` | `invalid_request` | Missing PKCE or nonce, an unverified domain, an unregistered origin, or an unknown `acr_values` |
| `/pair` | `login_required` | `prompt=none` with no silent session to resume |
| pairing | `request_denied` | The holder declined in their ZOREAL ID app: **not an error to alarm on**; offer to try again |
| pairing | `request_expired` | The pairing window elapsed, or a required liveness the device could not meet; offer to try again |

## The assurance block

`login.assurance()` is the ID token's `zoreal` claim, typed as `Assurance`. It
describes the strength of the *identity* behind this login (distinct from
`acr`, which grades the *login event*):

| Field | Type and values | Meaning |
|---|---|---|
| `uniqueness` | `Uniqueness::PersonalNumber` \| `Document` \| `NoAnchor` | The anchor the holder is deduplicated on. `PersonalNumber` (a national number from the chip) holds across documents; on `Document`, one person holding two documents counts as two |
| `verified_on` | `"YYYY-MM"` | The month the underlying document was verified. A month on purpose: a day-precision date is a cross-site correlator |
| `chip_liveness_proven` | `bool` | Whether the document chip's active-authentication challenge was proven (a genuine chip, not a clone) |
| `trust_tier` | `TrustTier::High` \| `Standard` | `High` when chip liveness was proven |
| `key_protection` | `KeyProtection::SecureEnclave` \| `Strongbox` \| `Tee` \| `Software` | How the holder's device key is protected. `Software` means no hardware attestation |

Every field is an `Option`, and every enum has an `Unknown` variant, so a value
a newer provider adds does not fail verification. **Gate on
`Uniqueness::PersonalNumber` only if you need one account per human**, and know
that it excludes holders whose documents carry no personal number.

```rust
use zoreal_oauth2::{TrustTier, Uniqueness};

let strong = login.assurance().is_some_and(|a| {
    a.uniqueness == Some(Uniqueness::PersonalNumber) && a.trust_tier == Some(TrustTier::High)
});
```

## A complete example

An axum handler, end to end. The crate does not depend on axum; any framework
looks the same.

```rust
use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;
use zoreal_oauth2::{Client, Error};

#[derive(Deserialize)]
struct ZorealCallback {
    code: String,
    code_verifier: String,
    nonce: String,
}

// Your frontend's onSuccess posts { code, code_verifier, nonce } here over your
// own TLS. Protect this route with your normal CSRF / same-origin controls,
// exactly as you would any login endpoint: the ZOREAL nonce protects the
// token, not your route.
async fn zoreal_login(
    State(zoreal): State<Client>,
    Json(body): Json<ZorealCallback>,
) -> Result<StatusCode, StatusCode> {
    let login = zoreal
        .authenticate(&body.code, &body.code_verifier, &body.nonce, None)
        // .authenticate(..., Some(Acr::Live)) for a step-up / high-value login
        .await
        .map_err(|err| match err {
            // A bug in this server's configuration, not the holder's problem.
            Error::Configuration { .. } => StatusCode::SERVICE_UNAVAILABLE,
            // A spent code or a token that did not verify: restart the login.
            // Log err; do not send its reason to the browser.
            _ => StatusCode::UNAUTHORIZED,
        })?;

    // Match on (provider, sub) first.
    let user = match find_user_by_provider("zoreal", login.sub()).await {
        Some(user) => user,
        None => {
            // Personal data lives at /userinfo. A failure here is fatal only
            // because a new account needs the email.
            let email = login.email().await.map_err(|_| StatusCode::UNAUTHORIZED)?;
            let verified = login.email_verified().await.map_err(|_| StatusCode::UNAUTHORIZED)?;
            let existing = match (email, verified) {
                (Some(email), true) => find_user_by_email(email).await, // claim, don't collide
                _ => None,
            };
            let user = match existing {
                Some(user) => user,
                None => create_user(email, login.name().await.ok().flatten()).await,
            };
            link_provider(&user, "zoreal", login.sub()).await;
            user
        }
    };

    establish_session(&user).await; // your session, rotated against fixation
    Ok(StatusCode::NO_CONTENT)
}
```

`find_user_by_provider`, `find_user_by_email`, `create_user`, `link_provider`
and `establish_session` are your application's own; the crate's job ends at a
verified `Login`.

## Things worth knowing before you integrate

- **The button says "Continue with ZOREAL"** (or "Sign in with ZOREAL" /
  "Sign up with ZOREAL"). It asserts nothing about the person, because it
  appears before anyone has authenticated.
- **What a ZOREAL login does not tell you.** It authenticates a human to your
  site. It is **not KYC**: a verified name at sign-in is not a KYC record, with
  none of the screening or retention obligations a KYC product carries. It is
  not a legal signature. It does not prove that the person at the browser is
  the person who approved on the phone (someone can be talked into scanning a
  QR code from the wrong site), or that consent was given freely. And ZOREAL
  does not vouch for the person: a document was verified and a face was
  captured, nothing more was assessed.
- **The ID token never carries personal data.** `sub`, timing, `acr`/`amr`,
  the assurance block, and, if registered, `age_over_*` booleans and
  `nationality`. Email, names, birthdate and document fields come only from
  `/userinfo`, which is why `authenticate` alone is not enough for a signup.
- **The ID token lives two minutes and the access token ten.** Verify right
  after the exchange and read `/userinfo` while handling the login; store
  neither token.
- **`sub` is pairwise per verified domain.** It is the right account key and
  it is derived from your registered domain: changing your asset's domain
  rotates every `sub` you have stored. Plan domain changes as a migration, and
  delete the `sub` with the account.
- **ES256 only.** The provider signs ID tokens with nothing else, and this
  crate refuses every other `alg`, `none` included, before it looks at a key.
- **The nonce is mandatory, and it is not your CSRF token.** The SDK generates
  it and gives it to your frontend in `onSuccess`; passing it here confirms the
  ID token was minted for *this* login rather than substituted. Protect your
  login route with your framework's normal CSRF / same-origin defence, and
  remember that PKCE, not the nonce, proves whoever exchanges the code is
  whoever started the flow. Do not log the nonce or the verifier.
- **Email is a deliberate choice.** It is a Tier B scope because a shared email
  defeats the unlinkability the pairwise `sub` provides. Request it because you
  need it, not because the checkbox is familiar.
- **The issuer must match the token's `iss` exactly.** It is compared, not
  normalized. Production is `https://id.zoreal.com` (the default); set
  `.issuer(...)` only when you were given a non-production provider. The
  issuer must be `https` (plain `http` is accepted only on a loopback host, for
  tests).
- **Nothing panics on untrusted input.** Tokens, JWKS documents and provider
  responses are size-capped and parsed defensively; every failure is an
  `Error`.

## Verifying this release

Every version is published from GitHub Actions by
[crates.io trusted publishing](https://crates.io/docs/trusted-publishing): the
workflow authenticates to crates.io over OIDC and no long-lived API token is
stored. Each `.crate` is also attested with [Sigstore](https://www.sigstore.dev/)
build provenance and recorded in a public transparency log, so you can confirm
which commit and workflow produced it:

```sh
curl -sSfL -o zoreal-oauth2-0.1.0.crate https://crates.io/api/v1/crates/zoreal-oauth2/0.1.0/download
gh attestation verify zoreal-oauth2-0.1.0.crate --repo Bynn-Intelligence/zoreal-oauth2-rust
```

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
cargo audit
```

The tests are offline: they generate a P-256 key in process and serve the
JWKS, token and userinfo endpoints from a local mock server.

## The ZOREAL OAuth2 library family

| Repository | Package | Role |
|---|---|---|
| zoreal-oauth2-react | @zoreal/oauth2-react (npm) | React frontend: the button, the QR, the polling |
| zoreal-oauth2-js | @zoreal/oauth2-js (npm) | Framework-free browser core |
| zoreal-oauth2-react-native | @zoreal/oauth2-react-native (npm) | React Native frontend |
| zoreal-oauth2-node | @zoreal/oauth2-node (npm) | Node.js backend |
| zoreal-oauth2-ruby | zoreal-oauth2 (RubyGems) | Ruby backend |
| zoreal-oauth2-python | zoreal-oauth2 (PyPI) | Python backend |
| zoreal-oauth2-php | zoreal/oauth2 (Packagist) | PHP backend |
| zoreal-oauth2-go | github.com/Bynn-Intelligence/zoreal-oauth2-go | Go backend |
| zoreal-oauth2-java | com.zoreal:oauth2 (Maven Central) | JVM backend |
| zoreal-oauth2-dotnet | Zoreal.OAuth2 (NuGet) | .NET backend |
| zoreal-oauth2-rust | zoreal-oauth2 (crates.io) | Rust backend |

The repository always carries the platform suffix; the package drops it where
the registry already scopes the ecosystem. None of them are named after a
framework, because none of them depend on one.

## License

MIT.
