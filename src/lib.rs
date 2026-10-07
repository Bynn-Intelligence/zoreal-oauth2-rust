//! Sign in with ZOREAL for Rust backends: the relying-party half of the
//! OpenID Connect flow that the ZOREAL browser SDK
//! ([`@zoreal/oauth2-react`](https://github.com/Bynn-Intelligence/zoreal-oauth2-react)
//! or [`@zoreal/oauth2-js`](https://github.com/Bynn-Intelligence/zoreal-oauth2-js))
//! starts in the browser.
//!
//! The browser SDK runs the pairing (QR code or app link) and hands your
//! frontend an authorization `code` plus the `code_verifier` and `nonce` it
//! generated. Your frontend posts all three to your backend, and this crate
//! does the rest: the code exchange with your client authentication, ES256
//! verification of the ID token against the provider's JWKS, and the
//! `/userinfo` read for personal claims.
//!
//! The crate is async (tokio and reqwest with rustls) and does not depend on
//! any web framework.
//!
//! # Example
//!
//! ```no_run
//! use zoreal_oauth2::{Acr, Client, Error};
//!
//! # async fn handle(code: &str, code_verifier: &str, nonce: &str) -> Result<(), Error> {
//! // Build once at startup and share; clones are cheap.
//! let zoreal = Client::builder(std::env::var("ZOREAL_CLIENT_ID").unwrap_or_default()) // ast_...
//!     .client_secret(std::env::var("ZOREAL_CLIENT_SECRET").unwrap_or_default())
//!     .build()?;
//!
//! // In the handler your frontend posts { code, code_verifier, nonce } to:
//! let login = zoreal.authenticate(code, code_verifier, nonce, None).await?;
//!
//! let sub = login.sub(); // pairwise, stable for your verified domain: the account key
//! let device_or_better = login.satisfies_acr(Acr::Device);
//! let email = login.email().await?; // from /userinfo, with the email scope
//! # let _ = (sub, device_or_better, email);
//! # Ok(())
//! # }
//! ```
//!
//! To require a fresh face capture, request `acr_values: 'zoreal.live'` in
//! the browser SDK *and* pass `Some(Acr::Live)` as the floor here. Requesting
//! is advisory; only the floor checked against the signed `acr` claim is a
//! security control.
//!
//! # Errors
//!
//! Every fallible call returns [`Error`], with four kinds:
//! [`Error::Configuration`], [`Error::Exchange`], [`Error::Verification`] and
//! [`Error::Userinfo`]. Nothing in this crate panics on input from the
//! network or the browser, and no secret or token value appears in an error
//! or in Debug output.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod acr;
mod auth;
mod claims;
mod client;
mod error;
mod jwks;
mod jwt;
mod login;

use std::time::Duration;

pub use acr::Acr;
pub use auth::{ClientAuth, PrivateKey, TlsIdentity};
pub use claims::{Assurance, IdTokenClaims, KeyProtection, TrustTier, Uniqueness, Userinfo};
pub use client::{Client, ClientBuilder, TokenResponse};
pub use error::{BoxError, Error, Result};
pub use login::Login;
pub use secrecy::{ExposeSecret, SecretString};

/// The production ZOREAL OpenID Provider. Every endpoint is relative to the
/// issuer, and the configured value must equal the `iss` inside the tokens.
pub const DEFAULT_ISSUER: &str = "https://id.zoreal.com";

/// How long the fetched JWKS is held: the provider's own ten-minute cache
/// lifetime, so a busy relying party stays off the endpoint without holding a
/// rotated-out key longer than the provider itself would.
pub const JWKS_TTL: Duration = Duration::from_secs(600);

/// The default bound on every HTTP request.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// The default bound on establishing a connection.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// The default clock skew allowed on `exp`, `nbf` and `iat`. The ID token
/// lives two minutes, so verify it straight after the exchange.
pub const DEFAULT_LEEWAY: Duration = Duration::from_secs(30);

/// The lifetime of a `private_key_jwt` client assertion. The provider refuses
/// an assertion whose `exp` is more than 60 seconds out by its own clock;
/// 50 seconds leaves room for the relying party's clock to run ahead.
pub const ASSERTION_LIFETIME: Duration = Duration::from_secs(50);
