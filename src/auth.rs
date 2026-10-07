//! Client authentication at the token endpoint.

use std::fmt;

use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;
use secrecy::zeroize::Zeroize;
use secrecy::{ExposeSecret, SecretString};

use crate::error::{Error, Result};

/// How the client authenticates at `/token`: the four
/// `token_endpoint_auth_method` values a ZOREAL client can register.
///
/// Debug output never shows the secret or the key.
#[non_exhaustive]
pub enum ClientAuth {
    /// `none`: a public client. PKCE is the only proof, which is why a
    /// public client can only ever have been granted Tier A scopes.
    None,
    /// `client_secret_basic`: the secret travels as the HTTP Basic password,
    /// never as a form field.
    ClientSecretBasic(SecretString),
    /// `private_key_jwt`: a fresh RFC 7523 assertion is signed per exchange
    /// with an ES256 P-256 key. The key never travels.
    PrivateKeyJwt(PrivateKey),
    /// `tls_client_auth`: the certificate rides the TLS handshake of every
    /// request the client makes. The provider accepts the method at
    /// registration but answers 501 at the token endpoint today, which
    /// surfaces as the [`Error::Exchange`] it is.
    TlsClientAuth(TlsIdentity),
}

impl ClientAuth {
    /// `client_secret_basic` from the secret (`zcs_...`).
    pub fn client_secret_basic(secret: impl Into<SecretString>) -> Self {
        ClientAuth::ClientSecretBasic(secret.into())
    }

    /// The registered method name, as it appears on the wire.
    pub fn method(&self) -> &'static str {
        match self {
            ClientAuth::None => "none",
            ClientAuth::ClientSecretBasic(_) => "client_secret_basic",
            ClientAuth::PrivateKeyJwt(_) => "private_key_jwt",
            ClientAuth::TlsClientAuth(_) => "tls_client_auth",
        }
    }
}

impl fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientAuth::None => f.write_str("ClientAuth::None"),
            ClientAuth::ClientSecretBasic(_) => {
                f.write_str("ClientAuth::ClientSecretBasic([REDACTED])")
            }
            ClientAuth::PrivateKeyJwt(key) => f
                .debug_tuple("ClientAuth::PrivateKeyJwt")
                .field(key)
                .finish(),
            ClientAuth::TlsClientAuth(_) => f.write_str("ClientAuth::TlsClientAuth([REDACTED])"),
        }
    }
}

/// An ES256 signing key on P-256 for `private_key_jwt`, with the optional
/// `kid` the assertion header advertises when your registered JWKS names one.
///
/// The key material is zeroized on drop and never printed.
pub struct PrivateKey {
    pub(crate) key: SigningKey,
    pub(crate) kid: Option<String>,
}

impl PrivateKey {
    /// Parses a PEM private key: PKCS #8 (`BEGIN PRIVATE KEY`) or SEC1
    /// (`BEGIN EC PRIVATE KEY`). The key must be on P-256; anything else is
    /// an [`Error::Configuration`].
    pub fn from_pem(pem: &str) -> Result<Self> {
        let key = if pem.contains("BEGIN EC PRIVATE KEY") {
            p256::SecretKey::from_sec1_pem(pem)
                .map(SigningKey::from)
                .map_err(|e| {
                    Error::configuration_with(
                        "the EC private key did not parse as a P-256 SEC1 key",
                        e.to_string(),
                    )
                })?
        } else {
            SigningKey::from_pkcs8_pem(pem).map_err(|e| {
                Error::configuration_with(
                    "the private key did not parse as a P-256 PKCS #8 key",
                    e.to_string(),
                )
            })?
        };
        Ok(PrivateKey { key, kid: None })
    }

    /// Parses a DER-encoded PKCS #8 P-256 private key.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let key = SigningKey::from_pkcs8_der(der).map_err(|e| {
            Error::configuration_with(
                "the private key did not parse as a P-256 PKCS #8 key",
                e.to_string(),
            )
        })?;
        Ok(PrivateKey { key, kid: None })
    }

    /// Sets the `kid` header of every assertion.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// The `kid` the assertions advertise, if any.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("alg", &"ES256")
            .field("kid", &self.kid)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// A TLS client certificate and its private key for `tls_client_auth`.
pub struct TlsIdentity {
    pub(crate) identity: reqwest::Identity,
}

impl TlsIdentity {
    /// Builds the identity from a PEM certificate chain and a PEM private key
    /// (PKCS #8, PKCS #1 or SEC1). The combined buffer is zeroized after use.
    pub fn from_pem(certificate_chain: &[u8], private_key: &SecretString) -> Result<Self> {
        let mut buffer =
            Vec::with_capacity(certificate_chain.len() + private_key.expose_secret().len() + 1);
        buffer.extend_from_slice(certificate_chain);
        buffer.push(b'\n');
        buffer.extend_from_slice(private_key.expose_secret().as_bytes());
        let identity = reqwest::Identity::from_pem(&buffer);
        buffer.zeroize();
        let identity = identity.map_err(|e| {
            Error::configuration_with("the TLS client certificate or key did not parse", e)
        })?;
        Ok(TlsIdentity { identity })
    }
}

impl fmt::Debug for TlsIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TlsIdentity([REDACTED])")
    }
}
