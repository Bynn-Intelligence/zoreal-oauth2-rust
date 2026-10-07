//! Compact JWS handling: ES256 only, parsed and checked by hand.
//!
//! The grammar this crate needs is small: a three-part compact JWS whose
//! header says `ES256`, a 64-byte `r || s` signature, and an EC P-256 JWKS.
//! Handling it directly keeps the algorithm choice out of any library's hands:
//! the header is read only to refuse anything that is not ES256 and to pick
//! the key, and the payload is not parsed until the signature has verified.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::Deserialize;
use serde_json::json;

use crate::error::{Error, Result, sanitize};

/// An ID token is a few hundred bytes. Anything far larger is refused before
/// any decoding work is spent on it.
pub(crate) const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// A provider JWKS holds a handful of keys; more than this is not a JWKS this
/// crate needs to understand.
const MAX_JWKS_KEYS: usize = 32;

#[derive(Deserialize)]
struct Header {
    alg: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    crit: Option<serde_json::Value>,
}

/// A compact JWS split and decoded, signature not yet checked.
pub(crate) struct Jws<'a> {
    pub(crate) kid: Option<String>,
    signing_input: &'a str,
    payload_b64: &'a str,
    signature: Signature,
}

impl<'a> Jws<'a> {
    pub(crate) fn parse(token: &'a str) -> Result<Self> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(Error::verification("the ID token is too large"));
        }
        let mut parts = token.split('.');
        let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::verification("the ID token is not a compact JWS"));
        };
        let signing_input = &token[..header_b64.len() + 1 + payload_b64.len()];

        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|e| Error::verification_with("the ID token header is not base64url", e))?;
        let header: Header = serde_json::from_slice(&header_bytes)
            .map_err(|e| Error::verification_with("the ID token header is not a JSON object", e))?;

        // ES256 and nothing else, compared exactly. There is no fallback: the
        // provider signs with nothing else, and accepting a second algorithm
        // (or none) is how algorithm confusion starts.
        match header.alg.as_deref() {
            Some("ES256") => {}
            Some(other) => {
                return Err(Error::verification(format!(
                    "the ID token is signed with {:?}; only ES256 is accepted",
                    sanitize(other)
                )));
            }
            None => {
                return Err(Error::verification(
                    "the ID token header names no algorithm",
                ));
            }
        }
        if header.crit.is_some() {
            return Err(Error::verification(
                "the ID token header carries critical extensions this client does not understand",
            ));
        }

        let signature_bytes = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|e| Error::verification_with("the ID token signature is not base64url", e))?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
            Error::verification("the ID token signature is not a 64-byte ES256 signature")
        })?;

        Ok(Jws {
            kid: header.kid,
            signing_input,
            payload_b64,
            signature,
        })
    }

    pub(crate) fn verifies_with(&self, key: &VerifyingKey) -> bool {
        key.verify(self.signing_input.as_bytes(), &self.signature)
            .is_ok()
    }

    /// The payload bytes. Call only after the signature verified.
    pub(crate) fn payload(&self) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(self.payload_b64)
            .map_err(|e| Error::verification_with("the ID token payload is not base64url", e))
    }
}

/// One verification key from the provider JWKS.
pub(crate) struct Jwk {
    pub(crate) kid: Option<String>,
    pub(crate) key: VerifyingKey,
}

/// Parses a JWKS, keeping the EC P-256 signature keys and skipping every
/// other shape: a provider may advertise keys this crate will never need. A
/// coordinate pair that is not on the curve is skipped, not trusted.
pub(crate) fn parse_jwks(body: &[u8]) -> Result<Vec<Jwk>> {
    #[derive(Deserialize)]
    struct Document {
        keys: Vec<RawKey>,
    }
    #[derive(Deserialize)]
    struct RawKey {
        #[serde(default)]
        kty: Option<String>,
        #[serde(default)]
        crv: Option<String>,
        #[serde(default)]
        alg: Option<String>,
        #[serde(default, rename = "use")]
        key_use: Option<String>,
        #[serde(default)]
        kid: Option<String>,
        #[serde(default)]
        x: Option<String>,
        #[serde(default)]
        y: Option<String>,
    }

    let document: Document = serde_json::from_slice(body)
        .map_err(|e| Error::verification_with("the provider JWKS is not valid JSON", e))?;

    let mut keys = Vec::new();
    for raw in document.keys.into_iter().take(MAX_JWKS_KEYS) {
        if raw.kty.as_deref() != Some("EC") || raw.crv.as_deref() != Some("P-256") {
            continue;
        }
        if raw.alg.as_deref().is_some_and(|alg| alg != "ES256")
            || raw.key_use.as_deref().is_some_and(|u| u != "sig")
        {
            continue;
        }
        let (Some(x), Some(y)) = (raw.x, raw.y) else {
            continue;
        };
        let (Ok(x), Ok(y)) = (URL_SAFE_NO_PAD.decode(x), URL_SAFE_NO_PAD.decode(y)) else {
            continue;
        };
        if x.len() != 32 || y.len() != 32 {
            continue;
        }
        let mut point = [0u8; 65];
        point[0] = 0x04;
        point[1..33].copy_from_slice(&x);
        point[33..].copy_from_slice(&y);
        if let Ok(key) = VerifyingKey::from_sec1_bytes(&point) {
            keys.push(Jwk { kid: raw.kid, key });
        }
    }
    Ok(keys)
}

/// Signs an RFC 7523 client assertion in the shape the provider verifies:
/// `iss` and `sub` are the client_id, `aud` is the token endpoint, `exp` is
/// the provider's 60-second cap, and `jti` is fresh because the provider
/// enforces single use on it.
pub(crate) fn client_assertion(
    key: &SigningKey,
    kid: Option<&str>,
    client_id: &str,
    token_endpoint: &str,
    now: i64,
    lifetime_secs: i64,
) -> String {
    let mut header = json!({ "alg": "ES256", "typ": "JWT" });
    if let Some(kid) = kid {
        header["kid"] = json!(kid);
    }
    let claims = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": token_endpoint,
        "iat": now,
        "exp": now + lifetime_secs,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature: Signature = key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}
