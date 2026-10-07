//! Shared fixtures: an in-process P-256 key, token minting, and a local mock
//! provider. No test touches the network beyond 127.0.0.1.

#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::Generate as _;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zoreal_oauth2::{Client, ClientAuth};

pub const CLIENT_ID: &str = "ast_testclient";
pub const NONCE: &str = "n-0S6_WzA2Mj";
pub const SECRET: &str = "test-secret-value";

pub struct Key {
    pub signing: SigningKey,
    pub kid: String,
}

impl Key {
    pub fn generate(kid: &str) -> Self {
        Key {
            signing: SigningKey::generate(),
            kid: kid.to_owned(),
        }
    }

    pub fn jwk(&self) -> Value {
        let point = self.signing.verifying_key().to_sec1_point(false);
        let bytes = point.as_bytes();
        json!({
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "kid": self.kid,
            "x": URL_SAFE_NO_PAD.encode(&bytes[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&bytes[33..65]),
        })
    }

    /// Signs `claims` with this key under an arbitrary header.
    pub fn sign_with_header(&self, header: &Value, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature: Signature = self.signing.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    pub fn sign(&self, claims: &Value) -> String {
        self.sign_with_header(
            &json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid }),
            claims,
        )
    }
}

pub fn jwks(keys: &[&Key]) -> Value {
    json!({ "keys": keys.iter().map(|k| k.jwk()).collect::<Vec<_>>() })
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// The claims a real ZOREAL ID token carries, for the given issuer.
pub fn base_claims(issuer: &str) -> Value {
    let now = now();
    json!({
        "iss": issuer,
        "sub": "TC5X-JN7G-YTSE-6E63",
        "aud": CLIENT_ID,
        "exp": now + 120,
        "iat": now,
        "auth_time": now,
        "nonce": NONCE,
        "acr": "zoreal.device",
        "amr": ["hwk", "user"],
        "zoreal": {
            "uniqueness": "personal_number",
            "verified_on": "2026-08",
            "chip_liveness_proven": true,
            "trust_tier": "high",
            "key_protection": "strongbox"
        },
        "age_over_18": true,
        "nationality": "SWE"
    })
}

pub fn with(mut claims: Value, overrides: Value) -> Value {
    for (k, v) in overrides.as_object().unwrap() {
        if v.is_null() {
            claims.as_object_mut().unwrap().remove(k);
        } else {
            claims[k] = v.clone();
        }
    }
    claims
}

pub struct Provider {
    pub server: MockServer,
    pub key: Key,
}

impl Provider {
    /// A mock provider serving discovery and a JWKS with one key. Token and
    /// userinfo responses are mounted per test.
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        let key = Key::generate("key-1");
        let provider = Provider { server, key };
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": provider.issuer(),
                "token_endpoint": format!("{}/token", provider.issuer()),
                "userinfo_endpoint": format!("{}/userinfo", provider.issuer()),
                "jwks_uri": format!("{}/jwks", provider.issuer()),
                "id_token_signing_alg_values_supported": ["ES256"],
            })))
            .mount(&provider.server)
            .await;
        provider
    }

    pub fn issuer(&self) -> String {
        self.server.uri()
    }

    pub async fn serve_jwks(&self, keys: &[&Key]) {
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks(keys)))
            .mount(&self.server)
            .await;
    }

    pub async fn serve_token(&self, id_token: &str) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id_token": id_token,
                "access_token": "access-token-value",
                "token_type": "Bearer",
                "expires_in": 600,
                "scope": "openid email profile.name",
            })))
            .mount(&self.server)
            .await;
    }

    pub fn client(&self) -> Client {
        self.client_with(ClientAuth::client_secret_basic(SECRET))
    }

    pub fn client_with(&self, auth: ClientAuth) -> Client {
        Client::builder(CLIENT_ID)
            .issuer(self.issuer())
            .auth(auth)
            .build()
            .unwrap()
    }

    pub async fn requests_to(&self, p: &str) -> Vec<wiremock::Request> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.url.path() == p)
            .collect()
    }
}
