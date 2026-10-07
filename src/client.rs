//! The relying-party client: exchange, verify, userinfo.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::{StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::acr::Acr;
use crate::auth::ClientAuth;
use crate::claims::{IdTokenClaims, Userinfo};
use crate::error::{BoxError, Error, Result, sanitize};
use crate::jwks::{JwksCache, KeySet, Lookup};
use crate::jwt::{self, Jws};
use crate::login::Login;
use crate::{
    ASSERTION_LIFETIME, DEFAULT_CONNECT_TIMEOUT, DEFAULT_ISSUER, DEFAULT_LEEWAY, DEFAULT_TIMEOUT,
    JWKS_TTL,
};

/// Responses are small JSON documents; a cap keeps a misbehaving endpoint
/// from ballooning memory.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// Codes, verifiers and nonces are short strings. A cap keeps an oversized
/// request body from being forwarded to the provider.
const MAX_PARAM_BYTES: usize = 4096;
const MAX_LEEWAY: Duration = Duration::from_secs(120);

/// The relying-party client: one instance per registered ZOREAL client.
///
/// Cheap to clone (it is an `Arc` inside) and safe to share across tasks, so
/// build it once at startup. The JWKS cache and the HTTP connection pool are
/// shared by every clone.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

struct Inner {
    client_id: String,
    issuer: String,
    token_url: Url,
    jwks_url: Url,
    userinfo_url: Url,
    auth: ClientAuth,
    http: reqwest::Client,
    jwks: JwksCache,
    leeway: Duration,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("client_id", &self.inner.client_id)
            .field("issuer", &self.inner.issuer)
            .field("auth", &self.inner.auth)
            .finish_non_exhaustive()
    }
}

/// Builds a [`Client`]. Start from [`Client::builder`].
#[derive(Debug)]
#[must_use]
pub struct ClientBuilder {
    client_id: String,
    issuer: String,
    auth: ClientAuth,
    timeout: Duration,
    connect_timeout: Duration,
    jwks_ttl: Duration,
    leeway: Duration,
}

impl ClientBuilder {
    /// The issuer. Defaults to [`DEFAULT_ISSUER`]; set it only when you were
    /// given a non-production provider. A trailing slash is trimmed, and the
    /// result must equal the `iss` inside the tokens exactly. It must be
    /// `https`, except on a loopback host.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    /// The client authentication your registration names. Defaults to
    /// [`ClientAuth::None`], a public client.
    pub fn auth(mut self, auth: ClientAuth) -> Self {
        self.auth = auth;
        self
    }

    /// Shorthand for `auth(ClientAuth::client_secret_basic(secret))`.
    pub fn client_secret(self, secret: impl Into<SecretString>) -> Self {
        self.auth(ClientAuth::client_secret_basic(secret))
    }

    /// Bounds every request, connection to last byte. Defaults to
    /// [`DEFAULT_TIMEOUT`].
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Bounds establishing a connection (TCP and TLS). Defaults to
    /// [`DEFAULT_CONNECT_TIMEOUT`], and never exceeds [`Self::timeout`]. A
    /// short connect bound fails fast against an unreachable address instead
    /// of holding a login for the whole request timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// How long the fetched JWKS is held. Defaults to [`JWKS_TTL`], the
    /// provider's own cache lifetime. An unknown `kid` refetches early, so a
    /// key rotation never strands a login for the TTL.
    pub fn jwks_ttl(mut self, ttl: Duration) -> Self {
        self.jwks_ttl = ttl;
        self
    }

    /// Clock skew allowed on `exp`, `nbf` and `iat`. Defaults to
    /// [`DEFAULT_LEEWAY`]; at most two minutes, the ID token's whole
    /// lifetime.
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    /// Validates the configuration and builds the client. Every error is an
    /// [`Error::Configuration`].
    pub fn build(self) -> Result<Client> {
        let client_id = self.client_id.trim().to_owned();
        if client_id.is_empty() {
            return Err(Error::configuration("client_id is required"));
        }
        if let ClientAuth::ClientSecretBasic(secret) = &self.auth
            && secret.expose_secret().trim().is_empty()
        {
            return Err(Error::configuration(
                "client_secret_basic needs a non-empty client secret",
            ));
        }
        if self.timeout.is_zero() || self.connect_timeout.is_zero() {
            return Err(Error::configuration(
                "the timeouts must be greater than zero",
            ));
        }
        if self.jwks_ttl.is_zero() {
            return Err(Error::configuration(
                "the JWKS TTL must be greater than zero",
            ));
        }
        if self.leeway > MAX_LEEWAY {
            return Err(Error::configuration(
                "the leeway may be at most 120 seconds",
            ));
        }

        let issuer = self.issuer.trim().trim_end_matches('/').to_owned();
        let parsed = Url::parse(&issuer)
            .map_err(|e| Error::configuration_with("the issuer is not a URL", e))?;
        let loopback = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        match parsed.scheme() {
            "https" => {}
            "http" if loopback => {}
            _ => return Err(Error::configuration("the issuer must be an https URL")),
        }
        if parsed.query().is_some()
            || parsed.fragment().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(Error::configuration(
                "the issuer must not carry credentials, a query or a fragment",
            ));
        }
        let endpoint = |path: &str| {
            Url::parse(&format!("{issuer}/{path}"))
                .map_err(|e| Error::configuration_with("the issuer does not form endpoint URLs", e))
        };
        let token_url = endpoint("token")?;
        let jwks_url = endpoint("jwks")?;
        let userinfo_url = endpoint("userinfo")?;

        let mut http = reqwest::Client::builder()
            .timeout(self.timeout)
            .connect_timeout(self.connect_timeout.min(self.timeout))
            // Logins come in bursts: keep a bounded pool of warm connections
            // to the one provider host, and drop idle ones before a typical
            // load balancer's 60-second idle cut-off closes them under a
            // request.
            .pool_max_idle_per_host(32)
            .pool_idle_timeout(Duration::from_secs(50))
            // Nothing in this flow redirects. Following one would carry the
            // client authentication somewhere it was not meant for.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("zoreal-oauth2-rust/", env!("CARGO_PKG_VERSION")));
        if let ClientAuth::TlsClientAuth(identity) = &self.auth {
            http = http.identity(identity.identity.clone());
        }
        let http = http
            .build()
            .map_err(|e| Error::configuration_with("the HTTP client could not be built", e))?;

        Ok(Client {
            inner: Arc::new(Inner {
                client_id,
                issuer,
                token_url,
                jwks_url,
                userinfo_url,
                auth: self.auth,
                http,
                jwks: JwksCache::new(self.jwks_ttl),
                leeway: self.leeway,
            }),
        })
    }
}

/// The provider's answer to a successful code exchange.
///
/// Debug output redacts both tokens.
#[derive(Clone)]
#[non_exhaustive]
pub struct TokenResponse {
    /// The compact ID token. Verify it with [`Client::verify_id_token`]
    /// before trusting anything in it.
    pub id_token: String,
    /// The access token for `/userinfo`. It lives ten minutes: read
    /// `/userinfo` while handling the login, do not store it.
    pub access_token: Option<SecretString>,
    /// `Bearer`.
    pub token_type: Option<String>,
    /// The access token lifetime in seconds.
    pub expires_in: Option<u64>,
    /// The granted scopes, which may be narrower than the requested ones.
    pub scope: Option<String>,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("id_token", &"[REDACTED]")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

#[derive(Deserialize)]
struct RawTokenResponse {
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Deserialize, Default)]
struct Refusal {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

enum ReadError {
    Transport(reqwest::Error),
    TooLarge,
}

impl ReadError {
    fn into_box(self) -> BoxError {
        match self {
            ReadError::Transport(e) => Box::new(e.without_url()),
            ReadError::TooLarge => "the response exceeded the size limit".into(),
        }
    }
}

async fn read_capped(mut response: reqwest::Response) -> std::result::Result<Vec<u8>, ReadError> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
    {
        return Err(ReadError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(ReadError::Transport)? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(ReadError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn blank(value: &str) -> bool {
    value.trim().is_empty()
}

impl Client {
    /// Starts a builder for the client whose `client_id` (the asset token,
    /// `ast_...`) is given.
    pub fn builder(client_id: impl Into<String>) -> ClientBuilder {
        ClientBuilder {
            client_id: client_id.into(),
            issuer: DEFAULT_ISSUER.to_owned(),
            auth: ClientAuth::None,
            timeout: DEFAULT_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            jwks_ttl: JWKS_TTL,
            leeway: DEFAULT_LEEWAY,
        }
    }

    /// The configured `client_id`.
    pub fn client_id(&self) -> &str {
        &self.inner.client_id
    }

    /// The configured issuer, without a trailing slash.
    pub fn issuer(&self) -> &str {
        &self.inner.issuer
    }

    /// The whole login, in order: exchange the code with the PKCE verifier
    /// the browser SDK handed over, verify the ID token against the JWKS,
    /// require its nonce to equal `nonce`, and, when `acr_floor` is given,
    /// refuse a token whose assurance is below it.
    ///
    /// Personal data is not fetched here, because the ID token never carries
    /// it and not every caller wants it: [`Login::userinfo`] fetches it on
    /// first use.
    ///
    /// Requesting an assurance on the wire (the browser SDK's `acr_values`)
    /// is advisory; the signed `acr` claim is the proof, and `acr_floor` is
    /// where a relying party that asked for a liveness check verifies it
    /// happened.
    pub async fn authenticate(
        &self,
        code: &str,
        code_verifier: &str,
        nonce: &str,
        acr_floor: Option<Acr>,
    ) -> Result<Login> {
        // Checked before the exchange, so a request that can never verify
        // does not spend a network round trip.
        check_nonce_param(nonce)?;
        let tokens = self.exchange(code, code_verifier).await?;
        let claims = self
            .verify_id_token(&tokens.id_token, nonce, acr_floor)
            .await?;
        Ok(Login::new(self.clone(), claims, tokens))
    }

    /// `POST {issuer}/token`. The verifier is mandatory: PKCE is required for
    /// every ZOREAL client. The form always carries `client_id`, and client
    /// authentication rides along per the configured method. Every failure is
    /// an [`Error::Exchange`].
    pub async fn exchange(&self, code: &str, code_verifier: &str) -> Result<TokenResponse> {
        for (name, value) in [("code", code), ("code_verifier", code_verifier)] {
            if blank(value) {
                return Err(Error::exchange(
                    "invalid_request",
                    format!("{name} is required"),
                    None,
                    None,
                ));
            }
            if value.len() > MAX_PARAM_BYTES {
                return Err(Error::exchange(
                    "invalid_request",
                    format!("{name} is too long"),
                    None,
                    None,
                ));
            }
        }

        let inner = &*self.inner;
        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", "authorization_code".to_owned()),
            ("code", code.to_owned()),
            ("code_verifier", code_verifier.to_owned()),
            ("client_id", inner.client_id.clone()),
        ];
        if let ClientAuth::PrivateKeyJwt(key) = &inner.auth {
            let assertion = jwt::client_assertion(
                &key.key,
                key.kid.as_deref(),
                &inner.client_id,
                inner.token_url.as_str(),
                now_secs(),
                ASSERTION_LIFETIME.as_secs() as i64,
            );
            form.push((
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_owned(),
            ));
            form.push(("client_assertion", assertion));
        }

        let mut request = inner
            .http
            .post(inner.token_url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form);
        if let ClientAuth::ClientSecretBasic(secret) = &inner.auth {
            request = request.basic_auth(&inner.client_id, Some(secret.expose_secret()));
        }

        let response = request.send().await.map_err(|e| {
            Error::exchange(
                "server_error",
                "the token request did not complete",
                None,
                Some(Box::new(e.without_url())),
            )
        })?;
        let status = response.status();
        let body = read_capped(response).await.map_err(|e| {
            Error::exchange(
                "server_error",
                "the token response could not be read",
                Some(status.as_u16()),
                Some(e.into_box()),
            )
        })?;

        if !status.is_success() {
            let refusal: Refusal = serde_json::from_slice(&body).unwrap_or_default();
            let oauth_error = refusal
                .error
                .filter(|e| !blank(e))
                .map(|e| sanitize(&e))
                .unwrap_or_else(|| "server_error".to_owned());
            let description = refusal
                .error_description
                .filter(|d| !blank(d))
                .map(|d| sanitize(&d))
                .unwrap_or_else(|| format!("the provider answered {}", status.as_u16()));
            return Err(Error::exchange(
                oauth_error,
                description,
                Some(status.as_u16()),
                None,
            ));
        }

        let raw: RawTokenResponse = serde_json::from_slice(&body).map_err(|e| {
            Error::exchange(
                "server_error",
                // Not the serde error itself: it can quote a token value.
                format!(
                    "the token response was not valid JSON ({})",
                    json_position(&e)
                ),
                Some(status.as_u16()),
                None,
            )
        })?;
        let id_token = raw.id_token.filter(|t| !blank(t)).ok_or_else(|| {
            Error::exchange(
                "server_error",
                "no id_token in the token response",
                Some(status.as_u16()),
                None,
            )
        })?;
        Ok(TokenResponse {
            id_token,
            access_token: raw
                .access_token
                .filter(|t| !blank(t))
                .map(SecretString::from),
            token_type: raw.token_type,
            expires_in: raw.expires_in,
            scope: raw.scope,
        })
    }

    /// Verifies a compact ID token: an ES256 signature from a key in
    /// `{issuer}/jwks`, `iss` equal to the issuer exactly, `aud` containing
    /// the `client_id`, `exp` (and `nbf`, `iat` when present) within the
    /// leeway, a `nonce` equal to `nonce`, and, when `acr_floor` is given,
    /// an `acr` at or above it. Returns the claims; every failure is an
    /// [`Error::Verification`].
    ///
    /// There is no fallback algorithm: a token whose header says anything
    /// but `ES256`, `none` included, is refused before any key is consulted.
    pub async fn verify_id_token(
        &self,
        id_token: &str,
        nonce: &str,
        acr_floor: Option<Acr>,
    ) -> Result<IdTokenClaims> {
        check_nonce_param(nonce)?;
        if blank(id_token) {
            return Err(Error::verification("no ID token was given"));
        }
        let jws = Jws::parse(id_token.trim())?;

        let keys = self.keys_for(jws.kid.as_deref()).await?;
        if !keys
            .candidates(jws.kid.as_deref())
            .any(|key| jws.verifies_with(key))
        {
            return Err(Error::verification(
                "the ID token signature does not verify",
            ));
        }

        let payload = jws.payload()?;
        let claims: IdTokenClaims = serde_json::from_slice(&payload)
            // Not the serde error itself: it can quote a claim value.
            .map_err(|e| {
                Error::verification(format!(
                    "the ID token claims are malformed ({})",
                    json_position(&e)
                ))
            })?;
        self.check_claims(&claims, nonce, acr_floor)?;
        Ok(claims)
    }

    fn check_claims(
        &self,
        claims: &IdTokenClaims,
        nonce: &str,
        acr_floor: Option<Acr>,
    ) -> Result<()> {
        let inner = &*self.inner;
        // Compared exactly: no normalisation, no trailing-slash tolerance.
        if claims.iss != inner.issuer {
            return Err(Error::verification(
                "the ID token issuer is not the configured issuer",
            ));
        }
        if !claims.aud.contains(&inner.client_id) {
            return Err(Error::verification(
                "the ID token audience is not this client",
            ));
        }
        if claims
            .azp
            .as_deref()
            .is_some_and(|azp| azp != inner.client_id)
        {
            return Err(Error::verification(
                "the ID token's authorized party is not this client",
            ));
        }
        if claims.aud.len() > 1 && claims.azp.as_deref() != Some(inner.client_id.as_str()) {
            return Err(Error::verification(
                "the ID token has several audiences and this client is not its authorized party",
            ));
        }
        if claims.sub.trim().is_empty() {
            return Err(Error::verification("the ID token has no subject"));
        }

        let now = now_secs();
        let leeway = inner.leeway.as_secs() as i64;
        if now > claims.exp.saturating_add(leeway) {
            return Err(Error::verification("the ID token has expired"));
        }
        if claims
            .nbf
            .is_some_and(|nbf| now.saturating_add(leeway) < nbf)
        {
            return Err(Error::verification("the ID token is not valid yet"));
        }
        if claims
            .iat
            .is_some_and(|iat| iat > now.saturating_add(leeway))
        {
            return Err(Error::verification("the ID token was issued in the future"));
        }

        if claims.nonce.as_deref() != Some(nonce) {
            return Err(Error::verification(
                "the ID token nonce is not the one this login started with",
            ));
        }

        if let Some(floor) = acr_floor
            && !claims.acr_level().is_some_and(|actual| actual >= floor)
        {
            return Err(Error::verification(format!(
                "the ID token says acr {:?}, below the required {floor}",
                claims.acr.as_deref().map(sanitize)
            )));
        }
        Ok(())
    }

    /// `GET {issuer}/userinfo` with the Bearer access token from the exchange.
    /// This is the only place personal claims (email, `profile.*`) are
    /// served, and the access token lives ten minutes, so call it while
    /// handling the login. Every failure is an [`Error::Userinfo`].
    pub async fn userinfo(&self, access_token: &SecretString) -> Result<Userinfo> {
        let token = access_token.expose_secret();
        if blank(token) {
            return Err(Error::userinfo("an access token is required", None, None));
        }
        let inner = &*self.inner;
        let response = inner
            .http
            .get(inner.userinfo_url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| {
                Error::userinfo(
                    "the userinfo request did not complete",
                    None,
                    Some(Box::new(e.without_url())),
                )
            })?;
        let status = response.status();
        let body = read_capped(response).await.map_err(|e| {
            Error::userinfo(
                "the userinfo response could not be read",
                Some(status.as_u16()),
                Some(e.into_box()),
            )
        })?;

        if !status.is_success() {
            let refusal: Refusal = serde_json::from_slice(&body).unwrap_or_default();
            let description = refusal
                .error_description
                .filter(|d| !blank(d))
                .map(|d| sanitize(&d))
                .unwrap_or_else(|| format!("userinfo answered {}", status.as_u16()));
            return Err(Error::userinfo(description, Some(status.as_u16()), None));
        }

        let claims: Map<String, Value> = serde_json::from_slice(&body).map_err(|e| {
            // serde_json errors can quote the offending value, which here is
            // personal data: keep only the category and position.
            Error::userinfo(
                format!(
                    "the userinfo response was not a JSON object ({})",
                    json_position(&e)
                ),
                Some(status.as_u16()),
                None,
            )
        })?;
        Ok(Userinfo::new(claims))
    }

    /// The key set to verify a token with this `kid` against. Serves the
    /// cache while it is fresh and refreshes it ahead of expiry; on an
    /// unknown `kid`, refetches once (bounded by
    /// [`crate::jwks::FORCED_REFETCH_INTERVAL`]) so a key rotation is picked
    /// up without waiting for the TTL.
    async fn keys_for(&self, kid: Option<&str>) -> Result<Arc<KeySet>> {
        let cache = &self.inner.jwks;
        let set = match cache.lookup() {
            Lookup::Fresh(set) => set,
            Lookup::RefreshAhead(set) => {
                // One caller refreshes as part of its own request; the others
                // keep using the current set, which is still within its TTL.
                // A failed refresh-ahead is remembered and otherwise ignored.
                match cache.fetch_lock.try_lock() {
                    Ok(_guard)
                        if cache.within_soft_ttl().is_none()
                            && cache.recent_failure().is_none() =>
                    {
                        match self.download_jwks().await {
                            Ok(keys) => cache.store(keys),
                            Err(err) => {
                                cache.record_failure(&verification_reason(&err));
                                set
                            }
                        }
                    }
                    _ => set,
                }
            }
            Lookup::Expired => self.fetch_jwks(false).await?,
        };
        if set.has(kid) {
            return Ok(set);
        }
        let set = self.fetch_jwks(true).await?;
        if set.has(kid) {
            return Ok(set);
        }
        Err(Error::verification(
            "no key in the provider JWKS matches the ID token",
        ))
    }

    /// Fetches `{issuer}/jwks`, one fetch at a time. A caller that waited for
    /// another's attempt takes that attempt's outcome instead of fetching
    /// again; a recent failure is not retried until
    /// [`crate::jwks::FAILURE_BACKOFF`] has passed; and while refetching
    /// fails, a set no older than [`crate::jwks::MAX_STALE`] past its TTL is
    /// still served.
    async fn fetch_jwks(&self, forced: bool) -> Result<Arc<KeySet>> {
        let cache = &self.inner.jwks;
        let failed = |reason: &str| {
            cache
                .servable()
                .ok_or_else(|| Error::verification(reason.to_owned()))
        };

        let generation = cache.generation();
        let _guard = cache.fetch_lock.lock().await;

        if cache.generation() != generation {
            if let Some(set) = cache.within_ttl() {
                return Ok(set);
            }
            if let Some(reason) = cache.last_failure() {
                return failed(&reason);
            }
        }
        if !forced && let Some(set) = cache.within_ttl() {
            return Ok(set);
        }
        if let Some(reason) = cache.recent_failure() {
            return failed(&reason);
        }
        if forced && !cache.take_forced_refetch() {
            return failed("no key in the provider JWKS matches the ID token");
        }

        match self.download_jwks().await {
            Ok(keys) => Ok(cache.store(keys)),
            Err(err) => {
                cache.record_failure(&verification_reason(&err));
                cache.servable().ok_or(err)
            }
        }
    }

    async fn download_jwks(&self) -> Result<KeySet> {
        let inner = &*self.inner;
        let response = inner
            .http
            .get(inner.jwks_url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| {
                Error::verification_with("could not fetch the provider JWKS", e.without_url())
            })?;
        let status = response.status();
        if status != StatusCode::OK {
            return Err(Error::verification(format!(
                "could not fetch the provider JWKS ({})",
                status.as_u16()
            )));
        }
        let body = read_capped(response).await.map_err(|e| {
            Error::verification_with("could not read the provider JWKS", e.into_box())
        })?;
        Ok(KeySet::new(jwt::parse_jwks(&body)?))
    }
}

/// A serde_json error's category and position, without the value it quotes.
fn json_position(err: &serde_json::Error) -> String {
    format!(
        "{:?} error at line {}, column {}",
        err.classify(),
        err.line(),
        err.column()
    )
}

fn verification_reason(err: &Error) -> String {
    match err {
        Error::Verification { reason, .. } => reason.clone(),
        other => other.to_string(),
    }
}

fn check_nonce_param(nonce: &str) -> Result<()> {
    // The nonce is mandatory: without it the backend cannot tell a
    // substituted ID token from the one minted for this login.
    if blank(nonce) {
        return Err(Error::verification(
            "a nonce is required: pass the nonce the browser SDK generated for this login",
        ));
    }
    if nonce.len() > MAX_PARAM_BYTES {
        return Err(Error::verification("the nonce is too long"));
    }
    Ok(())
}
