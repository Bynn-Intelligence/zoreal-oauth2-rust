//! One verified login.

use std::fmt;

use secrecy::SecretString;
use tokio::sync::OnceCell;

use crate::acr::Acr;
use crate::claims::{Assurance, IdTokenClaims, Userinfo};
use crate::client::{Client, TokenResponse};
use crate::error::{Error, Result};

/// One verified login, returned by [`Client::authenticate`].
///
/// The ID token claims are already verified when this exists. Userinfo is
/// fetched on first use and kept, because the ID token never carries personal
/// data and not every login needs any.
///
/// Debug output redacts the tokens and lists no personal data.
pub struct Login {
    client: Client,
    claims: IdTokenClaims,
    id_token: String,
    access_token: Option<SecretString>,
    scope: Option<String>,
    userinfo: OnceCell<Userinfo>,
}

impl Login {
    pub(crate) fn new(client: Client, claims: IdTokenClaims, tokens: TokenResponse) -> Self {
        Login {
            client,
            claims,
            id_token: tokens.id_token,
            access_token: tokens.access_token,
            scope: tokens.scope,
            userinfo: OnceCell::new(),
        }
    }

    /// The verified ID token claims.
    pub fn claims(&self) -> &IdTokenClaims {
        &self.claims
    }

    /// The compact ID token the claims came from.
    pub fn id_token(&self) -> &str {
        &self.id_token
    }

    /// The access token from the exchange. It lives ten minutes.
    pub fn access_token(&self) -> Option<&SecretString> {
        self.access_token.as_ref()
    }

    /// The granted scopes, which may be narrower than the requested ones.
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    /// The pairwise subject: stable for your verified domain, meaningless to
    /// anyone else. Key accounts on it. It is derived from your registered
    /// domain, so changing your asset's domain changes every `sub`.
    pub fn sub(&self) -> &str {
        &self.claims.sub
    }

    /// The raw `acr` claim: what happened, never what was requested.
    pub fn acr(&self) -> Option<&str> {
        self.claims.acr.as_deref()
    }

    /// The `acr` claim as a level, or `None` outside the vocabulary.
    pub fn acr_level(&self) -> Option<Acr> {
        self.claims.acr_level()
    }

    /// A fresh face capture backed this login (`acr == zoreal.live`). For
    /// enforcement, pass a floor to [`Client::authenticate`] instead.
    pub fn is_live(&self) -> bool {
        self.acr_level() == Some(Acr::Live)
    }

    /// Whether the login's `acr` is `required` or stronger. An unknown `acr`
    /// satisfies nothing.
    pub fn satisfies_acr(&self, required: Acr) -> bool {
        self.acr_level().is_some_and(|actual| actual >= required)
    }

    /// The authentication methods used (`hwk`, `user`, `face`).
    pub fn amr(&self) -> &[String] {
        &self.claims.amr
    }

    /// The assurance block: uniqueness basis, verification month, chip
    /// liveness, trust tier, key protection.
    pub fn assurance(&self) -> Option<&Assurance> {
        self.claims.assurance.as_ref()
    }

    /// `zoreal.age` scope: `None` when no claim was minted for the threshold,
    /// which differs from `Some(false)`.
    pub fn age_over(&self, threshold: u8) -> Option<bool> {
        self.claims.age_over(threshold)
    }

    /// `zoreal.nationality` scope: ISO 3166-1 alpha-3, read from the chip.
    pub fn nationality(&self) -> Option<&str> {
        self.claims.nationality.as_deref()
    }

    /// Issued at, seconds since the Unix epoch.
    pub fn iat(&self) -> Option<i64> {
        self.claims.iat
    }

    /// Expiry, seconds since the Unix epoch.
    pub fn exp(&self) -> i64 {
        self.claims.exp
    }

    /// When the holder authenticated, seconds since the Unix epoch.
    pub fn auth_time(&self) -> Option<i64> {
        self.claims.auth_time
    }

    /// The Tier B claims from `/userinfo`, fetched once and kept. Empty when
    /// the exchange carried no access token. A response whose `sub` is
    /// missing or differs from the ID token's is refused.
    ///
    /// An [`Error::Userinfo`] is survivable for a returning user matched on
    /// [`Login::sub`], and fatal for a signup that needs the email. A failed
    /// fetch is not cached: the next call tries again, so read the fields
    /// from one successful `userinfo()` rather than retrying per field.
    pub async fn userinfo(&self) -> Result<&Userinfo> {
        self.userinfo
            .get_or_try_init(|| async {
                let Some(token) = &self.access_token else {
                    return Ok(Userinfo::default());
                };
                let info = self.client.userinfo(token).await?;
                // OpenID Connect requires the userinfo `sub` to be present
                // and to equal the ID token's; anything else is a response
                // about someone else, or about no one.
                match info.sub() {
                    Some(sub) if sub == self.claims.sub => Ok(info),
                    Some(_) => Err(Error::userinfo(
                        "the userinfo subject is not the ID token subject",
                        None,
                        None,
                    )),
                    None => Err(Error::userinfo(
                        "the userinfo response names no subject",
                        None,
                        None,
                    )),
                }
            })
            .await
    }

    /// `email` scope, from `/userinfo`.
    pub async fn email(&self) -> Result<Option<&str>> {
        Ok(self.userinfo().await?.email())
    }

    /// `email` scope: true only when the provider says exactly `true`.
    pub async fn email_verified(&self) -> Result<bool> {
        Ok(self.userinfo().await?.email_verified())
    }

    /// `profile.name` scope, from `/userinfo`.
    pub async fn name(&self) -> Result<Option<&str>> {
        Ok(self.userinfo().await?.name())
    }

    /// `profile.name` scope, from `/userinfo`.
    pub async fn given_name(&self) -> Result<Option<&str>> {
        Ok(self.userinfo().await?.given_name())
    }

    /// `profile.name` scope, from `/userinfo`.
    pub async fn family_name(&self) -> Result<Option<&str>> {
        Ok(self.userinfo().await?.family_name())
    }

    /// `profile.birthdate` scope, from `/userinfo`: an ISO 8601 date.
    pub async fn birthdate(&self) -> Result<Option<&str>> {
        Ok(self.userinfo().await?.birthdate())
    }

    /// `profile.document` scope, from `/userinfo`.
    pub async fn document_type(&self) -> Result<Option<&str>> {
        Ok(self.userinfo().await?.document_type())
    }

    /// `profile.document` scope, from `/userinfo`.
    pub async fn document_number(&self) -> Result<Option<&str>> {
        Ok(self.userinfo().await?.document_number())
    }

    /// `profile.document` scope, from `/userinfo`: ISO 3166-1 alpha-3.
    pub async fn issuing_country(&self) -> Result<Option<&str>> {
        Ok(self.userinfo().await?.issuing_country())
    }

    /// `profile.document` scope, from `/userinfo`: an ISO 8601 date.
    pub async fn document_expires_on(&self) -> Result<Option<&str>> {
        Ok(self.userinfo().await?.document_expires_on())
    }

    /// `profile.portrait` scope. Registrable, not served by the provider
    /// yet, so `None` until it is.
    pub async fn portrait(&self) -> Result<Option<&str>> {
        Ok(self.userinfo().await?.portrait())
    }
}

impl fmt::Debug for Login {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Login")
            .field("claims", &self.claims)
            .field("id_token", &"[REDACTED]")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("scope", &self.scope)
            .field("userinfo_fetched", &self.userinfo.initialized())
            .finish_non_exhaustive()
    }
}
