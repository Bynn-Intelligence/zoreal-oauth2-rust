//! The verified ID token claims, the assurance block and the userinfo claims.

use std::fmt;

use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use crate::acr::Acr;

/// The claims of a verified ID token. The ID token never carries personal
/// data: email, names, birthdate and document fields come only from
/// `/userinfo` (see [`Userinfo`]).
///
/// A claim the provider did not mint is `None`, never an empty value: the
/// provider omits what the underlying document did not carry.
#[derive(Clone, Deserialize)]
#[non_exhaustive]
pub struct IdTokenClaims {
    /// The issuer, already checked to equal the configured one exactly.
    pub iss: String,
    /// The pairwise subject: stable for your verified domain, meaningless to
    /// anyone else. Key accounts on it.
    pub sub: String,
    /// The audience, already checked to contain your `client_id`.
    #[serde(deserialize_with = "one_or_many")]
    pub aud: Vec<String>,
    /// Expiry, seconds since the Unix epoch.
    pub exp: i64,
    /// Issued at, seconds since the Unix epoch. Required in an ID token.
    pub iat: i64,
    /// When the holder authenticated, seconds since the Unix epoch.
    #[serde(default)]
    pub auth_time: Option<i64>,
    /// Not before, seconds since the Unix epoch, when the provider sets it.
    #[serde(default)]
    pub nbf: Option<i64>,
    /// The nonce, already checked to equal the one this login started with.
    #[serde(default)]
    pub nonce: Option<String>,
    /// The authorized party, when the provider sets it.
    #[serde(default)]
    pub azp: Option<String>,
    /// The raw `acr` claim. [`IdTokenClaims::acr_level`] reads it as an
    /// [`Acr`].
    #[serde(default)]
    pub acr: Option<String>,
    /// The authentication methods used: `hwk` a hardware key, `user` a local
    /// unlock gesture, `face` a face capture.
    #[serde(default)]
    pub amr: Vec<String>,
    /// The `zoreal` assurance block: how the identity behind this login was
    /// verified at enrolment.
    #[serde(default, rename = "zoreal")]
    pub assurance: Option<Assurance>,
    /// `zoreal.nationality` scope: ISO 3166-1 alpha-3, read from the chip.
    #[serde(default)]
    pub nationality: Option<String>,
    /// Every other claim, such as the `age_over_*` booleans.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl IdTokenClaims {
    /// The `acr` claim as a level, or `None` when it is absent or outside the
    /// vocabulary.
    pub fn acr_level(&self) -> Option<Acr> {
        self.acr.as_deref().and_then(Acr::from_claim)
    }

    /// `zoreal.age` scope: the `age_over_<threshold>` boolean. `None` means
    /// no claim was minted (the threshold is not registered on your asset),
    /// which is a different fact from `Some(false)`.
    pub fn age_over(&self, threshold: u8) -> Option<bool> {
        self.extra
            .get(&format!("age_over_{threshold}"))
            .and_then(Value::as_bool)
    }
}

// The nonce and the nationality are kept out of Debug output: the nonce
// travels from the browser to your backend and should go nowhere else, logs
// included, and the nationality is personal data.
impl fmt::Debug for IdTokenClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdTokenClaims")
            .field("iss", &self.iss)
            .field("sub", &self.sub)
            .field("aud", &self.aud)
            .field("exp", &self.exp)
            .field("iat", &self.iat)
            .field("auth_time", &self.auth_time)
            .field("acr", &self.acr)
            .field("amr", &self.amr)
            .field("assurance", &self.assurance)
            .field(
                "nationality",
                &self.nationality.as_ref().map(|_| "[REDACTED]"),
            )
            .field("extra", &self.extra.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

fn one_or_many<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(one) => vec![one],
        OneOrMany::Many(many) => many,
    })
}

/// The ID token's `zoreal` claim: the strength of the identity behind the
/// login, as distinct from `acr`, which grades the login event itself.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct Assurance {
    /// The anchor the holder is deduplicated on. Gate on
    /// [`Uniqueness::PersonalNumber`] if you need one account per human.
    #[serde(default)]
    pub uniqueness: Option<Uniqueness>,
    /// The month the underlying document was verified, `YYYY-MM`. A month,
    /// on purpose: a day-precision date is a cross-site correlator.
    #[serde(default)]
    pub verified_on: Option<String>,
    /// Whether the document chip's active-authentication challenge was proven
    /// (a genuine chip, not a clone).
    #[serde(default)]
    pub chip_liveness_proven: Option<bool>,
    /// `high` when chip liveness was proven, else `standard`.
    #[serde(default)]
    pub trust_tier: Option<TrustTier>,
    /// How the holder's device key is protected.
    #[serde(default)]
    pub key_protection: Option<KeyProtection>,
}

/// The `uniqueness` value of the assurance block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Uniqueness {
    /// A national personal number read from the chip: one human, whichever
    /// document they present.
    PersonalNumber,
    /// The document itself: a person holding two documents counts as two.
    Document,
    /// `none`: no reliable anchor.
    #[serde(rename = "none")]
    NoAnchor,
    /// A value this version of the crate does not know.
    #[serde(other)]
    Unknown,
}

/// The `trust_tier` value of the assurance block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TrustTier {
    /// Chip liveness was proven.
    High,
    /// Chip liveness was not proven.
    Standard,
    /// A value this version of the crate does not know.
    #[serde(other)]
    Unknown,
}

/// The `key_protection` value of the assurance block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum KeyProtection {
    /// Apple Secure Enclave.
    SecureEnclave,
    /// Android StrongBox.
    Strongbox,
    /// A trusted execution environment.
    Tee,
    /// No hardware attestation.
    Software,
    /// A value this version of the crate does not know.
    #[serde(other)]
    Unknown,
}

/// The claims `/userinfo` returned: the personal data your client was granted
/// (Tier B scopes). Every accessor returns `None` for a claim that was not
/// granted or that the holder's document does not carry.
///
/// Debug output lists the claim names only, never their values.
#[derive(Clone, Default)]
pub struct Userinfo {
    claims: Map<String, Value>,
}

impl Userinfo {
    pub(crate) fn new(claims: Map<String, Value>) -> Self {
        Userinfo { claims }
    }

    fn str_claim(&self, name: &str) -> Option<&str> {
        self.claims.get(name).and_then(Value::as_str)
    }

    /// Any claim by name.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.claims.get(name)
    }

    /// Every claim, as returned.
    pub fn claims(&self) -> &Map<String, Value> {
        &self.claims
    }

    /// The subject the userinfo response names.
    pub fn sub(&self) -> Option<&str> {
        self.str_claim("sub")
    }

    /// `email` scope.
    pub fn email(&self) -> Option<&str> {
        self.str_claim("email")
    }

    /// `email` scope: true only when the provider says exactly `true`.
    pub fn email_verified(&self) -> bool {
        self.claims.get("email_verified") == Some(&Value::Bool(true))
    }

    /// `profile.name` scope.
    pub fn name(&self) -> Option<&str> {
        self.str_claim("name")
    }

    /// `profile.name` scope.
    pub fn given_name(&self) -> Option<&str> {
        self.str_claim("given_name")
    }

    /// `profile.name` scope.
    pub fn family_name(&self) -> Option<&str> {
        self.str_claim("family_name")
    }

    /// `profile.birthdate` scope: an ISO 8601 date.
    pub fn birthdate(&self) -> Option<&str> {
        self.str_claim("birthdate")
    }

    /// `profile.document` scope: the document as presented, not an assertion
    /// about the person beyond it.
    pub fn document_type(&self) -> Option<&str> {
        self.str_claim("document_type")
    }

    /// `profile.document` scope.
    pub fn document_number(&self) -> Option<&str> {
        self.str_claim("document_number")
    }

    /// `profile.document` scope: ISO 3166-1 alpha-3.
    pub fn issuing_country(&self) -> Option<&str> {
        self.str_claim("issuing_country")
    }

    /// `profile.document` scope: an ISO 8601 date. Absent for documents that
    /// do not expire.
    pub fn document_expires_on(&self) -> Option<&str> {
        self.str_claim("document_expires_on")
    }

    /// `profile.portrait` scope. The scope is registrable but the provider
    /// does not serve the claim yet, so this is `None` until it does.
    pub fn portrait(&self) -> Option<&str> {
        self.str_claim("portrait")
    }
}

impl fmt::Debug for Userinfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Userinfo")
            .field("claims", &self.claims.keys().collect::<Vec<_>>())
            .finish()
    }
}
