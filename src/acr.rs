//! The assurance vocabulary of the `acr` claim.

use std::fmt;
use std::str::FromStr;

use crate::error::Error;

/// How strongly a login was authenticated, as the signed `acr` claim states
/// it. Ordered weakest to strongest: `Session < Device < Live`, so a floor of
/// [`Acr::Device`] is satisfied by a [`Acr::Live`] token, never the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Acr {
    /// `zoreal.session`: a silent re-authentication from an existing session,
    /// with no interaction on the phone.
    Session,
    /// `zoreal.device`: the holder approved on their enrolled phone, with a
    /// hardware-backed key released by a local unlock. The default.
    Device,
    /// `zoreal.live`: a device approval plus a fresh face capture for this
    /// login.
    Live,
}

impl Acr {
    /// Every level, weakest first.
    pub const ALL: [Acr; 3] = [Acr::Session, Acr::Device, Acr::Live];

    /// The wire value: `zoreal.session`, `zoreal.device` or `zoreal.live`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Acr::Session => "zoreal.session",
            Acr::Device => "zoreal.device",
            Acr::Live => "zoreal.live",
        }
    }

    /// The level a wire value names, or `None` for anything outside the
    /// vocabulary. An unknown value satisfies no floor.
    pub fn from_claim(value: &str) -> Option<Acr> {
        Acr::ALL.into_iter().find(|level| level.as_str() == value)
    }
}

impl fmt::Display for Acr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parses a configured floor, for example from an environment variable. A
/// value outside the vocabulary is an [`Error::Configuration`]: a typo such
/// as `zoreal.liveness` is a bug in your configuration, and failing every
/// login silently would be worse than saying so.
impl FromStr for Acr {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Acr::from_claim(value).ok_or_else(|| {
            Error::configuration(format!(
                "unknown acr {:?}; supported: zoreal.session, zoreal.device, zoreal.live",
                crate::error::sanitize(value)
            ))
        })
    }
}
