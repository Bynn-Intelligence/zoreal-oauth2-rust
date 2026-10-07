//! The one error type every fallible call returns.

/// A boxed underlying error, kept as the [`std::error::Error::source`] of an
/// [`Error`] so the transport or parse failure behind it stays inspectable.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The result type of this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Everything that can go wrong, in four kinds.
///
/// - [`Error::Configuration`]: a mistake in YOUR code or configuration, not in
///   a token: a client built without something it cannot work without, a key
///   that does not parse, an assurance level outside the vocabulary.
/// - [`Error::Exchange`]: the code exchange at `/token` failed. The provider's
///   own error code and description are carried, sanitized (control characters removed, at most 300 characters).
/// - [`Error::Verification`]: the ID token did not verify (signature,
///   algorithm, `iss`, `aud`, `exp`, `nonce`, or the assurance floor). A JWKS
///   that could not be fetched lands here too, because a token that cannot be
///   checked is a token that did not verify.
/// - [`Error::Userinfo`]: the `/userinfo` read failed.
///
/// No token, secret, key or code value ever appears in an error message.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The client was configured wrong, or a required assurance level is
    /// outside the vocabulary. A bug in the caller, never a bad token.
    #[error("zoreal-oauth2: configuration error: {message}")]
    #[non_exhaustive]
    Configuration {
        /// What is wrong.
        message: String,
        /// The underlying parse error, when there is one.
        #[source]
        source: Option<BoxError>,
    },

    /// The code exchange at the token endpoint failed.
    #[error("zoreal-oauth2: the token exchange failed: {oauth_error}: {description}")]
    #[non_exhaustive]
    Exchange {
        /// The RFC 6749 error code the provider answered (`invalid_grant`,
        /// `invalid_request`, ...), or `server_error` when it gave none.
        oauth_error: String,
        /// The provider's own reason, sanitized, or this crate's when the
        /// request never completed.
        description: String,
        /// The HTTP status, or `None` when no response arrived.
        status: Option<u16>,
        /// The transport or parse error, when there is one.
        #[source]
        source: Option<BoxError>,
    },

    /// The ID token did not verify.
    #[error("zoreal-oauth2: the ID token did not verify: {reason}")]
    #[non_exhaustive]
    Verification {
        /// Which check failed.
        reason: String,
        /// The transport or parse error, when there is one.
        #[source]
        source: Option<BoxError>,
    },

    /// The `/userinfo` read failed. A returning user matched on `sub` can
    /// survive it; a signup that needs the email cannot.
    #[error("zoreal-oauth2: userinfo: {description}")]
    #[non_exhaustive]
    Userinfo {
        /// The provider's `error_description`, sanitized, or this crate's.
        description: String,
        /// The HTTP status, or `None` when no response arrived.
        status: Option<u16>,
        /// The transport or parse error, when there is one.
        #[source]
        source: Option<BoxError>,
    },
}

impl Error {
    pub(crate) fn configuration(message: impl Into<String>) -> Self {
        Error::Configuration {
            message: message.into(),
            source: None,
        }
    }

    pub(crate) fn configuration_with(
        message: impl Into<String>,
        source: impl Into<BoxError>,
    ) -> Self {
        Error::Configuration {
            message: message.into(),
            source: Some(source.into()),
        }
    }

    pub(crate) fn exchange(
        oauth_error: impl Into<String>,
        description: impl Into<String>,
        status: Option<u16>,
        source: Option<BoxError>,
    ) -> Self {
        Error::Exchange {
            oauth_error: oauth_error.into(),
            description: description.into(),
            status,
            source,
        }
    }

    pub(crate) fn verification(reason: impl Into<String>) -> Self {
        Error::Verification {
            reason: reason.into(),
            source: None,
        }
    }

    pub(crate) fn verification_with(
        reason: impl Into<String>,
        source: impl Into<BoxError>,
    ) -> Self {
        Error::Verification {
            reason: reason.into(),
            source: Some(source.into()),
        }
    }

    pub(crate) fn userinfo(
        description: impl Into<String>,
        status: Option<u16>,
        source: Option<BoxError>,
    ) -> Self {
        Error::Userinfo {
            description: description.into(),
            status,
            source,
        }
    }

    /// The provider's OAuth error code, for an [`Error::Exchange`].
    pub fn oauth_error(&self) -> Option<&str> {
        match self {
            Error::Exchange { oauth_error, .. } => Some(oauth_error),
            _ => None,
        }
    }

    /// The HTTP status of the failed call, when a response arrived.
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Exchange { status, .. } | Error::Userinfo { status, .. } => *status,
            _ => None,
        }
    }

    /// True for [`Error::Configuration`].
    pub fn is_configuration(&self) -> bool {
        matches!(self, Error::Configuration { .. })
    }

    /// True for [`Error::Exchange`].
    pub fn is_exchange(&self) -> bool {
        matches!(self, Error::Exchange { .. })
    }

    /// True for [`Error::Verification`].
    pub fn is_verification(&self) -> bool {
        matches!(self, Error::Verification { .. })
    }

    /// True for [`Error::Userinfo`].
    pub fn is_userinfo(&self) -> bool {
        matches!(self, Error::Userinfo { .. })
    }
}

/// Provider-supplied text is quoted in errors and therefore in logs. Cap it
/// and drop control characters so a misbehaving endpoint cannot flood a log
/// line or forge a new one.
pub(crate) fn sanitize(text: &str) -> String {
    const MAX_CHARS: usize = 300;
    let mut out: String = text
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_CHARS)
        .collect();
    if text.chars().filter(|c| !c.is_control()).count() > MAX_CHARS {
        out.push_str("...");
    }
    out
}
