//! The in-process JWKS cache.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use p256::ecdsa::VerifyingKey;

use crate::jwt::Jwk;

/// A forged `kid` must not turn every verification into a JWKS fetch. An
/// unknown kid forces at most one refetch per this interval; a genuine key
/// rotation needs exactly one.
pub(crate) const FORCED_REFETCH_INTERVAL: Duration = Duration::from_secs(10);

pub(crate) struct KeySet {
    keys: Vec<Jwk>,
    fetched_at: Instant,
}

impl KeySet {
    pub(crate) fn new(keys: Vec<Jwk>) -> Self {
        KeySet {
            keys,
            fetched_at: Instant::now(),
        }
    }

    /// The keys to try for a token header: the one whose kid matches, or
    /// every key when the token names no kid.
    pub(crate) fn candidates<'a>(
        &'a self,
        kid: Option<&'a str>,
    ) -> impl Iterator<Item = &'a VerifyingKey> + 'a {
        self.keys
            .iter()
            .filter(move |jwk| kid.is_none() || jwk.kid.as_deref() == kid)
            .map(|jwk| &jwk.key)
    }

    pub(crate) fn has(&self, kid: Option<&str>) -> bool {
        self.candidates(kid).next().is_some()
    }
}

#[derive(Default)]
struct State {
    current: Option<Arc<KeySet>>,
    last_forced: Option<Instant>,
}

/// Readers take a short std lock and clone an `Arc`; fetches are serialized
/// by an async mutex so a burst of logins on a cold or expired cache makes
/// one request, not one each.
pub(crate) struct JwksCache {
    ttl: Duration,
    state: RwLock<State>,
    pub(crate) fetch_lock: tokio::sync::Mutex<()>,
}

impl JwksCache {
    pub(crate) fn new(ttl: Duration) -> Self {
        JwksCache {
            ttl,
            state: RwLock::new(State::default()),
            fetch_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// The cached set while it is within its TTL.
    pub(crate) fn fresh(&self) -> Option<Arc<KeySet>> {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .current
            .as_ref()
            .filter(|set| set.fetched_at.elapsed() < self.ttl)
            .cloned()
    }

    /// Whether a forced refetch is allowed now. Records the attempt when it
    /// is, so concurrent callers with the same unknown kid share one fetch.
    pub(crate) fn take_forced_refetch(&self) -> bool {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let allowed = state
            .last_forced
            .is_none_or(|at| at.elapsed() >= FORCED_REFETCH_INTERVAL);
        if allowed {
            state.last_forced = Some(Instant::now());
        }
        allowed
    }

    /// The newest set, whatever its age.
    pub(crate) fn latest(&self) -> Option<Arc<KeySet>> {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.current.clone()
    }

    pub(crate) fn store(&self, set: KeySet) -> Arc<KeySet> {
        let set = Arc::new(set);
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.current = Some(Arc::clone(&set));
        set
    }
}
