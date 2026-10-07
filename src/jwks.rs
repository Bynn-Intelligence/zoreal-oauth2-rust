//! The in-process JWKS cache.
//!
//! Three ages matter for a cached key set:
//!
//! - younger than the soft TTL (80 % of the TTL): served as is;
//! - between the soft TTL and the TTL: served, while one caller refreshes it
//!   as part of its own request (refresh-ahead), so no login waits on the
//!   periodic refetch;
//! - older than the TTL: refetched before use. If that refetch fails, the old
//!   set keeps being served for up to [`MAX_STALE`] beyond the TTL, so a
//!   brief JWKS outage does not become a login outage.
//!
//! Every fetch attempt, successful or not, bumps a generation counter. A
//! caller that queued behind another's fetch takes that fetch's outcome
//! instead of fetching again, and a failure is remembered for
//! [`FAILURE_BACKOFF`], so an unhealthy endpoint sees one request per window,
//! not one per login.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use p256::ecdsa::VerifyingKey;

use crate::jwt::Jwk;

/// A forged `kid` must not turn every verification into a JWKS fetch. An
/// unknown kid forces at most one refetch per this interval; a genuine key
/// rotation needs exactly one.
pub(crate) const FORCED_REFETCH_INTERVAL: Duration = Duration::from_secs(10);
/// How long a failed fetch is remembered before the next attempt.
pub(crate) const FAILURE_BACKOFF: Duration = Duration::from_secs(2);
/// How long past its TTL a key set may still be served while refetching it
/// fails.
pub(crate) const MAX_STALE: Duration = Duration::from_secs(3600);

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

    /// The keys to try for a token header: the one whose kid matches, or,
    /// when the token names no kid, the only key of a single-key set.
    pub(crate) fn candidates<'a>(
        &'a self,
        kid: Option<&'a str>,
    ) -> impl Iterator<Item = &'a VerifyingKey> + 'a {
        let single = self.keys.len() == 1;
        self.keys
            .iter()
            .filter(move |jwk| match kid {
                Some(kid) => jwk.kid.as_deref() == Some(kid),
                None => single,
            })
            .map(|jwk| &jwk.key)
    }

    pub(crate) fn has(&self, kid: Option<&str>) -> bool {
        self.candidates(kid).next().is_some()
    }

    fn age(&self) -> Duration {
        self.fetched_at.elapsed()
    }
}

#[derive(Default)]
struct State {
    current: Option<Arc<KeySet>>,
    generation: u64,
    last_failure: Option<(Instant, Arc<str>)>,
    last_forced: Option<Instant>,
}

/// What the cache says about the current set.
pub(crate) enum Lookup {
    /// Fresh: serve it.
    Fresh(Arc<KeySet>),
    /// Past the soft TTL: serve it and, if nobody else is, refresh it.
    RefreshAhead(Arc<KeySet>),
    /// Missing or past the TTL: fetch before use.
    Expired,
}

/// Readers take a short std lock and clone an `Arc`; fetches are serialized
/// by an async mutex. No std lock is held across an await.
pub(crate) struct JwksCache {
    ttl: Duration,
    soft_ttl: Duration,
    state: RwLock<State>,
    pub(crate) fetch_lock: tokio::sync::Mutex<()>,
}

impl JwksCache {
    pub(crate) fn new(ttl: Duration) -> Self {
        JwksCache {
            ttl,
            soft_ttl: ttl.mul_f64(0.8),
            state: RwLock::new(State::default()),
            fetch_lock: tokio::sync::Mutex::new(()),
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, State> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, State> {
        self.state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn lookup(&self) -> Lookup {
        match &self.read().current {
            Some(set) if set.age() < self.soft_ttl => Lookup::Fresh(Arc::clone(set)),
            Some(set) if set.age() < self.ttl => Lookup::RefreshAhead(Arc::clone(set)),
            _ => Lookup::Expired,
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.read().generation
    }

    /// The set within its soft TTL, if there is one: no refresh is due.
    pub(crate) fn within_soft_ttl(&self) -> Option<Arc<KeySet>> {
        self.read()
            .current
            .as_ref()
            .filter(|set| set.age() < self.soft_ttl)
            .cloned()
    }

    /// The set within its TTL, if there is one.
    pub(crate) fn within_ttl(&self) -> Option<Arc<KeySet>> {
        self.read()
            .current
            .as_ref()
            .filter(|set| set.age() < self.ttl)
            .cloned()
    }

    /// The set still servable while refetching fails: within the TTL plus
    /// [`MAX_STALE`].
    pub(crate) fn servable(&self) -> Option<Arc<KeySet>> {
        self.read()
            .current
            .as_ref()
            .filter(|set| set.age() < self.ttl + MAX_STALE)
            .cloned()
    }

    /// The reason of a failure younger than [`FAILURE_BACKOFF`].
    pub(crate) fn recent_failure(&self) -> Option<Arc<str>> {
        self.read()
            .last_failure
            .as_ref()
            .filter(|(at, _)| at.elapsed() < FAILURE_BACKOFF)
            .map(|(_, reason)| Arc::clone(reason))
    }

    /// The reason of the last failure, if the last attempt failed.
    pub(crate) fn last_failure(&self) -> Option<Arc<str>> {
        self.read()
            .last_failure
            .as_ref()
            .map(|(_, reason)| Arc::clone(reason))
    }

    /// Whether a forced refetch is allowed now. Records the attempt when it
    /// is, so concurrent callers with the same unknown kid share one fetch.
    pub(crate) fn take_forced_refetch(&self) -> bool {
        let mut state = self.write();
        let allowed = state
            .last_forced
            .is_none_or(|at| at.elapsed() >= FORCED_REFETCH_INTERVAL);
        if allowed {
            state.last_forced = Some(Instant::now());
        }
        allowed
    }

    pub(crate) fn store(&self, set: KeySet) -> Arc<KeySet> {
        let set = Arc::new(set);
        let mut state = self.write();
        state.current = Some(Arc::clone(&set));
        state.generation += 1;
        state.last_failure = None;
        set
    }

    pub(crate) fn record_failure(&self, reason: &str) {
        let mut state = self.write();
        state.generation += 1;
        state.last_failure = Some((Instant::now(), Arc::from(reason)));
    }
}
