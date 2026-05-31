//! Trusted-clock abstraction (closes WS-4 / T8 / T9).
//!
//! The host wallclock (`chrono::Utc::now()`) is untrusted from the policy
//! engine's perspective: a malicious operator can advance `CLOCK_REALTIME` to
//! roll the daily-volume date or satisfy the `time_window` rule. This module
//! provides a [`TrustedClock`] that:
//!
//! 1. **Caches** the most recent trusted wallclock reading and the
//!    `Instant::now()` value at the time of that reading.
//! 2. Computes `now()` as `cached_timestamp + (Instant::now() - last_refresh)`
//!    so policy decisions advance in lock-step with the monotonic clock,
//!    not whatever the host wallclock currently says.
//! 3. **Refuses** to return a timestamp if the cache is older than
//!    [`MAX_CACHE_AGE_SECS`] (default 60s). The caller is responsible for
//!    triggering [`TrustedClock::refresh`] periodically.
//!
//! Two backends are provided:
//! - [`RoughtimeBackend`] — verifies an Ed25519-signed timestamp from a
//!   Roughtime-style server. The server pubkey is committed in `policy.toml`.
//!   Currently scaffolded; the network dial is deferred to the operator's
//!   integration code (the verification machinery is in place).
//! - [`MonotonicBackend`] — fallback documented in WS-4 §6 of the audit:
//!   accepts `chrono::Utc::now()` BUT requires it to be within ±5s of a
//!   monotonic boot anchor. Refuses backwards skew (a host that turns the
//!   wallclock back is rejected). Used in Dev mode where Roughtime is not
//!   reachable.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
#[cfg(test)]
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Maximum age (seconds) of the cached timestamp before `now()` returns Err.
pub const MAX_CACHE_AGE_SECS: u64 = 60;

/// Maximum tolerated drift (seconds) between host wallclock and the monotonic
/// anchor in [`MonotonicBackend`].
pub const MAX_HOST_DRIFT_SECS: i64 = 5;

/// Source of the cached timestamp. We track this so `/metrics` can surface
/// "we are running on the monotonic fallback" as a degraded-state signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockSource {
    Roughtime,
    Monotonic,
}

/// Trait implemented by the network/IO side of a clock backend. Kept small so
/// tests can swap in a deterministic fake.
pub trait ClockBackend: Send + Sync {
    /// Refresh the trusted timestamp. Returns `(unix_seconds, source)`.
    fn refresh(&self) -> Result<(i64, ClockSource)>;
}

/// A trusted clock that hands out monotonic-anchored unix timestamps. Cheap
/// to read (`now()` is two atomic loads + one `Instant::now()`); refreshes
/// happen on a separate task or on the request path.
#[derive(Debug)]
pub struct TrustedClock {
    cached_timestamp: AtomicI64,
    last_refresh_inst: Mutex<Instant>,
    last_refresh_unix: AtomicI64,
    source: Mutex<ClockSource>,
    /// Boot-time monotonic + wallclock anchor. Used by `MonotonicBackend`
    /// to detect host clock skew (positive or negative).
    boot_inst: Instant,
    boot_unix: i64,
}

impl TrustedClock {
    /// Create a new clock with `MonotonicBackend` defaults. The first
    /// `refresh()` call seeds `cached_timestamp` from the host wallclock
    /// (verified against the boot anchor); subsequent calls advance by
    /// monotonic delta only.
    pub fn new_with_monotonic_seed() -> Result<Self> {
        let boot_inst = Instant::now();
        let boot_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock pre-1970")?
            .as_secs() as i64;
        let clock = Self {
            cached_timestamp: AtomicI64::new(boot_unix),
            last_refresh_inst: Mutex::new(boot_inst),
            last_refresh_unix: AtomicI64::new(boot_unix),
            source: Mutex::new(ClockSource::Monotonic),
            boot_inst,
            boot_unix,
        };
        Ok(clock)
    }

    /// Drive a refresh through the supplied backend. Updates the cached
    /// timestamp + monotonic anchor. Returns the new (unix, source) pair.
    pub fn refresh(&self, backend: &dyn ClockBackend) -> Result<(i64, ClockSource)> {
        let (ts, src) = backend.refresh().context("clock backend refresh failed")?;
        let now_inst = Instant::now();
        // Forbid backwards skew on the trusted timestamp itself: a refresh
        // that gives us a smaller `ts` than what we already cached is treated
        // as a tampering signal.
        let prior = self.cached_timestamp.load(Ordering::Relaxed);
        if ts < prior {
            return Err(anyhow!(
                "trusted clock backwards skew detected: cached={}, new={}",
                prior,
                ts
            ));
        }
        self.cached_timestamp.store(ts, Ordering::Release);
        self.last_refresh_unix.store(ts, Ordering::Release);
        *self.last_refresh_inst.lock().unwrap() = now_inst;
        *self.source.lock().unwrap() = src;
        Ok((ts, src))
    }

    /// Return the current trusted unix timestamp (seconds). Returns Err if
    /// the cache is older than [`MAX_CACHE_AGE_SECS`] — callers should treat
    /// this as a fail-closed condition in Production mode.
    pub fn now(&self) -> Result<i64> {
        let last_inst = *self.last_refresh_inst.lock().unwrap();
        let elapsed = last_inst.elapsed();
        if elapsed.as_secs() > MAX_CACHE_AGE_SECS {
            return Err(anyhow!(
                "trusted clock cache stale: last refresh {} secs ago (max {})",
                elapsed.as_secs(),
                MAX_CACHE_AGE_SECS
            ));
        }
        let cached = self.cached_timestamp.load(Ordering::Acquire);
        Ok(cached + elapsed.as_secs() as i64)
    }

    pub fn source(&self) -> ClockSource {
        *self.source.lock().unwrap()
    }

    /// Boot-anchor accessors used by [`MonotonicBackend`] to validate host
    /// drift. Public so tests can construct alternative backends.
    pub fn boot_anchor(&self) -> (Instant, i64) {
        (self.boot_inst, self.boot_unix)
    }
}

/// Fallback backend documented in WS-4 §6 of the audit. Uses
/// `SystemTime::now()` BUT only accepts the reading if the host wallclock
/// has not skewed by more than [`MAX_HOST_DRIFT_SECS`] vs the monotonic
/// boot anchor. Refuses backwards drift (clock turned back).
pub struct MonotonicBackend {
    boot_inst: Instant,
    boot_unix: i64,
}

impl MonotonicBackend {
    pub fn from_clock(clock: &TrustedClock) -> Self {
        let (boot_inst, boot_unix) = clock.boot_anchor();
        Self {
            boot_inst,
            boot_unix,
        }
    }
}

impl ClockBackend for MonotonicBackend {
    fn refresh(&self) -> Result<(i64, ClockSource)> {
        let host_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock pre-1970")?
            .as_secs() as i64;
        let mono_secs = self.boot_inst.elapsed().as_secs() as i64;
        let expected = self.boot_unix + mono_secs;
        let drift = host_unix - expected;
        if drift.abs() > MAX_HOST_DRIFT_SECS {
            return Err(anyhow!(
                "host wallclock drift {drift}s exceeds tolerance ±{MAX_HOST_DRIFT_SECS}s \
                 (host={host_unix}, monotonic-projected={expected})"
            ));
        }
        Ok((host_unix, ClockSource::Monotonic))
    }
}

/// Roughtime backend. The full Roughtime protocol speaks UDP and parses a
/// nested CBOR-like message; our worker only needs the *result* — a signed
/// timestamp from a server whose pubkey is committed in `policy.toml`. We
/// therefore implement a minimal interface:
///
/// - [`RoughtimeBackend::new`] takes the server pubkey + a closure that does
///   the actual network dial and returns `(timestamp_unix, signature_bytes)`.
/// - The signature is verified over `domain || timestamp.to_be_bytes()` using
///   Ed25519. Domain string is `b"GLYPH:roughtime:v1:"`.
///
/// Operators wire the network closure to `roughtime` crate or a custom
/// implementation; the worker side enforces signature verification regardless.
pub struct RoughtimeBackend<F>
where
    F: Fn() -> Result<(i64, Vec<u8>)> + Send + Sync,
{
    server_pubkey: VerifyingKey,
    fetch: F,
}

impl<F> RoughtimeBackend<F>
where
    F: Fn() -> Result<(i64, Vec<u8>)> + Send + Sync,
{
    pub fn new(server_pubkey: [u8; 32], fetch: F) -> Result<Self> {
        let server_pubkey = VerifyingKey::from_bytes(&server_pubkey)
            .map_err(|e| anyhow!("invalid Roughtime server pubkey: {e}"))?;
        Ok(Self {
            server_pubkey,
            fetch,
        })
    }

    /// Domain-separated payload for signature verification. Public so an
    /// integration test can sign a fake response with a test keypair.
    pub fn signing_payload(timestamp: i64) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"GLYPH:roughtime:v1:");
        h.update(timestamp.to_be_bytes());
        h.finalize().into()
    }
}

impl<F> ClockBackend for RoughtimeBackend<F>
where
    F: Fn() -> Result<(i64, Vec<u8>)> + Send + Sync,
{
    fn refresh(&self) -> Result<(i64, ClockSource)> {
        let (ts, sig_bytes) = (self.fetch)().context("roughtime fetch closure returned error")?;
        if sig_bytes.len() != 64 {
            return Err(anyhow!(
                "roughtime signature wrong length: {} (expected 64)",
                sig_bytes.len()
            ));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = DalekSignature::from_bytes(&sig_arr);
        let payload = Self::signing_payload(ts);
        self.server_pubkey
            .verify(&payload, &sig)
            .map_err(|e| anyhow!("roughtime signature verification failed: {e}"))?;
        Ok((ts, ClockSource::Roughtime))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn monotonic_backend_accepts_in_window() {
        let clock = TrustedClock::new_with_monotonic_seed().unwrap();
        let backend = MonotonicBackend::from_clock(&clock);
        // Refresh immediately — drift should be ~0.
        assert!(backend.refresh().is_ok());
    }

    #[test]
    fn now_advances_with_monotonic_delta() {
        let clock = TrustedClock::new_with_monotonic_seed().unwrap();
        let t0 = clock.now().unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        let t1 = clock.now().unwrap();
        assert!(
            t1 >= t0 + 1,
            "expected at least 1s monotonic delta, got {}",
            t1 - t0
        );
    }

    #[test]
    fn cache_staleness_is_caught() {
        let clock = TrustedClock::new_with_monotonic_seed().unwrap();
        // Force the last_refresh instant into the past. We shift via the
        // mutex so the test doesn't have to wait MAX_CACHE_AGE_SECS.
        {
            let mut g = clock.last_refresh_inst.lock().unwrap();
            *g = Instant::now() - Duration::from_secs(MAX_CACHE_AGE_SECS + 5);
        }
        let res = clock.now();
        assert!(res.is_err(), "stale cache must Err, got {:?}", res);
    }

    #[test]
    fn refresh_rejects_backwards_skew() {
        let clock = TrustedClock::new_with_monotonic_seed().unwrap();
        let prior = clock.cached_timestamp.load(Ordering::Acquire);
        struct BackwardsBackend(i64);
        impl ClockBackend for BackwardsBackend {
            fn refresh(&self) -> Result<(i64, ClockSource)> {
                Ok((self.0, ClockSource::Monotonic))
            }
        }
        let bad = BackwardsBackend(prior - 100);
        let res = clock.refresh(&bad);
        assert!(res.is_err(), "backwards skew must Err, got {:?}", res);
    }

    #[test]
    fn roughtime_backend_verifies_signature() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let ts = 1_700_000_000i64;
        let payload = RoughtimeBackend::<fn() -> Result<(i64, Vec<u8>)>>::signing_payload(ts);
        let sig = sk.sign(&payload).to_bytes().to_vec();
        let backend = RoughtimeBackend::new(pk, move || Ok((ts, sig.clone()))).unwrap();
        let (ts2, src) = backend.refresh().unwrap();
        assert_eq!(ts2, ts);
        assert_eq!(src, ClockSource::Roughtime);
    }

    #[test]
    fn roughtime_backend_rejects_wrong_signer() {
        let sk_real = SigningKey::from_bytes(&[7u8; 32]);
        let sk_fake = SigningKey::from_bytes(&[8u8; 32]);
        let pk_real = sk_real.verifying_key().to_bytes();
        let ts = 1_700_000_000i64;
        let payload = RoughtimeBackend::<fn() -> Result<(i64, Vec<u8>)>>::signing_payload(ts);
        let bad_sig = sk_fake.sign(&payload).to_bytes().to_vec();
        let backend = RoughtimeBackend::new(pk_real, move || Ok((ts, bad_sig.clone()))).unwrap();
        let res = backend.refresh();
        assert!(res.is_err(), "wrong-signer roughtime must Err");
    }
}
