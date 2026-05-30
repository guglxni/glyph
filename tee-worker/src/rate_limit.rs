//! Per-source-IP token-bucket rate limiter (closes T19).
//!
//! Default policy: 10 requests / minute / source IP, with burst capacity 10.
//! That matches the audit guidance ("11th intent in 60 s from same IP returns
//! `429 RateLimited`"). The implementation uses a single `Mutex<HashMap>`;
//! eviction of stale buckets runs lazily on `try_acquire` so a long-lived
//! worker doesn't accumulate entries from one-off probes.
//!
//! The limiter is intentionally NOT a global gate: it caps per-source traffic.
//! A global ceiling (e.g. queue depth) is a separate workstream and lives in
//! `metrics.rs` once we wire compute-budget back-pressure.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Per-IP token bucket. `capacity` is the burst size, `refill_per_sec` is the
/// sustained rate. Tokens accumulate continuously; on `try_acquire` we add
/// `elapsed * refill_per_sec` (clamped to capacity) and consume one.
#[derive(Debug, Clone)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug)]
pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    /// Drop bucket entries idle longer than this from the map.
    eviction_after: Duration,
    inner: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    /// Create a token-bucket limiter. Common defaults:
    /// - `RateLimiter::new(10.0, 10.0 / 60.0, Duration::from_secs(600))`
    pub fn new(capacity: f64, refill_per_sec: f64, eviction_after: Duration) -> Self {
        Self {
            capacity,
            refill_per_sec,
            eviction_after,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Default profile from the audit (10 req / 60 s / IP, burst 10).
    pub fn default_per_minute_10() -> Self {
        Self::new(10.0, 10.0 / 60.0, Duration::from_secs(600))
    }

    /// Returns `true` if a token is available (and consumed); `false` if the
    /// caller should be rejected with HTTP 429.
    pub fn try_acquire(&self, ip: IpAddr) -> bool {
        self.try_acquire_at(ip, Instant::now())
    }

    /// `try_acquire` with explicit time, for deterministic tests.
    pub fn try_acquire_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut map = self.inner.lock().expect("rate-limiter mutex poisoned");

        // Lazy eviction: drop buckets whose last_refill is older than `eviction_after`.
        // O(n) over the table — acceptable for a few-thousand-IP map.
        map.retain(|_, b| now.duration_since(b.last_refill) <= self.eviction_after);

        let bucket = map.entry(ip).or_insert(Bucket {
            tokens: self.capacity,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Test-only inspector.
    #[cfg(test)]
    pub fn bucket_count(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::default_per_minute_10()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn ten_through_then_429() {
        let limiter = RateLimiter::default_per_minute_10();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let t0 = Instant::now();
        for _ in 0..10 {
            assert!(limiter.try_acquire_at(ip, t0));
        }
        // 11th immediately should fail (refill at 10/60 over 0s = 0 tokens).
        assert!(!limiter.try_acquire_at(ip, t0));
    }

    #[test]
    fn refills_over_time() {
        let limiter = RateLimiter::default_per_minute_10();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let t0 = Instant::now();
        for _ in 0..10 {
            limiter.try_acquire_at(ip, t0);
        }
        // After ~6 seconds we get 1 token back (10/60 * 6 = 1).
        let t1 = t0 + Duration::from_secs(6);
        assert!(limiter.try_acquire_at(ip, t1));
        // No more tokens immediately after.
        assert!(!limiter.try_acquire_at(ip, t1));
    }

    #[test]
    fn separate_ips_have_separate_buckets() {
        let limiter = RateLimiter::default_per_minute_10();
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let t0 = Instant::now();
        for _ in 0..10 {
            assert!(limiter.try_acquire_at(a, t0));
        }
        // Bucket B is fresh — first request should succeed.
        assert!(limiter.try_acquire_at(b, t0));
    }
}
