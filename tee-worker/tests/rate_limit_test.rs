//! WS-5 — Per-IP token-bucket rate limiter.
//!
//! Acceptance: 10 OK, 11th gets 429.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use glyph_tee_worker::rate_limit::RateLimiter;

#[test]
fn first_ten_succeed_eleventh_fails() {
    let limiter = RateLimiter::default_per_minute_10();
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let t0 = Instant::now();
    for i in 0..10 {
        assert!(limiter.try_acquire_at(ip, t0), "request {i} should succeed");
    }
    assert!(!limiter.try_acquire_at(ip, t0), "11th must be rate-limited");
}

#[test]
fn separate_ips_have_independent_buckets() {
    let limiter = RateLimiter::default_per_minute_10();
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let t0 = Instant::now();
    for _ in 0..10 {
        limiter.try_acquire_at(a, t0);
    }
    assert!(limiter.try_acquire_at(b, t0), "second IP must not be limited");
}

#[test]
fn refills_at_correct_rate() {
    let limiter = RateLimiter::default_per_minute_10();
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let t0 = Instant::now();
    for _ in 0..10 {
        limiter.try_acquire_at(ip, t0);
    }
    // 10/60 token/sec → 6 seconds buys exactly 1 token.
    let t1 = t0 + Duration::from_secs(6);
    assert!(limiter.try_acquire_at(ip, t1));
    assert!(!limiter.try_acquire_at(ip, t1), "burst capacity should be 1 after 6s refill");
}
