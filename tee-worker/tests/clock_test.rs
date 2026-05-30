//! WS-4 — Trusted-clock integration tests.
//!
//! Acceptance: backwards skew is detected; cache staleness flips `now()` to Err.

use anyhow::Result;
use ed25519_dalek::{Signer, SigningKey};
use glyph_tee_worker::clock::{ClockBackend, ClockSource, RoughtimeBackend, TrustedClock};

struct FakeBackend(i64);
impl ClockBackend for FakeBackend {
    fn refresh(&self) -> Result<(i64, ClockSource)> {
        Ok((self.0, ClockSource::Monotonic))
    }
}

#[test]
fn backwards_skew_rejected() {
    let clock = TrustedClock::new_with_monotonic_seed().unwrap();
    let forward = FakeBackend(clock.now().unwrap() + 100);
    clock.refresh(&forward).unwrap();
    let backwards = FakeBackend(clock.now().unwrap() - 1_000_000);
    let res = clock.refresh(&backwards);
    assert!(res.is_err(), "backwards skew must be rejected");
}

#[test]
fn roughtime_round_trip() {
    let sk = SigningKey::from_bytes(&[5u8; 32]);
    let pk = sk.verifying_key().to_bytes();
    let ts = 1_900_000_000i64;
    let payload = RoughtimeBackend::<fn() -> Result<(i64, Vec<u8>)>>::signing_payload(ts);
    let sig = sk.sign(&payload).to_bytes().to_vec();
    let backend = RoughtimeBackend::new(pk, move || Ok((ts, sig.clone()))).unwrap();

    let clock = TrustedClock::new_with_monotonic_seed().unwrap();
    let (got, src) = clock.refresh(&backend).unwrap();
    assert_eq!(got, ts);
    assert_eq!(src, ClockSource::Roughtime);
}

#[test]
fn roughtime_bad_signature_rejected() {
    let real = SigningKey::from_bytes(&[5u8; 32]);
    let fake = SigningKey::from_bytes(&[9u8; 32]);
    let pk_real = real.verifying_key().to_bytes();
    let ts = 1_900_000_000i64;
    let payload = RoughtimeBackend::<fn() -> Result<(i64, Vec<u8>)>>::signing_payload(ts);
    let bad_sig = fake.sign(&payload).to_bytes().to_vec();
    let backend = RoughtimeBackend::new(pk_real, move || Ok((ts, bad_sig.clone()))).unwrap();
    assert!(backend.refresh().is_err());
}
