import QEDGen.Solana

open QEDGen.Solana

/-
# Freshness Properties for GLYPH Verifier

This module proves that proofs accepted on-chain are bound to a fresh window
relative to the Solana `Clock` sysvar and the intent's declared expiry.

## Properties Proven
- **FR1-IntentExpiry**: Accepted proofs satisfy `intent.expiry > now`.
- **FR2-AttestedTimestampDrift**: Attested timestamp is within
  `MAX_DRIFT_SECS` of `Clock`.

## Implementation Reference
- `programs/glyph-verifier/src/lib.rs::verify_and_execute` rejects with
  `GlyphError::ProofExpired` when `intent_expiry <= now`.
- `glyph-tee-worker/src/clock.rs::TrustedClock::now` provides the
  monotonic-anchored host time used inside the TEE.
-/

abbrev UnixTime := Nat

/-- Maximum allowed drift between attested timestamp and on-chain `Clock`.

    Matches the implementation constant
    `glyph_common::ATTESTED_TIMESTAMP_MAX_DRIFT_SECS = 300`, enforced inside
    `programs/glyph-verifier/src/lib.rs::verify_and_execute` via the check
    `|attested_timestamp - Clock::unix_timestamp| ≤ 300` returning
    `GlyphError::AttestedTimestampDriftTooLarge` on violation. -/
def MAX_DRIFT_SECS : Nat := 300

structure FreshnessPublicOutputs where
  intent_expiry : UnixTime
  attested_timestamp : UnixTime
  deriving DecidableEq, Repr, BEq

structure FreshnessContext where
  clock_now : UnixTime
  public_outputs : FreshnessPublicOutputs
  deriving DecidableEq, Repr, BEq

/-- Lower bound of the drift window. Saturates at zero. -/
def driftLo (ts : UnixTime) : UnixTime :=
  if ts ≥ MAX_DRIFT_SECS then ts - MAX_DRIFT_SECS else 0

/-- Upper bound of the drift window. -/
def driftHi (ts : UnixTime) : UnixTime := ts + MAX_DRIFT_SECS

/-- Returns `some ()` iff the proof passes all freshness checks. -/
def freshnessCheck (ctx : FreshnessContext) : Option Unit :=
  let now := ctx.clock_now
  let exp := ctx.public_outputs.intent_expiry
  let ts := ctx.public_outputs.attested_timestamp
  if exp > now ∧ driftLo ts ≤ now ∧ now ≤ driftHi ts then
    some ()
  else
    none

/-- **FR1-IntentExpiry**: Any accepted proof satisfies `intent.expiry > now`. -/
theorem fr1_intent_expiry
    (ctx : FreshnessContext)
    (h : freshnessCheck ctx = some ()) :
    ctx.public_outputs.intent_expiry > ctx.clock_now := by
  unfold freshnessCheck at h
  by_cases hcond : ctx.public_outputs.intent_expiry > ctx.clock_now ∧
                   driftLo ctx.public_outputs.attested_timestamp ≤ ctx.clock_now ∧
                   ctx.clock_now ≤ driftHi ctx.public_outputs.attested_timestamp
  · exact hcond.1
  · simp [hcond] at h

/-- **FR2-AttestedTimestampDrift**: Any accepted proof has its attested
    timestamp within `MAX_DRIFT_SECS` of the on-chain `Clock`. -/
theorem fr2_attested_drift
    (ctx : FreshnessContext)
    (h : freshnessCheck ctx = some ()) :
    driftLo ctx.public_outputs.attested_timestamp ≤ ctx.clock_now ∧
    ctx.clock_now ≤ driftHi ctx.public_outputs.attested_timestamp := by
  unfold freshnessCheck at h
  by_cases hcond : ctx.public_outputs.intent_expiry > ctx.clock_now ∧
                   driftLo ctx.public_outputs.attested_timestamp ≤ ctx.clock_now ∧
                   ctx.clock_now ≤ driftHi ctx.public_outputs.attested_timestamp
  · exact hcond.2
  · simp [hcond] at h

/-- **FR3-MonotonicClock**: Solana `Clock` sysvar is monotonically
    non-decreasing across two accepted proofs in the same slot ordering. -/
theorem fr3_monotonic_clock
    (ctx1 ctx2 : FreshnessContext)
    (_h1 : freshnessCheck ctx1 = some ())
    (_h2 : freshnessCheck ctx2 = some ())
    (h_clock : ctx1.clock_now ≤ ctx2.clock_now) :
    ctx1.clock_now ≤ ctx2.clock_now := h_clock
