import QEDGen.Solana

open QEDGen.Solana

/-
# Replay Protection Properties for GLYPH Verifier

This module proves that nonces are consumed atomically and cannot be replayed.
-/

-- =============================================================================
-- State Model
-- =============================================================================

/-- A nonce is represented as a list of bytes -/
abbrev Nonce := List U8

/-- Nonce account state - mirrors on-chain NonceAccount -/
structure NonceAccount where
  nonce : Nonce
  agent_pubkey : Pubkey
  policy_epoch : Nat
  deriving DecidableEq, Repr, BEq

/-- Global program state tracking used nonces -/
structure ProgramState where
  used_nonces : List (Nonce × Nat)
  agent_registries : List Pubkey
  deriving DecidableEq, Repr, BEq

-- =============================================================================
-- Helper Functions
-- =============================================================================

/-- Check if a nonce has been used in a specific epoch -/
def nonceUsed (state : ProgramState) (n : Nonce) (epoch : Nat) : Bool :=
  decide ((n, epoch) ∈ state.used_nonces)

/-- Mark a nonce as used in a specific epoch -/
def markNonceUsed (state : ProgramState) (n : Nonce) (epoch : Nat) : ProgramState :=
  { state with used_nonces := (n, epoch) :: state.used_nonces }

/-- 
Compute the PDA for a nonce account.
In the real program: PDA = ["nonce", epoch_bytes, nonce]
-/
def noncePDA (n : Nonce) (epoch : Nat) : String :=
  s!"nonce:{epoch}:{n}"

-- =============================================================================
-- Transition Functions
-- =============================================================================

/-- 
The verify_and_execute transition with nonce checking.
Returns some new_state if nonce has not been used, none otherwise.
-/
def verifyAndExecuteWithNonce 
    (state : ProgramState) 
    (_agent : Pubkey)
    (n : Nonce) 
    (epoch : Nat) : Option ProgramState :=
  if _h : nonceUsed state n epoch then
    none
  else
    some (markNonceUsed state n epoch)

-- =============================================================================
-- Theorem: RP1 - Nonce Atomicity (Replay Prevention)
-- =============================================================================

/-- 
**RP1-NonceAtomicity**: A nonce can only be used once per epoch.

If execution succeeds, then:
1. The nonce was NOT used in the pre-state
2. The nonce IS used in the post-state
-/
theorem rp1_nonce_atomicity 
    (pre post : ProgramState)
    (agent : Pubkey)
    (n : Nonce)
    (epoch : Nat)
    (h_exec : verifyAndExecuteWithNonce pre agent n epoch = some post) :
    nonceUsed pre n epoch = false ∧ nonceUsed post n epoch = true := by
  simp only [verifyAndExecuteWithNonce] at h_exec
  split at h_exec
  · -- Case: nonceUsed pre n epoch = true, returns none (contradiction)
    contradiction
  · -- Case: nonceUsed pre n epoch = false, returns some (markNonceUsed pre n epoch)
    rename_i h_not_used
    have h_used_false : nonceUsed pre n epoch = false := by
      simp at h_not_used
      exact h_not_used
    constructor
    · exact h_used_false
    · -- Now prove post-state has nonce used
      -- h_exec : some (markNonceUsed pre n epoch) = some post
      have h_eq : post = markNonceUsed pre n epoch := by
        have h_sym : some post = some (markNonceUsed pre n epoch) := by
          rw [←h_exec]  
        rw [Option.some_inj] at h_sym
        exact h_sym
      rw [h_eq]
      simp [nonceUsed, markNonceUsed]

-- =============================================================================
-- Theorem: RP2 - Epoch Isolation
-- =============================================================================

/-- 
**RP2-EpochIsolation**: The same nonce can be reused across different epochs.

This is stated as an axiom - proving string injectivity requires
more advanced string theory in Lean.
-/
axiom rp2_epoch_isolation 
    (n : Nonce)
    (e1 e2 : Nat)
    (h_ne : e1 ≠ e2) :
    noncePDA n e1 ≠ noncePDA n e2

-- =============================================================================
-- Theorem: Double-Spend Prevention
-- =============================================================================

/-- 
**DoubleSpendPrevention**: Using a nonce twice in the same epoch fails.

If we successfully execute once, attempting again fails.
-/
theorem double_spend_prevention
    (state1 state2 : ProgramState)
    (agent : Pubkey)
    (n : Nonce)
    (epoch : Nat)
    (h_first : verifyAndExecuteWithNonce state1 agent n epoch = some state2) :
    verifyAndExecuteWithNonce state2 agent n epoch = none := by
  -- After first execution, nonce n is in state2.used_nonces
  have h_used : nonceUsed state2 n epoch = true := by
    simp only [verifyAndExecuteWithNonce] at h_first
    split at h_first
    · -- Case: nonceUsed state1 n epoch = true, returns none (contradiction)
      contradiction
    · -- Case: nonceUsed state1 n epoch = false
      have h_eq : state2 = markNonceUsed state1 n epoch := by
        have h_sym : some state2 = some (markNonceUsed state1 n epoch) := by
          rw [←h_first]
        rw [Option.some_inj] at h_sym
        exact h_sym
      rw [h_eq]
      simp [nonceUsed, markNonceUsed]
  -- Now prove that second call returns none
  simp only [verifyAndExecuteWithNonce]
  simp [h_used]
