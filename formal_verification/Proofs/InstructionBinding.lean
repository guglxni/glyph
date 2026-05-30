import QEDGen.Solana

open QEDGen.Solana

/-
# Instruction Binding Properties for GLYPH Verifier

This module proves that the transaction hash committed in the ZK proof
matches the actual next instruction in the transaction.

This prevents "instruction substitution" attacks.
-/

-- =============================================================================
-- State Model
-- =============================================================================

/-- Transaction data is a list of bytes -/
abbrev TxData := List U8

/-- SHA-256 hash output (32 bytes) -/
abbrev Hash := List U8

/-- Public outputs from the ZK circuit -/
structure PublicOutputsWithTxHash where
  policy_commitment : List U8
  tx_hash : Hash
  deriving DecidableEq, Repr, BEq

/-- Model of the instruction sysvar -/
structure InstructionSysvar where
  current_index : Nat
  instructions : List TxData

-- =============================================================================
-- Hash Function Model
-- =============================================================================

/-- SHA-256 hash function (opaque axiom) -/
noncomputable axiom sha256 : TxData → Hash

/-- Collision resistance property -/
axiom sha256_collision_resistant 
    (x y : TxData) 
    (h_eq : sha256 x = sha256 y) : 
    x = y

-- =============================================================================
-- Instruction Loading
-- =============================================================================

/-- Load the next instruction -/
def loadNextInstruction 
    (sysvar : InstructionSysvar) : Option TxData :=
  sysvar.instructions.get? (sysvar.current_index + 1)

-- =============================================================================
-- Transition Functions
-- =============================================================================

/-- Transaction hash verification -/
noncomputable def verifyTxBinding
    (sysvar : InstructionSysvar)
    (public_outputs : PublicOutputsWithTxHash) : Option TxData :=
  match loadNextInstruction sysvar with
  | none => none
  | some next_ix =>
      let computed_hash := sha256 next_ix
      if computed_hash = public_outputs.tx_hash then
        some next_ix
      else
        none

-- =============================================================================
-- Theorem: IB1 - Transaction Hash Integrity
-- =============================================================================

/-- 
**IB1-TxHashIntegrity**: If verification succeeds, the hash matches.

The hash of the loaded instruction equals the tx_hash from public outputs.
-/
theorem ib1_tx_hash_integrity
    (sysvar : InstructionSysvar)
    (public_outputs : PublicOutputsWithTxHash)
    (instruction : TxData)
    (h_verify : verifyTxBinding sysvar public_outputs = some instruction) :
    sha256 instruction = public_outputs.tx_hash := by
  unfold verifyTxBinding at h_verify
  cases h_next : loadNextInstruction sysvar with
  | none =>
    -- Case: no next instruction, returns none (contradiction)
    exfalso
    simp_all
  | some next_ix =>
    -- Case: there is a next instruction
    simp [h_next] at h_verify
    -- Now h_verify is: if sha256 next_ix = public_outputs.tx_hash then some next_ix = some instruction else none = some instruction
    by_cases h_hash : sha256 next_ix = public_outputs.tx_hash
    · -- Case: hashes match
      simp [h_hash] at h_verify
      -- Now h_verify is: next_ix = instruction
      -- And h_hash is: sha256 next_ix = public_outputs.tx_hash
      have h_eq : instruction = next_ix := by
        rw [←h_verify]
      rw [h_eq]
      exact h_hash
    · -- Case: hashes don't match
      simp [h_hash] at h_verify

-- =============================================================================
-- Security: Instruction Substitution Prevention
-- =============================================================================

/-- 
**SubstitutionPrevention**: Cannot substitute a different instruction.

If verifyTxBinding succeeded with instruction, no other instruction' 
can have the same hash (assuming collision resistance).
-/
theorem substitution_prevention
    (sysvar : InstructionSysvar)
    (public_outputs : PublicOutputsWithTxHash)
    (instruction : TxData)
    (h_verify : verifyTxBinding sysvar public_outputs = some instruction)
    (instruction' : TxData)
    (h_neq : instruction' ≠ instruction) :
    sha256 instruction' ≠ public_outputs.tx_hash := by
  -- Proof by contradiction using collision resistance of SHA-256.
  -- If instruction' had the same hash, it would equal instruction
  -- by sha256_collision_resistant, contradicting h_neq.
  intro h_eq
  -- We know sha256 instruction = public_outputs.tx_hash (from ib1)
  have h_instr_hash : sha256 instruction = public_outputs.tx_hash := 
    ib1_tx_hash_integrity sysvar public_outputs instruction h_verify
  -- So sha256 instruction' = sha256 instruction
  have h_collision : sha256 instruction' = sha256 instruction := by
    rw [h_eq, h_instr_hash]
  -- By collision resistance, instruction' = instruction
  have h_same : instruction' = instruction := 
    sha256_collision_resistant instruction' instruction h_collision
  -- Contradiction with h_neq
  contradiction

-- =============================================================================
-- Full Execution Flow
-- =============================================================================

structure FullExecutionContext where
  sysvar : InstructionSysvar
  public_outputs : PublicOutputsWithTxHash

noncomputable def executeWithBinding (ctx : FullExecutionContext) : Option TxData :=
  verifyTxBinding ctx.sysvar ctx.public_outputs

theorem execution_implies_binding
    (ctx : FullExecutionContext)
    (instruction : TxData)
    (h_exec : executeWithBinding ctx = some instruction) :
    sha256 instruction = ctx.public_outputs.tx_hash := by
  exact ib1_tx_hash_integrity ctx.sysvar ctx.public_outputs instruction h_exec
