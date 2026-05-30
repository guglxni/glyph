import QEDGen.Solana

open QEDGen.Solana

/-
# Access Control Properties for GLYPH Verifier

This module proves that only authorized agents can execute transactions
through the verify_and_execute instruction.

## Properties Proven
- **AC1-ActiveAgentOnly**: Only active agents can execute
- **AC2-AgentIdentityBinding**: Signer must match registered agent
-/

-- =============================================================================
-- State Model
-- =============================================================================

/-- Agent registry state - mirrors on-chain AgentRegistry account -/
structure AgentRegistry where
  authority : Pubkey
  agent_pubkey : Pubkey
  policy_commitment : List U8  -- 32 bytes
  attestation_hash : List U8   -- 32 bytes  
  policy_epoch : Nat
  is_active : Bool
  deriving DecidableEq, Repr, BEq

/-- Program state includes the registry and transaction context -/
structure VerifyContext where
  registry : AgentRegistry
  signer : Pubkey
  system_program : Pubkey

-- =============================================================================
-- Transition Functions
-- =============================================================================

/-- 
The verify_and_execute transition.
Returns some () if the signer is authorized (active agent),
returns none if access control check fails.
-/
def verifyAndExecuteTransition (ctx : VerifyContext) : Option Unit :=
  if ctx.registry.is_active then
    if ctx.signer = ctx.registry.agent_pubkey then
      some ()
    else
      none
  else
    none

-- =============================================================================
-- Theorem: AC1 - Only Active Agents Can Execute
-- =============================================================================

/-- 
**AC1-ActiveAgentOnly**: If verify_and_execute succeeds, the agent must be active.

For all contexts, if the transition returns some (success),
then the agent registry shows is_active = true.
-/
theorem ac1_active_agent_only (ctx : VerifyContext)
    (h_exec : verifyAndExecuteTransition ctx ≠ none) :
    ctx.registry.is_active = true := by
  -- Proof by cases on is_active
  cases h_active : ctx.registry.is_active
  · -- Case: is_active = false, verifyAndExecuteTransition returns none
    have h_result : verifyAndExecuteTransition ctx = none := by
      simp [verifyAndExecuteTransition, h_active]
    rw [h_result] at h_exec
    contradiction
  · -- Case: is_active = true
    rfl

-- =============================================================================
-- Theorem: AC2 - Agent Identity Binding
-- =============================================================================

/-- 
**AC2-AgentIdentityBinding**: If verify_and_execute succeeds, 
the signer must be the registered agent.

For all contexts, if the transition returns some (success),
then the signer's public key equals the agent_pubkey in registry.
-/
theorem ac2_agent_identity_binding (ctx : VerifyContext)
    (h_exec : verifyAndExecuteTransition ctx ≠ none) :
    ctx.signer = ctx.registry.agent_pubkey := by
  -- First establish that agent is active (by AC1)
  have h_active : ctx.registry.is_active = true := ac1_active_agent_only ctx h_exec
  
  -- Now use by_cases on signer equality
  by_cases h_signer : ctx.signer = ctx.registry.agent_pubkey
  · -- Case: signer = agent_pubkey, which is what we want
    exact h_signer
  · -- Case: signer ≠ agent_pubkey, then result is none (contradiction)
    have h_result : verifyAndExecuteTransition ctx = none := by
      simp [verifyAndExecuteTransition, h_active, h_signer]
    rw [h_result] at h_exec
    contradiction

-- =============================================================================
-- Combined Access Control Theorem
-- =============================================================================

/-- 
Combined access control: successful execution requires BOTH conditions.

This combines AC1 and AC2 into a single theorem for convenience.
-/
theorem access_control_combined (ctx : VerifyContext)
    (h_exec : verifyAndExecuteTransition ctx ≠ none) :
    ctx.registry.is_active = true ∧ ctx.signer = ctx.registry.agent_pubkey := by
  constructor
  · exact ac1_active_agent_only ctx h_exec
  · exact ac2_agent_identity_binding ctx h_exec

-- =============================================================================
-- Negative Cases (When access is denied)
-- =============================================================================

/-- If agent is not active, execution fails -/
theorem inactive_agent_fails (ctx : VerifyContext)
    (h_inactive : ctx.registry.is_active = false) :
    verifyAndExecuteTransition ctx = none := by
  simp [verifyAndExecuteTransition, h_inactive]

/-- If signer doesn't match agent, execution fails (assuming agent is active) -/
theorem wrong_signer_fails (ctx : VerifyContext)
    (h_active : ctx.registry.is_active = true)
    (h_wrong : ctx.signer ≠ ctx.registry.agent_pubkey) :
    verifyAndExecuteTransition ctx = none := by
  simp [verifyAndExecuteTransition, h_active, h_wrong]
