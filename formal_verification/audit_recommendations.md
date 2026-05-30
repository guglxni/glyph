# Formal Verification Recommendations for GLYPH

## Properties Suitable for Lean 4 Verification

### 1. Access Control Properties
```lean
-- Pattern from qedgen SKILL.md
structure AgentRegistry where
  agent_pubkey : Pubkey
  policy_commitment : [U8; 32]
  is_active : Bool

theorem only_active_agent_can_execute (pre : AgentRegistry) (signer : Pubkey)
    (h_exec : executeTransition pre signer ≠ none) :
    pre.is_active = true ∧ signer = pre.agent_pubkey := by
  -- Proof showing both conditions required
```

### 2. Nonce Uniqueness (Replay Protection)
```lean
def verifyAndExecuteTransition 
    (s : State) (proof : Groth16Proof) (nonce : [U8; 32]) : Option State :=
  if nonceUsed s nonce then none
  else if ¬verifyGroth16 proof then none
  else some (markNonceUsed s nonce)

theorem nonce_replay_prevented (pre post : State) (nonce : [U8; 32]) (proof)
    (h_exec : verifyAndExecuteTransition pre proof nonce = some post) :
    ¬nonceUsed pre nonce ∧ nonceUsed post nonce := by
  -- Proof showing nonce atomic consumption
```

### 3. Instruction Binding Correctness
```lean
theorem tx_hash_binding (intent : IntentPayload) (tx_data : List U8)
    (h_commit : intent.tx_hash = sha256 tx_data) :
    -- Any modification to tx_data changes the hash
    ∀ tx_data' : List U8, tx_data' ≠ tx_data → sha256 tx_data' ≠ intent.tx_hash := by
  -- Collision resistance assumption
```

## Suggested Verification Scope

| Component | Property | Priority | Effort |
|-----------|----------|----------|--------|
| nonce_account.rs | Nonce initialization atomicity | High | Low |
| verify_and_execute.rs | Access control correctness | High | Medium |
| verifier.rs | Pairing equation completeness | Medium | High |
| register_agent.rs | Attestation verification | High | Medium |
| update_policy.rs | State consistency after update | Medium | Low |
