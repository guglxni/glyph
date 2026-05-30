# GLYPH Protocol Verification Spec v1.0

The GLYPH protocol enables AI agents to execute transactions through a TEE (Trusted Execution Environment) worker with Zero-Knowledge proof verification on Solana.

## 0. Security Goals

### SG1: Agent Authorization
**SG1-ONLY-ACTIVE-AGENTS**: Only agents registered as active in the AgentRegistry MUST be able to execute transactions through `verify_and_execute`.

### SG2: Identity Binding
**SG2-SIGNER-MATCHES-AGENT**: The transaction signer MUST match the `agent_pubkey` stored in the AgentRegistry for the executing agent.

### SG3: Replay Prevention
**SG3-NONCE-CONSUMPTION**: Each nonce MUST be consumed exactly once per epoch. Reusing a nonce in the same epoch MUST fail.

### SG4: Policy Integrity
**SG4-POLICY-COMMITMENT**: The policy commitment in the ZK proof's public inputs MUST match the policy commitment stored in the agent's registry.

### SG5: Proof Verification
**SG5-ZK-VERIFICATION**: The Groth16 proof MUST verify against the canonical verification key for the GLYPH circuit.

### SG6: Transaction Binding
**SG6-TX-HASH-BINDING**: The transaction hash committed in the ZK proof MUST match the hash of the actual next instruction in the transaction.

### SG7: Arithmetic Safety
**SG7-NO-OVERFLOW**: All arithmetic operations MUST be protected against overflow/underflow.

## 1. State Model

### 1.1 AgentRegistry
```rust
struct AgentRegistry {
    pub authority: Pubkey,               // Account authority (signer for updates)
    pub agent_pubkey: Pubkey,            // The agent's signing key
    pub policy_commitment: [u8; 32],     // Hash of the policy
    pub attestation_hash: [u8; 32],      // TEE attestation
    pub policy_epoch: u32,               // Current policy epoch
    pub is_active: bool,                 // Activation status
}
```

### 1.2 NonceAccount
```rust
struct NonceAccount {
    pub nonce: [u8; 32],                 // Unique nonce
    pub agent_pubkey: Pubkey,            // Agent that owns this nonce
    pub policy_epoch: u32,               // Epoch for replay protection
}
```

### 1.3 InstructionsSysvar
The transaction introspection sysvar allows reading other instructions in the same transaction.

## 2. Operations

### 2.1 verify_and_execute
**Signers**: The agent's keypair (must match registry.agent_pubkey)

**Preconditions**:
1. AgentRegistry exists and is_active = true
2. AgentRegistry.agent_pubkey = transaction signer
3. Nonce has not been used in current epoch
4. Policy commitment matches between proof and registry

**Effects**:
1. Load next instruction from Instructions sysvar
2. Compute SHA-256 hash of next instruction data
3. Verify hash matches public_outputs.tx_hash
4. Verify Groth16 proof with canonical VK
5. Create NonceAccount PDA (atomic replay prevention)
6. CPI to target program with next instruction data

**Postconditions**:
1. NonceAccount exists at deterministic PDA
2. Target program instruction has executed

## 3. Formal Properties

### 3.1 Access Control

**AC1-ActiveAgentOnly**:
For all contexts ctx,
if verifyAndExecuteTransition(ctx) ≠ none
then ctx.registry.is_active = true.

**AC2-AgentIdentityBinding**:
For all contexts ctx,
if verifyAndExecuteTransition(ctx) ≠ none
then ctx.signer = ctx.registry.agent_pubkey.

### 3.2 Replay Protection

**RP1-NonceAtomicity**:
For all states pre, post, agent, nonce n, epoch e,
if verifyAndExecuteWithNonce(pre, agent, n, e) = some(post)
then nonceUsed(pre, n, e) = false ∧ nonceUsed(post, n, e) = true.

**RP2-EpochIsolation**:
For all nonces n, epochs e1, e2,
if e1 ≠ e2 then noncePDA(n, e1) ≠ noncePDA(n, e2).

**RP3-DoubleSpendPrevention**:
For all states s1, s2, agent, nonce n, epoch e,
if verifyAndExecuteWithNonce(s1, agent, n, e) = some(s2)
then verifyAndExecuteWithNonce(s2, agent, n, e) = none.

### 3.3 Policy Binding

**PB1-PolicyBinding**:
For all vk, registry, proof, public_inputs, journal_bytes,
if verifyAndExecuteVerify(vk, registry, proof, public_inputs, journal_bytes) ≠ none
then public_inputs.policy_commitment = registry.policy_commitment.

**PB2-VKIntegrity**:
For all verification functions f, VKs vk1, vk2, proofs p, journals j,
if f(vk1, p, j) ≠ f(vk2, p, j)
then vk1 ≠ vk2.

### 3.4 Instruction Binding

**IB1-TxHashIntegrity**:
For all sysvar, public_outputs, instruction,
if verifyTxBinding(sysvar, public_outputs) = some(instruction)
then sha256(instruction) = public_outputs.tx_hash.

**IB2-SubstitutionPrevention**:
For all sysvar, public_outputs, instruction, instruction',
if verifyTxBinding(sysvar, public_outputs) = some(instruction)
and instruction' ≠ instruction
and sha256(instruction') = public_outputs.tx_hash
and sha256 is collision-resistant
then False.

## 4. Trust Boundary

### 4.1 Axiomatic Components
- **SHA-256**: Assumed collision-resistant (cryptographic axiom)
- **Groth16**: Assumed sound (proof system axiom)
- **alt_bn128**: Solana syscalls assumed correct
- **Solana runtime**: Transaction execution model assumed correct

### 4.2 TEE-Enforced Properties (out of circuit)
- `time_window`: Requires real-time clock (not in circuit)
- `daily_volume`: Requires cross-request state (not in circuit)
- `allowed_token_mints`: Requires token account introspection (not in circuit)

## 5. Verification Results

| Property | Status | Proof |
|---|---|---|
| AC1-ActiveAgentOnly | **In Progress** | Proofs/AccessControl.lean |
| AC2-AgentIdentityBinding | **In Progress** | Proofs/AccessControl.lean |
| RP1-NonceAtomicity | **In Progress** | Proofs/ReplayProtection.lean |
| RP2-EpochIsolation | **In Progress** | Proofs/ReplayProtection.lean |
| RP3-DoubleSpendPrevention | **In Progress** | Proofs/ReplayProtection.lean |
| PB1-PolicyBinding | **In Progress** | Proofs/PolicyBinding.lean |
| PB2-VKIntegrity | **In Progress** | Proofs/PolicyBinding.lean |
| IB1-TxHashIntegrity | **In Progress** | Proofs/InstructionBinding.lean |
| IB2-SubstitutionPrevention | **In Progress** | Proofs/InstructionBinding.lean |
