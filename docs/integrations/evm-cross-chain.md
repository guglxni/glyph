# Integration: EVM Cross-Chain Port

Out-of-scope integration design for GLYPH v3+. Tracks how the GLYPH
verifier could be ported to EVM ecosystems while preserving the
canonical primitives.

## 1. Paper Reference

- Tobin South, *Private, Verifiable, and Auditable AI Systems*
  (arXiv:2509.00085) — **out of scope in thesis.** The thesis is
  chain-agnostic in its specification (it sketches "small attestations"
  hash-linked into an audit chain, per Chapter 5 *"Holographic graph
  logs"*) but does not commit to any specific blockchain. The thesis
  mentions blockchains only twice:
  - `verifyevals.tex` notes that *"this zero-knowledge aggregation step
    makes sense when posting model inferences to a blockchain"* — but
    no design is given.
  - Chapter 4 cites `buterin_what_2023` for blockchain-anchored
    credentials in a single sentence.
- **GLYPH's contribution** (per `audit/PAPER_BRIEF.md` §6) is precisely
  the on-chain instantiation: a Solana program that verifies, stores
  policy commitments, and enforces replay protection. Porting that to
  EVM is a natural extension to broaden where verifiable agent
  delegation can land.

External grounding (verify chain-specific details before implementing):
- EVM precompiles `ecadd` (0x06), `ecmul` (0x07), `ecpairing` (0x08)
  for BN254 — gas costs codified in EIPs 1108 / 2565.
- LayerZero v2, Wormhole NTT, Axelar GMP — all live cross-chain
  messaging protocols; trust assumptions vary materially.

## 2. Current GLYPH State

GLYPH is **Solana-only**:
- `programs/glyph-verifier/` is an Anchor program (`Cargo.toml` declares
  `anchor-lang`).
- On-chain state is held in PDAs (`AgentRegistry`, `NonceAccount`,
  `RelayAccount`).
- Groth16 BN254 verification uses Solana's `alt_bn128_pairing` syscall.
- The Ed25519 delegator signature is verified via the
  `Ed25519Program` sibling-instruction precompile.

Importantly, the **canonical encoding crate (`common/`) is already
chain-agnostic**. `delegation_signing_payload`, `intent_hash`,
`policy_commitment` are all big-endian / little-endian explicit, ASCII
prefixed, and contain no Solana-specific types. This was a deliberate
design choice that makes the EVM port mechanical.

## 3. Proposed Integration

Port the verifier to Solidity, preserving the canonical encoding:

1. **`glyph-verifier.sol`** — Solidity contract that mirrors the Anchor
   program. Uses `ecadd` / `ecmul` / `ecpairing` precompiles for BN254
   Groth16 verification. EVM's pairing precompile is significantly
   cheaper-per-pairing than Solana's `alt_bn128_pairing` syscall and
   doesn't have Solana's compute-unit budget.
2. **PDA → ERC-721-style registry.** Each registered agent is a
   non-transferable token (NFT-shaped registry entry) keyed by the
   `agent_pubkey`. `register_agent` mints; `deregister_agent` burns or
   sets a tombstone bit.
3. **Nonce PDA → mapping.** Solana's "create-PDA-as-spend" anti-replay
   pattern maps cleanly to EVM's `mapping(bytes32 => bool) consumedNonces`
   with a single SSTORE per intent.
4. **Ed25519 signature.** EVM has no native Ed25519 precompile (Solana
   does). Options:
   - **EIP-7212-style precompile** (P-256 is closer to landing than
     Ed25519; verify current EIP status before committing).
   - **In-EVM Ed25519 verifier** — expensive (~hundreds of thousands of
     gas).
   - **Switch to secp256k1** for the delegator signature in the EVM
     deployment — uses cheap `ecrecover` (~3k gas). This breaks
     cross-chain key compatibility (a delegator can no longer use the
     same key for Solana and EVM agents), which may be acceptable.
5. **Cross-chain attestation bridging.** Attestation evidence (Nitro /
   SGX / NRAS) is already on-chain on Solana as a hash; bridging it to
   EVM via LayerZero / Wormhole / Axelar carries that hash forward.
   Verifying the bridge's own trust assumption is required — these
   are not zero-trust bridges.

The encoding (`common/`) ships unchanged. EVM contracts read the same
byte layouts.

## 4. Wire Format / API Surface

Canonical encoding (chain-agnostic; already in `common/`) is unchanged.
Solidity-side ABI:

```solidity
struct PublicInputs {
    bytes32 policyCommitment;
    bytes32 intentHash;
    bytes32 agentPubkey;
    uint64  nonce;
    bytes32 txHash;
}

interface IGlyphVerifier {
    function registerAgent(RegisterAgentArgs calldata args) external;
    function verifyAndExecute(
        bytes calldata proof,
        PublicInputs calldata publicInputs,
        bytes calldata targetCalldata
    ) external;
    function updatePolicy(/* … */) external;
    function deregisterAgent(/* … */) external;
}
```

Cross-chain message format (LayerZero / Wormhole payload):

```text
"GLYPH:XCHAIN:v1:"  (16 bytes ASCII)
‖ src_chain_id       (8 LE u64)
‖ dst_chain_id       (8 LE u64)
‖ agent_pubkey       (32)
‖ policy_commitment  (32)
‖ attestation_hash   (32)
```

The receiving chain stores this in a mirror registry; the bridge's
guardian set / DVN configuration determines trust.

## 5. Implementation Plan / Workstream

- **Owner:** `glyph-evm/` — new repo. **v3 deliverable.**
- **Phases:**
  1. Solidity port of the Groth16 BN254 verifier. Reference: the
     `RISC-Zero/risc0-ethereum` Solidity verifier — already exists and
     is well-tested; can be reused largely as-is.
  2. ERC-721-style agent registry contract; Foundry test suite mirroring
     the Anchor tests.
  3. Decide Ed25519 vs secp256k1 for the delegator signature. If
     Ed25519, integrate a vetted in-EVM verifier (e.g.,
     `solana-bridges`-style implementations) and benchmark gas.
  4. Choose L2 target (Optimism / Arbitrum / Base / zkSync) — L1 EVM
     gas for the pairing alone (~113k gas per pairing per EIP-1108,
     plus per-input costs) makes L1 too expensive for routine
     verification. L2s drop this by ~10×-100×.
  5. Cross-chain message-passing PoC via one bridge (LayerZero or
     Wormhole). Trust-model documentation must accompany the choice.
- **Out of scope:** porting the TEE worker. The worker is Rust today
  and stays Rust; the only change is that it emits a transaction
  targeting the EVM verifier contract instead of the Solana program.

## 6. Risks & Trade-offs

- **L1 pairing gas is expensive.** A full Groth16 BN254 verification
  on Ethereum L1 costs ~500k gas (one pairing check plus multiple G1
  multiplications); at recent gas prices this is dollars-per-verify.
  L2 deployment is essentially mandatory for production.
- **Bridge trust assumption is the weakest link.** LayerZero relies on
  DVN configuration; Wormhole on a 19-guardian set; Axelar on validator
  PoS. Each adds an honest-majority assumption that GLYPH-on-Solana
  does not have. Document this explicitly per deployment.
- **Ed25519 vs secp256k1 split-brain.** If the EVM deployment uses
  secp256k1 for delegator signatures, an end user has *two different
  delegator identities* — one per chain. This is operationally messy.
  EIP-7212 (P-256 precompile) is closer but still not Ed25519. The
  cleanest fix is a future EVM Ed25519 precompile; until then, the
  in-EVM verifier path with its gas cost is the alternative.
- **Coprocessor / Bonsai-relay pattern.** For heavier proving systems
  (Halo2/KZG, STARKs) the EVM verifier becomes prohibitive even on
  L2. The RISC Zero Bonsai relay pattern (submit proof off-chain,
  receive a small on-chain attestation) is the practical bridge —
  this also makes the cross-chain story easier (Bonsai posts to any
  chain).
- **Encoding stability is load-bearing.** The whole port works because
  `common/` is byte-stable and chain-agnostic. Any future Solana-side
  encoding change must be reflected on EVM — versioning the encoding
  prefix (`v1:`, `v2:`) is the right discipline and is already in
  place.
- **State proof gaps.** Solana's PDA model is account-centric; EVM's
  is contract-storage-centric. The semantic mapping is direct for
  agent registries and nonces but does not match for large relay
  accounts (`RelayAccount`); the EVM equivalent would be calldata or
  off-chain proof relay, not on-chain storage.
- **Out of scope until Solana side is rock-solid.** GLYPH's
  differentiator is the Solana on-chain story; an EVM port dilutes
  focus until v1/v2 of the Solana side has shipped and audited.
