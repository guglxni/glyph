# GLYPH Invariants

Use this checklist before committing GLYPH changes.

## Policy And Commitment

- Preserve canonical serialization order.
- Reject unknown policy keys in generated policy objects.
- Clamp generated numeric ranges deterministically.
- Keep SOL-to-lamports conversion exact and explicit.
- Maintain TypeScript/Rust parity tests when changing policy structures.

## Proof Contract

- Journal bytes are part of the public contract. Keep Borsh encoding unless all consumers migrate together.
- Public input to Groth16 is `SHA-256(journal_bytes)`.
- Circuit changes require rerunning proof/VK extraction and updating verifier expectations.
- If the final proof run is slow or fails, report the actual run id, step, elapsed time, and log clue.

## On-chain Enforcement

- Keep full instruction binding: program id, accounts, and data.
- Keep policy commitment and agent pubkey checks before execution.
- Keep nonce PDA replay protection in the verifier transaction path.
- Add compute-budget instructions for verifier calls that need high CU.

## Production Truthfulness

- Do not present dev-mode proof generation as a production proof.
- Do not present seeded VK structure as a final proof unless it came from the compiled circuit.
- Distinguish local tests, CI proof success, live devnet accounts, and mainnet readiness.
- Document hardening gaps rather than hiding them.

## Frontend Claims

- If UI says "live", the backing endpoint/account should be queried live or the copy should say "demo".
- If UI says "implementation of arXiv:2509.00085", tie it to the concrete pipeline: delegation, policy, TEE, ZK proof, verifier.
- Avoid showing local absolute filesystem paths or local paper-source folders in public UI; link the article at `https://arxiv.org/abs/2509.00085`.
