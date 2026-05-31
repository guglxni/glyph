# Thesis Map

GLYPH implements the architecture class described by Tobin South, *Private, Verifiable, and Auditable AI Systems* (`arXiv:2509.00085`).

Use this mapping when explaining or extending the project:

| Thesis concept | Local source | GLYPH implementation |
| --- | --- | --- |
| Privacy, verifiability, auditability as the trust target | Article abstract | TEE policy checks, ZK proof output, and on-chain audit trail |
| Verifiable and auditable claims with zero-knowledge cryptography | Chapter 2 | RISC Zero guest/host and Groth16 verifier |
| Confidential deployment with TEEs/MPC | Chapter 3 | `tee-worker/src/`, vendor attestation modules, production mode guard |
| Authenticated delegation and scoped permissions for agents | Chapter 4 | wallet/PDA identity, policy DSL, agent registry, delegation docs |
| Layered accountability architecture | Chapter 5 | hardware -> cryptography -> consensus enforcement stack |

Important phrasing:

- Good: "GLYPH instantiates the thesis's layered accountability architecture as Solana infrastructure."
- Good: "This is a concrete implementation aligned with arXiv:2509.00085."
- Avoid: "The thesis specifies every GLYPH implementation detail." Some bindings are GLYPH proposals where the thesis is high-level.
- Avoid: "All future hardening items are complete." Keep KMS sealing, SGX DCAP, SNP verification, and stateful-in-circuit rules honest.
