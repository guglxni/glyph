# Repository Map

Start here when you need to orient quickly.

## Frontend

- `web/app/page.tsx` - homepage narrative, thesis positioning, trust stack, live sections.
- `web/components/PolicyCompiler.tsx` - BYOK natural-language to policy compiler UI.
- `web/components/LlmSettings.tsx` - provider settings, API key handling, model controls.
- `web/lib/policyCompiler.ts` - deterministic schema guard and TOML rendering.
- `web/lib/glyph.ts` - TypeScript canonical policy serialization, hashing, and browser evaluator.

## Circuit And Prover

- `circuits/glyph-circuit/guest/src/main.rs` - stateless policy rules executed in zkVM.
- `circuits/glyph-circuit/host/src/lib.rs` - host proof generation and journal handling.
- `circuits/glyph-circuit/host/tests/integration.rs` - parity and journal round-trip tests.
- `scripts/extract-vk/` - real verification-key extraction after circuit build.

## TEE Worker

- `tee-worker/src/policy.rs` - off-chain rule enforcement, including stateful rules.
- `tee-worker/src/prover.rs` - `DevProver` and `RiscZeroProver` boundary.
- `tee-worker/src/transaction_builder.rs` - verifier instruction construction.
- `tee-worker/src/vendors/` - Nitro, SGX, and SEV attestation provider boundaries.

## Solana Program

- `programs/glyph-verifier/src/instructions/verify_and_execute.rs` - verification and execution path.
- `programs/glyph-verifier/src/groth16/verifier.rs` - BN254 pairing verifier.
- `programs/glyph-verifier/src/groth16/vk.rs` - seeded VK data and integrity hash.
- `programs/glyph-verifier/src/lib.rs` - public program interface and instruction hashing.

## Docs And Claims

- `README.md` - public technical overview and citation.
- `docs/production-migration-blueprint.md` - hardening plan and thesis mapping.
- `docs/CAPSTONE_GAPS.md` - honest remaining gaps.
- `docs/integrations/` - thesis-aligned future integration designs.
