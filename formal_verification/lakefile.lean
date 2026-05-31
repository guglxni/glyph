import Lake
open Lake DSL

-- GLYPH on-chain verifier — formal verification (Lean 4).
-- Vendored support library (no Mathlib dependency: the proofs use only the
-- QEDGen.Solana model + core Lean, so `lake build` is fast and reproducible).
require qedgenSupport from "lean_solana"

package Proofs where
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩,
    ⟨`pp.proofs.withType, false⟩
  ]

@[default_target]
lean_lib Proofs
