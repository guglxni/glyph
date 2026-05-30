import Lake
open Lake DSL

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.15.0"

-- Use the local copy of qedgen's lean_solana support library
require qedgenSupport from
  "/Users/aaryanguglani/.agents/skills/qedgen/lean_solana"

package Proofs where
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩,
    ⟨`pp.proofs.withType, false⟩
  ]

-- Build the proof library (no executable needed)
@[default_target]
lean_lib Proofs
