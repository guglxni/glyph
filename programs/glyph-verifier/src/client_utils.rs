//! Client-side utilities for transaction construction (off-chain only)
#![cfg(not(target_os = "solana"))]

use solana_program::{instruction::Instruction, compute_budget::ComputeBudgetInstruction};

/// Minimum compute budget required for Groth16 verification
/// 1.4M CU covers the four alt_bn128_pairing calls plus account operations
pub const MIN_COMPUTE_BUDGET: u32 = 1_400_000;

/// Creates a ComputeBudget instruction setting the CU limit to the minimum required
/// for Groth16 verification.
/// 
/// Use this helper when constructing transactions that call `verify_and_execute`.
/// 
/// # Example
/// ```rust
/// let compute_budget_ix = glyph_verifier::client_utils::compute_budget_ix();
/// let verify_ix = instruction::verify_and_execute(...);
/// let tx = Transaction::new_with_payer(&[compute_budget_ix, verify_ix], Some(&payer));
/// ```
pub fn compute_budget_ix() -> Instruction {
    ComputeBudgetInstruction::set_compute_unit_limit(MIN_COMPUTE_BUDGET)
}

/// Creates a ComputeBudget instruction with custom CU limit.
pub fn compute_budget_ix_with_limit(cu_limit: u32) -> Instruction {
    ComputeBudgetInstruction::set_compute_unit_limit(cu_limit)
}

/// Creates a priority fee instruction (micro-lamports per CU).
pub fn priority_fee_ix(micro_lamports_per_cu: u64) -> Instruction {
    ComputeBudgetInstruction::set_compute_unit_price(micro_lamports_per_cu)
}
