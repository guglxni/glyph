#![no_main]

use glyph_common::{
    canonical_intent_preimage, canonical_serialize_policy, sha256, verify_mint_merkle_path,
    CircuitFailureCode, IntentPayload, MerklePath, Policy, PublicOutputs,
    RULE_BIT_ALLOWED_PROGRAMS,
    RULE_BIT_ALLOWED_TOKEN_MINTS, RULE_BIT_DAILY_VOLUME, RULE_BIT_MAX_ACCOUNTS,
    RULE_BIT_MAX_LAMPORTS, RULE_BIT_POLICY_EXPIRY, RULE_BIT_REQUIRE_SIGNER, RULE_BIT_SLIPPAGE,
    RULE_BIT_TIME_WINDOW, SECONDS_PER_DAY,
};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

/// Wire-format extension of the IntentPayload that the WS-8 guest needs in
/// order to enforce the formerly-TEE-side rules. The host writes this as
/// `Vec<[u8; 32]>` for token mints, plus a flag for "is signer present"
/// (rule 8 cannot be reconstructed from the compact `IntentPayload` alone).
#[derive(serde::Serialize, serde::Deserialize)]
struct IntentExtras {
    /// Token mints the intent claims, if any. Each must Merkle-prove against
    /// `allowed_token_mints_root`. None means the intent did not claim any
    /// token-mint constraint.
    allowed_tokens: Option<Vec<[u8; 32]>>,
    /// At least one of the instruction account-metas had `is_signer == true`.
    has_signer: bool,
    /// Inclusion proofs (one per allowed_tokens entry, parallel ordering).
    mint_inclusion_proofs: Vec<MerklePath>,
}

fn main() {
    // Private inputs
    let intent: IntentPayload = env::read();
    let policy: Policy = env::read();
    let tx_bytes: Vec<u8> = env::read();
    let extras: IntentExtras = env::read();

    // Public inputs
    let expected_policy_commitment: [u8; 32] = env::read();
    let image_id: [u32; 8] = env::read();
    let attested_timestamp: u64 = env::read();
    let prior_daily_total: u64 = env::read();
    let allowed_token_mints_root: [u8; 32] = env::read();

    let daily_bucket_id = attested_timestamp / SECONDS_PER_DAY;

    // 1. Verify policy commitment
    let policy_commitment = sha256(&canonical_serialize_policy(&policy));

    let mut bitmap: u32 = 0;
    let mut failure: CircuitFailureCode = CircuitFailureCode::None;

    // The order below is significant: we record bitmap progression even on
    // failure so the verifier can see WHICH rule triggered. Once `failure`
    // is non-None we stop recording further rules (the verifier rejects on
    // any non-None code regardless).
    macro_rules! fail_with {
        ($code:expr) => {{
            if matches!(failure, CircuitFailureCode::None) {
                failure = $code;
            }
        }};
    }

    if policy_commitment != expected_policy_commitment {
        fail_with!(CircuitFailureCode::InvalidPolicyCommitment);
    }

    // ─── Rule 1: Max lamports per tx ────────────────────────────────────────
    bitmap |= RULE_BIT_MAX_LAMPORTS;
    if intent.max_lamports > policy.max_lamports_per_tx {
        fail_with!(CircuitFailureCode::MaxLamportsExceeded);
    }

    // ─── Rule 2: Allowed programs ───────────────────────────────────────────
    bitmap |= RULE_BIT_ALLOWED_PROGRAMS;
    if !policy.allowed_programs.is_empty()
        && !policy.allowed_programs.contains(&intent.target_program)
    {
        fail_with!(CircuitFailureCode::ProgramNotAllowed);
    }

    // ─── Rule 3: Time window — uses TEE-attested timestamp ─────────────────
    // The `attested_timestamp` is committed to the journal so the on-chain
    // verifier checks it against `Clock::unix_timestamp` (closes F-23 partial
    // for time_window).
    bitmap |= RULE_BIT_TIME_WINDOW;
    if let Some(window) = &policy.time_window {
        let secs_into_day = attested_timestamp % SECONDS_PER_DAY;
        let hour = (secs_into_day / 3600) as u8;
        let in_window = if window.start_hour_utc <= window.end_hour_utc {
            hour >= window.start_hour_utc && hour <= window.end_hour_utc
        } else {
            hour >= window.start_hour_utc || hour <= window.end_hour_utc
        };
        if !in_window {
            fail_with!(CircuitFailureCode::OutsideTimeWindow);
        }
    }

    // ─── Rule 4: Max daily volume ──────────────────────────────────────────
    // The TEE-attested `prior_daily_total` plus `intent.max_lamports` must not
    // exceed `policy.max_daily_volume_lamports`. The on-chain `DailyBucket`
    // PDA is read+written using `(prior_daily_total, daily_bucket_id)` to
    // enforce monotonicity (closes F-23 partial for daily_volume).
    bitmap |= RULE_BIT_DAILY_VOLUME;
    let projected = prior_daily_total.saturating_add(intent.max_lamports);
    if projected > policy.max_daily_volume_lamports
        || prior_daily_total.checked_add(intent.max_lamports).is_none()
    {
        fail_with!(CircuitFailureCode::DailyVolumeExceeded);
    }

    // ─── Rule 5: Slippage ───────────────────────────────────────────────────
    bitmap |= RULE_BIT_SLIPPAGE;
    if let Some(max_bps) = policy.max_slippage_bps {
        match intent.max_slippage_bps {
            Some(actual) if actual <= max_bps => {}
            _ => fail_with!(CircuitFailureCode::SlippageExceeded),
        }
    }

    // ─── Rule 6: Allowed token mints (Merkle inclusion against root) ───────
    bitmap |= RULE_BIT_ALLOWED_TOKEN_MINTS;
    if let Some(allowed) = &policy.allowed_token_mints {
        if !allowed.is_empty() {
            // Intent must specify mints AND each must Merkle-prove against
            // the policy-committed root.
            match &extras.allowed_tokens {
                None => fail_with!(CircuitFailureCode::TokenMintNotAllowed),
                Some(req) => {
                    if extras.mint_inclusion_proofs.len() != req.len() {
                        fail_with!(CircuitFailureCode::TokenMintNotAllowed);
                    } else {
                        for (mint, path) in req.iter().zip(extras.mint_inclusion_proofs.iter()) {
                            if !verify_mint_merkle_path(mint, path, &allowed_token_mints_root) {
                                fail_with!(CircuitFailureCode::TokenMintNotAllowed);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // ─── Rule 7: Max accounts per tx ───────────────────────────────────────
    bitmap |= RULE_BIT_MAX_ACCOUNTS;
    if let Some(max_accounts) = policy.max_accounts_per_tx {
        if intent.num_accounts > max_accounts {
            fail_with!(CircuitFailureCode::TooManyAccounts);
        }
    }

    // ─── Rule 8: Require signer present ────────────────────────────────────
    bitmap |= RULE_BIT_REQUIRE_SIGNER;
    if policy.require_signer_present && !extras.has_signer {
        fail_with!(CircuitFailureCode::NoSignerPresent);
    }

    // ─── Rule 9: Policy expiry ─────────────────────────────────────────────
    bitmap |= RULE_BIT_POLICY_EXPIRY;
    if policy.expires_at > 0 && intent.expiry > policy.expires_at {
        fail_with!(CircuitFailureCode::ExpiryExceeded);
    }
    // Also require a positive intent expiry so an old proof cannot be replayed
    // forever (closes F-22 partial). The verifier still checks
    // `expiry > Clock::unix_timestamp`.
    if intent.expiry == 0 {
        fail_with!(CircuitFailureCode::ExpiryExceeded);
    }

    // 3. Compute intent hash and tx hash
    let intent_hash = sha256(&canonical_intent_preimage(&intent));
    let tx_hash = sha256(&tx_bytes);

    // 4. Commit public outputs (always — even on failure — so the verifier
    //    can read `failure_code` and reject with the precise reason).
    let outputs = PublicOutputs {
        policy_commitment,
        intent_hash,
        agent_pubkey: intent.agent_pubkey,
        nonce: intent.nonce,
        tx_hash,
        expiry: intent.expiry,
        image_id,
        attested_timestamp,
        daily_bucket_id,
        prior_daily_total,
        circuit_rule_bitmap: bitmap,
        failure_code: failure as u8,
    };
    env::commit(&outputs);
}
