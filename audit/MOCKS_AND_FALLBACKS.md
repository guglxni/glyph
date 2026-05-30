# GLYPH — Mocks, Fallbacks, Dev-Mode Escape Hatches

**Date:** 2026-05-10
**Scope:** non-test code paths reachable in production builds. Pure-test occurrences dropped.
**Sweep tools:** ripgrep across `*.rs` / `*.ts` / `*.tsx` / `*.toml` / `*.sh`, excluding `target/`, `arXiv-2509.00085v1/`, `graphify-out/`, `node_modules/`, `**/.lake/`.

## Counts per category

| Category | Count |
| --- | --- |
| MOCK | 8 |
| DEV_MODE | 6 |
| FALLBACK | 9 |
| TODO | 0 *(grep-confirmed: zero TODO/FIXME/XXX/HACK comments in non-test source. The repo is unusually clean here — all such markers live in `audit/`, `docs/`, vendored docstrings under `target/doc/`, or `.agents/`)* |
| PLACEHOLDER | 11 |
| UNIMPLEMENTED | 0 *(no `unimplemented!`/`todo!`/`unreachable!` macros — but see panic chain in `tee-worker/src/main.rs` and the `bail!(" ... not yet implemented")` calls covered by AUDIT_TEE T1)* |
| ENV_BYPASS | 5 |
| DEAD_CODE | 4 |

**Already covered (do not re-flag below):**
- DevProver lifecycle, dev-key VK, `extract-vk` stub, `dev_mode_generate_proof_roundtrip` test → see AUDIT_ZK.md F-1, F-5, F-7, F-8, F-16, F-24, F-25, F-30
- Vendor TEE stubs (`Err("not yet implemented")` in nitro/sgx/sev), dev attestation passthrough, `daily_volume_tracker` host clock → see AUDIT_TEE.md T1, T3, T8, T9, T14, T15, T16
- DevProver indistinguishability of bundles → see AUDIT_ZK.md F-16
- Cross-language canonical mismatch and SDK transport plaintext → see AUDIT_SDK.md F-1, F-7

The findings below are the **delta** that the three other audits do not already enumerate, plus a small set of cross-cutting items called out so an operator has a single grep-friendly index.

---

## Findings table

| Sev | Cat | File:line | Description |
| --- | --- | --- | --- |
| HIGH | PLACEHOLDER | `programs/glyph-verifier/src/lib.rs:3` | `declare_id!("G1yPHveri1111111111111111111111111111111111")` is a vanity placeholder program ID. Same string is hardcoded in `Anchor.toml:6,9` and used as a fallback in `tee-worker/src/main.rs:102`. Mainnet deploy with this ID = anyone who deployed first owns the program account. |
| HIGH | PLACEHOLDER | `Anchor.toml:6` | `glyph_verifier = "G1yPHveri1111111111111111111111111111111111"` (localnet) — same string as above. |
| HIGH | PLACEHOLDER | `Anchor.toml:9` | `glyph_verifier = "G1yPHveri1111111111111111111111111111111111"` (devnet) — must be regenerated per environment. |
| HIGH | FALLBACK | `tee-worker/src/main.rs:99-103` | `GLYPH_VERIFIER_PROGRAM_ID` falls back to the same placeholder pubkey via `unwrap_or_else`. A misconfigured worker will silently sign bundles addressed to a non-existent or attacker-controlled program. |
| HIGH | FALLBACK | `tee-worker/src/main.rs:411-412` | `GLYPH_SOLANA_RPC_URL` defaults to `"https://api.mainnet-beta.solana.com"`. A mis-deployed staging/dev worker can submit real-money transactions to mainnet without explicit operator opt-in. |
| HIGH | DEAD_CODE | `programs/glyph-verifier/src/lib.rs:82, 292` + `verify_and_execute` body | `VerifierConfig.paused: bool` is initialized to `false` in `initialize()` but is **never read** by any instruction handler. The pause switch exists in storage but does nothing; an emergency stop is not actually wired. |
| HIGH | DEAD_CODE | `programs/glyph-verifier/src/lib.rs:305-334` (`register_agent`) | `register_agent` accepts a `tee_attestation: Vec<u8>`, hashes it, but does **not** call `verify_attestation_commitment` — that check exists only on `update_policy:361`. An attacker can register an agent with a fake/empty attestation that does not bind the policy_commitment. (AUDIT_TEE T2 notes the worker-side gap; this is the on-chain twin.) |
| HIGH | DEV_MODE | `tee-worker/src/types.rs:140-146` | `default_runtime_mode()` returns `RuntimeMode::Dev`. Combined with `tee-worker/src/main.rs:395-402` (typo'd `GLYPH_MODE` → Dev — also AUDIT_TEE T30), any deserialization or env miss silently degrades to dev mode. |
| HIGH | FALLBACK | `tee-worker/src/main.rs:384-393` | `GLYPH_TEE_VENDOR` defaults to `"sgx"` when unset. On a non-SGX host this auto-selects the dev-mode passthrough provider. (AUDIT_TEE T13 — included here for cross-index.) |
| MEDIUM | PLACEHOLDER | `tmp_hash.rs:1-46` | Stray standalone Rust file at repo root that **regenerates the placeholder VK_HASH** by feeding the dev VK constants into SHA-256. Not in `Cargo.toml`, not gated, not deleted. Operator who runs `cargo run --bin tmp_hash` and pipes into `vk.rs` re-bakes the placeholder. Delete or move to `scripts/`. |
| MEDIUM | DEV_MODE | `scripts/demo.sh:31-32` | `export GLYPH_MODE=dev; export GLYPH_PROVER=dev` set unconditionally. Demo script is committed; copy/paste hazard for operators who base prod systemd units on it. |
| MEDIUM | DEV_MODE | `scripts/demo.sh:24` | Demo silently swallows `anchor build` failure with `|| echo Warning ...`. A dev who sees green output may not notice the on-chain side never built. |
| MEDIUM | DEV_MODE | `scripts/demo.sh:56` | Embedded JS sets `connection: null, // Simulated` — a Node.js consumer copying this snippet ships a client that cannot submit on-chain. |
| MEDIUM | FALLBACK | `tee-worker/src/policy.rs:179-191` | `load_volume()` uses three nested `if let Ok(...)` — every error (missing file, unseal failure, malformed JSON) silently produces empty tracker, resetting daily-volume budget. AUDIT_TEE T12 already raises this; relisted because grep for "FALLBACK" should land here. |
| MEDIUM | FALLBACK | `tee-worker/src/main.rs:407-410` | `GLYPH_POLICY_PATH` / `GLYPH_KEYPAIR_PATH` / `GLYPH_LISTEN_ADDR` all default via `unwrap_or_else`. Loopback default `127.0.0.1:8088` is fine, but `policy.toml.sealed` and `worker-keypair.json` defaults silently land in the worker's CWD — different in dev vs systemd — leading to "wrong policy loaded" footguns. |
| MEDIUM | FALLBACK | `tee-worker/src/metrics.rs:130-132` | `GLYPH_METRICS_ADDR` defaults to `127.0.0.1:9091`. Setting to `0.0.0.0` works without warning — leaks operational telemetry to the public internet. (AUDIT_TEE T38 partially, repeated here for the env-bypass index.) |
| MEDIUM | DEAD_CODE | `programs/glyph-verifier/src/errors.rs:153` | `DevModeNotAllowed = 6090` error code is defined but never returned anywhere. Suggests a planned `Mode::Dev` rejection check that wasn't wired. |
| MEDIUM | DEAD_CODE | `programs/glyph-verifier/src/errors.rs:135` | `InsufficientComputeBudget = 6070` error code is defined but never returned (also called out in AUDIT_ZK F-13). |
| MEDIUM | MOCK | `examples/intent.json:3,12` | `agent_pubkey` and `accounts[0].pubkey` are both `"11111111111111111111111111111111"` (System Program ID). An operator who copy/pastes this fixture into staging is signing intents *as the System Program* — the worker will reject, but the canonical example invites confusion. |
| MEDIUM | MOCK | `examples/policy.toml:13` | `allowed_programs = ["11111111111111111111111111111111"]` — the System Program. A no-op allowlist; a copy/paste prod policy that grants nothing useful and yet looks plausible. |
| MEDIUM | MOCK | `examples/policy.toml:24` | `allowed_token_mints = ["So11111...112"]` — wSOL only. Fine as an example, hazardous as a default. |
| MEDIUM | ENV_BYPASS | `tee-worker/src/main.rs:121-126` | `RuntimeMode::Staging` only emits `tracing::warn!("Running in STAGING mode ...")` — no enforcement that DevProver is forbidden, no enforcement that real attestation is on. Anyone who flips `GLYPH_MODE=staging` gets dev-equivalent behaviour with no friction. |
| MEDIUM | ENV_BYPASS | `tee-worker/src/main.rs:50-55` | Production check enforces only `RISC0_DEV_MODE` is unset for the **risc0** side. There is no equivalent rejection for `GLYPH_PROVER=dev` *plus* `--features risc0` co-existing — production mode panics earlier (`main.rs:43-47`), but Staging silently allows the combination. |
| MEDIUM | PLACEHOLDER | `programs/glyph-verifier/src/groth16/vk.rs:75-87` | 13-line "CRITICAL SECURITY WARNING" banner explicitly says the VK is a placeholder. Banner exists; no compile-time assertion enforces it. (AUDIT_ZK F-1 covers this at depth — flagged again so a grep for "placeholder" in source lands here.) |
| MEDIUM | PLACEHOLDER | `programs/glyph-verifier/src/groth16/vk.rs:195-202` | `GLYPH_VK_HASH` is a "DEV: This is a dummy hash" constant. Detection branch at line 219 (`if GLYPH_VK_HASH == [0u8; 32]`) is dead code because `verify_vk_integrity()` is never called — see AUDIT_ZK F-3. |
| LOW | MOCK | `circuits/glyph-circuit/host/tests/integration.rs:168` | `let tx_data = b"mock_instruction_data".to_vec();` — test-only. Listed because the function `test_dev_prover_signing_and_verification` it lives in is reused by the workspace integration test (`tests/integration/pipeline_tests.rs`) which is *not* gated `#[cfg(test)]` — both crates produce a real binary's test artifact. Not exposed to prod, but the harness boundary is thinner than it looks. |
| LOW | MOCK | `tee-worker/src/prover.rs:191-203` | `DevProver` constructs a "fake but structurally valid" journal with all-zero `tx_hash`. Already AUDIT_ZK F-16; relisted because this comment block contains the only in-source string `"fake"` outside tests. |
| LOW | DEV_MODE | `tee-worker/src/types.rs:117-126` | Doc-comment lists production requirements (`GLYPH_PROVER=risc0`, `RISC0_DEV_MODE` unset, attestation real) but those are enforced **only** in `tee-worker/src/main.rs:34-58`, which is hand-rolled and grep-only. No central `enforce_production_invariants(&config)` function. Adding/removing a check requires touching the panic chain by hand. |
| LOW | FALLBACK | `tee-worker/src/main.rs:374` | `RUST_LOG` defaults to `"glyph_tee_worker=info,info"`. Leaking `info`-level logs by default is fine but a typo'd custom value (e.g. `RUST_LOG=of`) silently disables logging. Harmless on its own; combined with T20 (no audit log) the operator has no signal a worker is mis-tracing. |
| LOW | FALLBACK | `sdk/rust/src/client.rs:107-117` | `normalize_tee_endpoint` strips `tcp://`, `http://`, `https://` and treats them all as raw `host:port` for an unauthenticated TCP socket. AUDIT_SDK F-7 already raises the security gap; the silent-protocol-downgrade is the hazard for this audit. |
| LOW | FALLBACK | `tee-worker/src/main.rs:374-375` | `unwrap_or_else(|_| "glyph_tee_worker=info,info".into())` — `RUST_LOG` parse failure returns the default. `EnvFilter::try_new` on a malformed value silently degrades. |
| LOW | ENV_BYPASS | `tee-worker/src/main.rs:380-381` | `GLYPH_WORKER_CONFIG` env-var allows pointing to an arbitrary config file; no validation that the path is sealed, owned by the worker user, or under a known directory. |
| LOW | ENV_BYPASS | `tee-worker/src/main.rs:395-402` | `GLYPH_MODE` accepts `production`, `prod`, `staging`; everything else maps to `Dev`. Already AUDIT_TEE T30 — relisted under ENV_BYPASS for the index. |
| LOW | DEAD_CODE | `programs/glyph-verifier/src/groth16/vk.rs:216-234` | `verify_vk_integrity()` is `pub fn`, defined, never called. AUDIT_ZK F-3. |
| INFO | MOCK | `sdk/typescript/src/__tests__/sdk.test.ts:17` | `const DUMMY_DATA = Buffer.from('transfer_data').toString('base64')` — test only, exposed to prod via the published TS SDK if the test file is shipped (check `tsconfig`/`files` → the build excludes `__tests__/`). Confirmed test-only; logged for completeness. |

---

## Cross-references already covered (do not re-flag)

- AUDIT_ZK.md F-1 — placeholder Groth16 VK
- AUDIT_ZK.md F-3 — `verify_vk_integrity` dead code
- AUDIT_ZK.md F-5 — DevProver in production binary
- AUDIT_ZK.md F-7 — empty `GLYPH_CIRCUIT_ELF` without `risc0` feature
- AUDIT_ZK.md F-8 — zero `GLYPH_CIRCUIT_ID`
- AUDIT_ZK.md F-13 — compute budget set client-side only
- AUDIT_ZK.md F-16 — DevProver indistinguishable bundles
- AUDIT_ZK.md F-18 — verifier never checks `Clock`
- AUDIT_ZK.md F-24 / F-25 — extract-vk stub + non-risc0 placeholder fallback
- AUDIT_ZK.md F-30 — `GLYPH_IMAGE_ID` ASCII tag
- AUDIT_TEE.md T1 — vendor `attest`/`verify_attestation`/`seal`/`unseal` stubs
- AUDIT_TEE.md T2 — `provider.attest()` never called by worker pipeline
- AUDIT_TEE.md T3 — identity-passthrough `seal`/`unseal` in dev
- AUDIT_TEE.md T4 — `is_real_enclave` auto-detect with no production gate
- AUDIT_TEE.md T8 / T9 / T34 — host-clock daily-volume / time-window
- AUDIT_TEE.md T12 — `load_volume` swallows errors
- AUDIT_TEE.md T13 / T30 — `GLYPH_TEE_VENDOR` / `GLYPH_MODE` typo downgrade
- AUDIT_TEE.md T14 / T15 / T16 — 32-byte sliding-window attestation match
- AUDIT_SDK.md F-1 — Rust/TS canonical `max_lamports` mismatch
- AUDIT_SDK.md F-7 — SDK accepts `https://` and silently downgrades to TCP

---

## Highest-priority delta items (not in other audits)

1. **`declare_id!` placeholder + `Anchor.toml` placeholders + worker fallback** (HIGH): three independent files share `G1yPHveri111...`. Generate a real keypair, run `solana-keygen pubkey -o target/deploy/glyph_verifier-keypair.json`, paste, commit. Fail the worker startup if `verifier_program_id == placeholder` in any non-Dev mode.
2. **`register_agent` does not call `verify_attestation_commitment`** (HIGH): on-chain twin of AUDIT_TEE T2. Add the call before `registry.policy_commitment = ...` and refuse registration on failure.
3. **`config.paused` unused** (HIGH): wire `require!(!ctx.accounts.config.paused, GlyphError::Paused)` into `verify_and_execute`, `register_agent`, `update_policy`. Add a `pause`/`unpause` instruction guarded by `config.authority`. Without this, there is no working circuit-breaker.
4. **`tmp_hash.rs` at repo root** (MEDIUM): delete or move to `scripts/`. Today it's a one-command path back to the placeholder hash.
5. **`scripts/demo.sh` exports `GLYPH_MODE=dev`/`GLYPH_PROVER=dev` and silently ignores anchor-build failures** (MEDIUM): document that this is demo-only at the top of the file; consider adding an `if [ "$1" != "--demo-only" ]; then exit 1; fi` guard.
6. **`Staging` runtime mode is not enforced** (MEDIUM): treat `Staging` as "production-with-extra-logging", not "dev-with-warning". Today an operator can set `GLYPH_MODE=staging` and bypass the `RISC0_DEV_MODE`/`GLYPH_PROVER=risc0` checks that `Production` enforces.
7. **Dead `DevModeNotAllowed = 6090` error code** (MEDIUM): either return it from the verifier when public-input fields suggest a dev bundle (e.g., zero `tx_hash`), or remove from the enum so the surface stays honest.
