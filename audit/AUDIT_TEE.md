# GLYPH TEE Worker — Production-Readiness Audit

**Auditor:** Claude (Opus 4.7, 1M context)
**Date:** 2026-05-10
**Scope:**
- Entry / RPC server: `tee-worker/src/main.rs`
- Library root: `tee-worker/src/lib.rs`
- Policy DSL evaluator: `tee-worker/src/policy.rs`
- Wire / config / proof bundle types: `tee-worker/src/types.rs`
- Prover invocation: `tee-worker/src/prover.rs`
- On-chain transaction builder: `tee-worker/src/transaction_builder.rs`
- Vendor TEE adapters: `tee-worker/src/vendors/{mod.rs, nitro.rs, sgx.rs, sev.rs}`
- Metrics exposure: `tee-worker/src/metrics.rs`
- Policy integration tests: `tee-worker/tests/policy_tests.rs`

**Cross-references:**
- `docs/SECURITY_AUDIT.md` — three prior findings, all marked PATCHED (Findings #1 / #2 / #3 below).
- `docs/production-migration-blueprint.md` — WS-3 ("Attestation Path Completion"), WS-4 ("Policy and State Completeness"), WS-8 ("Observability").
- `audit/AUDIT_ZK.md` — companion audit covering circuit / verifier / VK.
- `audit/PAPER_BRIEF.md` — Tobin South thesis section on TEE / attestation requirements.

---

## Summary table

| # | Severity | Cat | Finding | New / Known |
| --- | --- | --- | --- | --- |
| T1 | **CRITICAL** | A,B,C,D | All three TEE vendor providers (`Nitro`, `Sgx`, `Sev`) ship with the production `attest`, `verify_attestation`, `seal`, `unseal` paths returning `Err("not yet implemented")`; only the dev path produces values | Acknowledged in WS-3 / blueprint §4.3, but **flagged as stubs not safe** here |
| T2 | **CRITICAL** | E,H | The runtime *never* invokes `provider.attest()` or `provider.verify_attestation()` — the trait methods are dead code in the worker pipeline; only `seal`/`unseal` are called, and only for the policy file | NEW |
| T3 | **CRITICAL** | A,H | In dev / staging mode, `seal`/`unseal` are **identity functions** (`Ok(plaintext.to_vec())` / `Ok(sealed.to_vec())`) on all three vendors — sealed policy file is plaintext on disk and silently consumed as if sealed | NEW |
| T4 | **CRITICAL** | E,H | `is_real_enclave` is auto-detected from `Path::new("/dev/sgx_enclave").exists()` etc. The auto-detect is the **only gate** between the production-error path and the identity-passthrough path. There is no enforcement that `RuntimeMode::Production` requires `is_real_enclave == true` | NEW |
| T5 | **CRITICAL** | A,G | No KMS / NSM / vTPM-derived sealing key exists. `seal`/`unseal` either return `Err` or pass plaintext through; there is no AEAD, no key wrap, no MAC. A compromised host can read or replace the policy blob undetected | NEW |
| T6 | **CRITICAL** | F,K | Attestation is never bound to (a) the live policy commitment, (b) the agent pubkey, or (c) the intent — because `attest()` is never called by the worker. `compute_user_data()` and `compute_report_data()` exist on the providers but are unreachable from `process_intent` | NEW |
| T7 | **CRITICAL** | K | The TEE worker does not enforce **intent freshness**: `intent.timestamp` and `intent.expiry` are never compared against the current clock before proving. A signed intent valid for 100 years can be replayed to the worker indefinitely | NEW |
| T8 | **CRITICAL** | I | `daily_volume_tracker` keys on `Utc::now().format("%Y-%m-%d")` using **untrusted host wallclock**. A malicious host can advance `CLOCK_REALTIME` to roll the date and bypass `max_daily_volume_lamports` | NEW |
| T9 | **HIGH** | I | Same untrusted-clock issue applies to the **TimeWindow** rule (`policy.rs:120`): `Utc::now().hour()` is host-time. Host advancing the clock satisfies any time window | NEW |
| T10 | **HIGH** | F | The signing payload (`signing_payload`) elides `intent.signature` (correct) but **does not bind** the policy commitment, worker pubkey, or epoch. An intent signed for one worker's policy is valid against any worker running any policy | NEW |
| T11 | **HIGH** | I | `max_daily_volume_lamports` is **incremented even when the prover later fails** — the volume is committed inside `evaluate_intent` (`policy.rs:173`), then `persist_volume` is called *before* proving. A repeated proof failure or builder error consumes the budget without producing a usable bundle | NEW |
| T12 | **HIGH** | I,G | `load_volume()` silently swallows every error: missing file, unseal failure, malformed JSON all produce `daily_volume_tracker = empty`. After an attacker corrupts or deletes `policy.toml.volume.json.sealed`, the daily budget resets to zero on next start | NEW |
| T13 | **HIGH** | E | `create_provider()` (`vendors/mod.rs:28`) has no fallback `default` arm — that is correct — but `WorkerConfig::tee_vendor` deserialises from a string with `#[serde(rename_all = "lowercase")]`, and the env-var loader (`main.rs:386-393`) **defaults to `sgx`** when `GLYPH_TEE_VENDOR` is unset. A misconfigured host gets SGX adapter, which then runs the dev-mode identity-seal path because `/dev/sgx_enclave` doesn't exist | NEW |
| T14 | **HIGH** | A,B | The Nitro dev-mode "synthetic attestation document" is a printable byte string (`b"nitro-dev-attest:v1:" || bound_user_data || b":policy:" || policy_commitment`). A `verify_attestation` window-search for a 32-byte commitment gives **trivial false positives** if the commitment happens to appear anywhere in any payload, e.g. an attacker-controlled quote of length ≥ 32 with embedded bytes | NEW |
| T15 | **HIGH** | A,C | SGX `verify_attestation` dev path (`sgx.rs:149-153`) does the same window search — accepts any 32-byte sliding window match. There is no MRENCLAVE check, no signature check, no DCAP collateral check | NEW |
| T16 | **HIGH** | A,D | SEV `verify_attestation` dev path (`sev.rs:160-163`) — same vulnerability. No VCEK signature check, no measurement allowlist, no `guest_svn` floor | NEW |
| T17 | **HIGH** | F,K | `intent_to_payload` (`prover.rs:36`) hashes `intent.nonce` with SHA-256 to produce a 32-byte commitment, but **never verifies the nonce hasn't been seen before in the worker**. The on-chain `NonceAccount` enforces uniqueness, but a compromised worker can front-run the on-chain commit by re-proving the same intent into multiple bundles | NEW |
| T18 | **HIGH** | L | `handle_connection` accepts on plain TCP (`main.rs:136-167`). There is **no TLS, no client authentication, no IP allowlist**. Per the WS-3 blueprint comment, the worker should be reachable only from the SDK / signer; in practice the listen address can be any value the operator sets, and there are no checks that it is not `0.0.0.0` | NEW |
| T19 | **HIGH** | L | The worker listens on plain TCP and parses arbitrary JSON. No rate limit, no per-source throttle, no auth header — only the 1 MiB body cap from prior Finding #3. A single TCP connection per request × N parallel sockets can saturate the proving pipeline | NEW |
| T20 | **HIGH** | M | Per Tobin South §3 ("Attestation"), each privileged component should emit a small attestation. The TEE worker emits **no audit trail at all**: no signed log of accepted intents, no chained hash, no Merkle commitment. Metrics are counters only — non-cryptographic, non-tamper-evident | NEW |
| T21 | **HIGH** | A,G | The signing key (`signing_key`) is loaded from `worker-keypair.json` on disk (`main.rs:73`). There is **no sealing** of this file — it is plaintext on the host filesystem regardless of TEE vendor. The `unseal` call is only on `policy.toml.sealed`, not on the keypair | NEW |
| T22 | **MEDIUM** | I | `policy.rs:135` uses `saturating_add` on the daily-volume accumulator — silently caps at `u64::MAX` instead of erroring. With a large `max_daily_volume_lamports`, an integer-overflowing intent is rejected only because `proposed > rules.max_daily_volume_lamports`; for a policy with `max_daily_volume_lamports == u64::MAX`, saturation hides the overflow | NEW |
| T23 | **MEDIUM** | I | `volume_file = path.with_extension("volume.json.sealed")` (`policy.rs:80`) collides if two policies share a path stem (e.g. `default.toml` + `default.alt.toml.sealed`); `with_extension` only replaces the *last* extension component | NEW |
| T24 | **MEDIUM** | I | The `TimeWindow` rule does **not** validate `start_hour_utc` and `end_hour_utc` are in `0..=23`. Out-of-range values give silent always-false windows | NEW |
| T25 | **MEDIUM** | I | `evaluate_intent` returns `PolicyViolationError` with no rule discriminator. Operationally this means the metrics counter says "policy_rejected" but no field or log line says *which* rule rejected. Debugging a wedge requires re-running with extra instrumentation | NEW |
| T26 | **MEDIUM** | I | `Rule 6 (AllowedTokenMints)` only enforces if `intent.constraints.allowed_tokens` is `Some`. An intent that omits `allowed_tokens` skips the check entirely (`policy.rs:148`), even when the policy lists a non-empty allowlist | NEW |
| T27 | **MEDIUM** | F,J | `canonical_target_instruction_bytes` (`transaction_builder.rs:141-160`) writes account flags as `is_signer as u8` then `is_writable as u8`. The on-chain verifier must use the same byte order; the prior SECURITY_AUDIT Finding #1 fixed the field set, but there is no shared serializer crate — both sides reimplement, divergence risk is permanent until consolidated. Already partially called out in `AUDIT_ZK.md` | KNOWN-OVERLAP |
| T28 | **MEDIUM** | J | `canonical_target_instruction_bytes` does **not** length-prefix the data section. `program_id || metas || data` with variable-length `data` is unambiguous only because `metas` is fixed 34 bytes per entry, but there is no `num_accounts` count prefix — if the verifier reads accounts by parsing a length, it must agree byte-for-byte. A future addition of optional metadata would silently break | NEW |
| T29 | **MEDIUM** | E | Worker `RuntimeMode::Production` checks (`main.rs:34-58`) enforce ZK side (`risc0` feature, env-var, no `RISC0_DEV_MODE`) but do **not** enforce the TEE side: no check that `provider.attest("", &[0;32])` succeeds, no check that `is_real_enclave`, no check that `seal`/`unseal` round-trips through KMS. Production mode passes with sealed-policy = plaintext-policy | NEW |
| T30 | **MEDIUM** | H | `GLYPH_MODE` falls back to `Dev` for any value other than `production`/`prod`/`staging`. A typo in deployment YAML (`PRODUCTON`) silently downgrades to dev mode | NEW |
| T31 | **MEDIUM** | F | `intent_to_payload` hashes `intent.nonce` (a hex string) but does not validate it is a hex string — if the SDK ever emits a non-hex nonce, the on-chain `NonceAccount` PDA seed (which is also derived from the nonce string) might disagree depending on the canonical decode path | NEW (verify with verifier) |
| T32 | **MEDIUM** | M | `tracing::info!` calls log `listen_addr`, `mode`, peer addresses, and error strings into the structured log. There is no log redaction layer; if a future change ever logs `intent.nonce` or `agent_pubkey`, it leaks correlation data | INFO |
| T33 | **MEDIUM** | A,B,C,D | Vendor providers have no "real-enclave required" flag for production. Each provider's `new()` silently falls back to dev mode if the device file is missing. Operations should be `panic!` / `Err` at construction time when `RuntimeMode::Production` is selected | NEW |
| T34 | **MEDIUM** | I | `chrono::Utc::now()` is called three times inside `evaluate_intent` (hour, daily date, then implicitly via `persist_volume`'s caller). Three calls are not atomic — if the host clock jumps between calls, the rule decisions and the persisted state can disagree | NEW |
| T35 | **LOW** | E | `provider: Arc::from(create_provider(...))` (`main.rs:60`) panics if `create_provider` returns `Box::new(SgxProvider::new())` and `SgxProvider::new()` itself panics — none currently do, but there is no `?`-style error path for provider initialisation failure | INFO |
| T36 | **LOW** | I | `daily_volume_tracker: BTreeMap<String, u64>` is keyed on a date string — leaving an unbounded map across restarts. `load_volume` filters to today's key, but `evaluate_intent` never prunes; a long-running worker accumulates at most ~3650 entries / decade — fine, but unnecessary | INFO |
| T37 | **LOW** | M | `WorkerMetrics` has no counter for `attestation_*` or `seal_*` events because those code paths never fire. After fixing T2, add them | NEW |
| T38 | **LOW** | M | The `/metrics` HTTP server (`metrics.rs:129-177`) is a hand-rolled minimalist server, no `tokio` integration, single-thread blocking. A misbehaving scraper can stall it. Listens on `127.0.0.1:9091` by default — fine — but configurable to `0.0.0.0` via `GLYPH_METRICS_ADDR` | INFO |
| T39 | **LOW** | L | `metrics.rs:155`: `read_line` reads the request line but **does not consume** the rest of the headers. With pipelined requests this can leave header bytes in the buffer; harmless for one-shot scrapers but technically incorrect HTTP | NEW |
| T40 | **INFO** | A,B,C,D | Vendor providers are well-documented: each file lists the production flow, exact crate dependencies, ioctl / SDK references, and security trade-offs. The audit-debt is fully *visible* in source — that's a positive. The risk is that visibility is not the same as enforcement (T2, T4) | POSITIVE |

Total: **40 findings** — 8 CRITICAL, 13 HIGH, 13 MEDIUM, 5 LOW, 1 INFO/positive.

---

## A. Vendor stubs (Nitro / SGX / SEV)

### T1 — CRITICAL — All vendor `attest`/`verify_attestation`/`seal`/`unseal` production paths return `Err`

**File:line:**
- `tee-worker/src/vendors/nitro.rs:70-208` (all four methods)
- `tee-worker/src/vendors/sgx.rs:58-154` (all four methods)
- `tee-worker/src/vendors/sev.rs:62-165` (all four methods)

**Description:** Each vendor adapter has two arms: `if self.is_real_enclave` and `else`. The `is_real_enclave == true` arm in every case returns `Err(anyhow!("... not yet implemented"))` for `seal`, `unseal`, `attest`, and `verify_attestation`. Examples:

- `nitro.rs:84-87`: `Err(anyhow!("NitroProvider::seal — KMS sealing not yet implemented..."))`
- `nitro.rs:108-111`: `Err(anyhow!("NitroProvider::unseal — KMS unsealing not yet implemented..."))`
- `nitro.rs:137-140`: `Err(anyhow!("NitroProvider::attest — NSM attestation not yet implemented..."))`
- `nitro.rs:190-193`: `Err(anyhow!("NitroProvider::verify_attestation — full COSE verification not yet implemented..."))`

The `else` arm runs in dev mode — see T3 for what it does (identity passthrough).

**Impact:** A worker that boots inside a real Nitro Enclave / SGX enclave / SEV-SNP guest fails-closed on any attempt to seal the policy or perform attestation. Worker startup itself fails on `provider.unseal(&sealed_policy)` (`main.rs:65`) the moment a real device file is detected.

A worker that boots *outside* a real enclave silently runs in dev-mode passthrough.

There is therefore **no configuration that exercises real attestation today**; this is acknowledged in `docs/production-migration-blueprint.md` §4.3 ("Vendor providers in `tee-worker/src/vendors/` still contain TODO-level stubs"), but the present audit promotes it from "in progress" to **production blocker** because the worker presents itself in `types.rs:117-120` as supporting a "Production" mode that "TEE attestation must be real (vendor stubs rejected)" — a claim the code does not enforce.

**Fix:**

1. Implement each vendor's production path against the documented dependency:
   - **Nitro:** Add `aws-nitro-enclaves-nsm-api` for the `NSM_GetAttestationDocument` ioctl; `aws-sdk-kms` with PCR-bound IAM condition for `seal`/`unseal`; `coset` + `x509-parser` + the AWS Nitro Root CA bundle for `verify_attestation` (`docs/aws.amazon.com/enclaves/latest/user/verify-root.html`).
   - **SGX:** Use `sgx-dcap-ql` for ECDSA quote generation and `sgx-dcap-quoteverify` (Intel DCAP QVL) for verification; use `sgx_seal_data`/`sgx_unseal_data` from the Intel SGX SDK with policy `SGX_KEYPOLICY_MRENCLAVE`.
   - **SEV-SNP:** Use the [`sev`](https://crates.io/crates/sev) crate for `SNP_GET_REPORT`; use `p384` for ECDSA-P384 verification of VCEK; for sealing pick either vTPM-bound key wrap (libtpm2) or KMS-with-attestation-bound-auth.
2. For each provider add a `pub fn require_real(&self) -> Result<()>` that returns `Err` whenever `is_real_enclave` is `false`. Call it from `main.rs` immediately after `create_provider` when `runtime_mode == Production`.

---

### T14 — HIGH — Nitro dev-path `verify_attestation` is a 32-byte window search

**File:line:** `tee-worker/src/vendors/nitro.rs:194-207`

```rust
let commitment_found = evidence.quote
    .windows(32)
    .any(|w| w == expected_commitment);
```

**Impact:** Any `quote` byte-string that contains the 32-byte `expected_commitment` anywhere — including in the middle of attacker-controlled data — passes `verify_attestation` in dev mode. There is no signature, no CBOR decode, no certificate chain, no MRENCLAVE / measurement check, no timestamp drift bound.

A test harness that runs in dev mode therefore proves nothing about attestation: an attacker can synthesize a "quote" of any length that embeds the expected commitment. The dev-mode evidence is fundamentally unverifiable.

**Fix:** Restrict the dev-mode `verify_attestation` to the *exact* synthetic format produced by the dev-mode `attest`:

```rust
let prefix = b"nitro-dev-attest:v1:";
if !evidence.quote.starts_with(prefix) { return Ok(false); }
let suffix_marker = b":policy:";
let pos = evidence.quote.windows(suffix_marker.len()).position(|w| w == suffix_marker)
    .ok_or(...)?;
let policy = &evidence.quote[pos + suffix_marker.len()..];
Ok(policy == expected_commitment)
```

…and additionally **forbid** the dev path entirely under `RuntimeMode::Production` (covered by T1's fix).

### T15, T16 — HIGH — Same window-search bug in SGX and SEV

**File:line:** `tee-worker/src/vendors/sgx.rs:149-153`, `tee-worker/src/vendors/sev.rs:160-163`

Identical `evidence.quote.windows(32).any(|w| w == expected_commitment)` pattern. Same fix.

---

## B. Nitro NSM ioctl usage

### T1 (Nitro slice)

The ioctl is **never called**. `nitro.rs:118-160` wraps a comment block describing the production path; the `Err(...)` is the only behaviour. The dev path produces a synthetic 84-byte string.

There is no:
- `/dev/nsm` open
- COSE_Sign1 production
- AWS Nitro root cert anchoring
- KMS interaction
- PCR0/1/2 commitment
- timestamp / nonce binding

Per blueprint WS-3, this is the WS-3 deliverable B (2026-04-28 → 2026-05-03) and was not landed.

---

## C. SGX DCAP

### T1 (SGX slice)

DCAP is **never called**. `sgx.rs:91-122` returns `Err` on the real path; dev path produces `b"sgx-dev-attest:v1:" || report_data || b":policy:" || policy_commitment`.

There is no:
- `sgx_create_report` or `EREPORT`
- `sgx_get_quote` (ECDSA / EPID)
- PCS / PCCS collateral fetch
- `sgx_qv_verify_quote`
- TCB level enforcement
- MRENCLAVE allowlist
- supplemental_data freshness

There is **no DCAP linkage at all**; the `cargo` dependency tree (visible from the imports in `sgx.rs:21-26`) imports only `anyhow`, `chrono`, `sha2`, `crate::types::TeeVendor`, `super::{AttestationEvidence, TeeProvider}`. No `sgx-dcap-*` crate is wired.

---

## D. SEV-SNP

### T1 (SEV slice)

`SNP_GET_REPORT` is **never called**. `sev.rs:98-130` returns `Err` on the real path; dev path produces `b"sev-snp-dev-attest:v1:" || report_data || b":policy:" || policy_commitment`.

There is no:
- `/dev/sev-guest` ioctl
- 512-byte attestation report parse
- VCEK certificate fetch from AMD KDS
- ECDSA-P384 signature verification
- measurement allowlist
- guest_svn floor
- vTPM-based or KMS-based sealing

`sev` and `p384` crates are **not** wired into the dependency tree.

---

## E. TeeProvider trait dispatch — is the `default` provider safe?

### T2 — CRITICAL — Attestation methods are dead code in the worker pipeline

**File:line:** `tee-worker/src/main.rs` (entire file). `attest` and `verify_attestation` have **zero callers** in `main.rs` or elsewhere in the worker.

**Description:** A `grep` of the worker source for `provider.attest(`, `.attest(`, `verify_attestation(` outside of vendor files returns no hits. The provider arc is constructed (`main.rs:60`), passed to `PolicyEngine::load_from_path` for `seal`/`unseal` of the policy (`main.rs:70`), and stored in `AppState.provider` for later `seal` of the volume tracker (`main.rs:258`). It is **never** asked to attest, and is **never** asked to verify an attestation.

**Impact:** Even with fully-implemented vendors (T1 fix), the worker as written would still not produce or check attestations. The trait surface and the runtime are decoupled. The on-chain `register_agent` and `update_policy` (per `docs/SECURITY_AUDIT.md` Finding #2) verify attestation evidence — but the worker never produces that evidence in the first place; whatever the SDK passes to `register_agent` is not generated by the worker pipeline.

**Fix:**

1. After `policy_engine` is loaded, immediately call `provider.attest(b"GLYPH_WORKER_BOOT_v1", &policy_commitment)` and store the resulting `AttestationEvidence` in `AppState`. Refuse to start in `Production` mode if `attest` returns `Err`.
2. On every accepted intent, the worker should attach the boot-time `AttestationEvidence` to the proof bundle (or to a separate `WorkerCertificate` envelope) so the SDK / on-chain verifier can re-verify with the live policy commitment.
3. Periodically (e.g. every 5 minutes) re-run `attest` and rotate the evidence; refuse new intents if the latest attestation is stale.
4. Add a worker-side `verify_attestation(evidence, &expected_commitment)` self-check after every `attest` call to detect provider regressions (defence-in-depth).

### T13 — HIGH — `GLYPH_TEE_VENDOR` defaults to SGX with no enforcement

**File:line:** `tee-worker/src/main.rs:384-393`

```rust
let tee_vendor = match env::var("GLYPH_TEE_VENDOR")
    .unwrap_or_else(|_| "sgx".to_string())
    ...
```

If `GLYPH_TEE_VENDOR` is unset, the worker selects SGX. `SgxProvider::new()` then auto-detects `/dev/sgx_enclave`. On a generic Linux host (or any environment without that device), the provider runs in dev mode and `seal`/`unseal` are identity functions.

**Fix:** In `Production` mode, require `GLYPH_TEE_VENDOR` to be explicitly set; refuse to default. Refuse to construct a provider whose `is_real_enclave == false` when in `Production`.

### T29 — MEDIUM — Production-mode check covers only ZK, not TEE

**File:line:** `tee-worker/src/main.rs:33-58`

The production-mode block enforces:
- compiled `with --features risc0`
- `GLYPH_PROVER == "risc0"`
- `RISC0_DEV_MODE` not set

It does **not** enforce:
- `provider.is_real_enclave == true`
- `provider.attest("", &[0;32])` returns Ok
- A KMS / NSM ping succeeded
- `GLYPH_TEE_VENDOR` is explicitly set
- Worker keypair is sealed

**Fix:** Add to the production-mode block:

```rust
if !provider.is_real_enclave_check()? {
    panic!("FATAL: Production mode requires a real TEE enclave; got {:?}", config.tee_vendor);
}
let _evidence = provider.attest(b"GLYPH_BOOT_v1", &[0u8; 32])
    .expect("FATAL: attest() must succeed in Production mode");
```

---

## F. Attestation commitment — what is bound?

### T6 — CRITICAL — Attestation is bound to nothing live

**File:line:** `tee-worker/src/vendors/nitro.rs:54-60`, `sgx.rs:42-48`, `sev.rs:46-52`

`compute_user_data` / `compute_report_data` exist:

```rust
fn compute_report_data(user_data: &[u8], policy_commitment: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"GLYPH:sgx:report_data:v1:");
    hasher.update(policy_commitment);
    hasher.update(user_data);
    hasher.finalize().into()
}
```

The hash is correctly domain-separated (`GLYPH:<vendor>:user_data:v1:`) and binds `policy_commitment || user_data`, but:

1. The function is private to each vendor and only called by `attest()`.
2. `attest()` is **never called** by the worker (T2).
3. No callsite in the worker passes an `agent_pubkey` or `intent_hash` — the `user_data` argument is a freeform byte slice and the only callers of `attest` are tests in `tee-worker/tests/policy_tests.rs`, which doesn't actually call them either.

**Impact:** There is no part of the worker pipeline today where the attestation evidence binds the policy, the agent pubkey, *and* the intent. The thesis (PAPER_BRIEF §3) requires all three for "auditable delegation".

**Fix:** Implement `compute_user_data` to bind `(policy_commitment, agent_pubkey, worker_pubkey, boot_nonce, epoch)`:

```rust
fn compute_user_data(
    policy_commitment: &[u8;32],
    agent_pubkey: &[u8;32],
    worker_pubkey: &[u8;32],
    boot_nonce: &[u8;32],
    epoch: u64,
) -> [u8;32] { ... }
```

Call from `main.rs::main` after key + policy load. Re-call when policy is rotated or epoch changes.

---

## G. Sealing key story

### T5 — CRITICAL — No sealing key exists

**File:line:** `tee-worker/src/vendors/{nitro,sgx,sev}.rs` (`seal`/`unseal`)

The dev path (`is_real_enclave == false`) is a verbatim identity passthrough on all three vendors:

- `nitro.rs:91-93`: `Ok(plaintext.to_vec())`
- `sgx.rs:73-75`: `Ok(plaintext.to_vec())`
- `sev.rs:81-83`: `Ok(plaintext.to_vec())`

The production path returns `Err`.

There is **no compile-time constant**, no env-derived key, no PBKDF2 from a passphrase — there is *no* key at all. The worker happily writes `policy.toml.sealed` as plaintext to disk and reads it back. `policy.rs:80-83` writes the volume tracker the same way.

**Impact:**
1. Anyone with read access to the worker's filesystem can read the policy and the daily volume state.
2. Anyone with write access can swap the policy for a permissive one, or set the daily volume to zero. The worker has no MAC to detect tampering.
3. The on-chain `policy_commitment` would still be correct (because it is supplied separately by the SDK at registration), but the *enforcement* path on the worker is the unsealed file — a mismatch goes undetected because nothing compares the file hash against the on-chain commitment after load.

**Fix:**

1. Implement real `seal`/`unseal` per T1 (Nitro KMS, SGX EGETKEY, SEV vTPM/KMS).
2. As a stop-gap for dev mode, derive a key with `argon2id` from a high-entropy `GLYPH_SEAL_PASSPHRASE` env-var and AEAD-encrypt with `chacha20poly1305`. Fail if the passphrase is shorter than 32 bytes or the env-var is unset.
3. Compare `hash(unsealed_policy)` against the on-chain `policy_commitment` after every `unseal` call. Refuse to start if mismatched.

### T21 — HIGH — Worker keypair is plaintext on disk

**File:line:** `tee-worker/src/main.rs:73`

```rust
let keypair_bytes = std::fs::read(&config.keypair_path)
    .with_context(|| format!("failed to load keypair from {}", config.keypair_path))?;
```

No `provider.unseal` call wraps this read. The Ed25519 signing key is plaintext on disk. A host filesystem compromise lifts the worker's signing key directly.

**Fix:** Either (a) seal the keypair file with the same provider; or (b) generate the keypair fresh inside the enclave on first boot, seal it via TEE-bound key, and never persist plaintext. Option (b) is preferred because it removes an out-of-band trust assumption.

---

## H. Mock-mode escape hatches

### T3 — CRITICAL — Identity seal in dev mode (per-vendor)

Already covered in T5. The escape is `is_real_enclave == false`; the trigger is the absence of `/dev/sgx_enclave`, `/dev/nsm`, or `/dev/sev-guest`. There is no env-var, no feature flag — just device-file presence.

**Risk pattern:** If an operator runs the production binary on a host without the device file (e.g. mid-migration, or a dev container mistakenly tagged `production`), the production-mode check at `main.rs:34-58` *passes* because it does not look at `is_real_enclave`. The worker accepts intents and persists state in plaintext while reporting itself as "production". This is the most dangerous failure mode in this audit.

### T30 — MEDIUM — Typo'd `GLYPH_MODE` silently downgrades to dev

**File:line:** `tee-worker/src/main.rs:395-403`

```rust
let runtime_mode = match env::var("GLYPH_MODE")
    .unwrap_or_else(|_| "dev".to_string())
    .to_lowercase()
    .as_str()
{
    "production" | "prod" => RuntimeMode::Production,
    "staging" => RuntimeMode::Staging,
    _ => RuntimeMode::Dev,
};
```

A typo (`PRODUCTON`, `prod1`, `prooduction`) maps to `Dev`. The default when the env-var is **absent** is also `Dev`.

**Fix:** Treat unknown values as a hard error (`return Err(anyhow!("invalid GLYPH_MODE: {other}"))`) and require the var to be set explicitly when boot-args contain any `production`-correlated flag (e.g. `--release` build).

---

## I. Policy evaluator (`policy.rs`)

### Rule coverage

All eight rules are *implemented*:

| # | Rule | File:line | Notes |
| --- | --- | --- | --- |
| 1 | MaxLamportsPerTx | `policy.rs:104-107` | OK |
| 2 | AllowedPrograms | `policy.rs:109-116` | OK |
| 3 | TimeWindow | `policy.rs:118-129` | **Untrusted host clock** (T9) |
| 4 | MaxDailyVolumeLamports | `policy.rs:131-137` | **Untrusted clock + budget consumed before proof** (T8, T11) |
| 5 | RequireSlippageBpsLte | `policy.rs:139-145` | OK |
| 6 | AllowedTokenMints | `policy.rs:147-158` | **Skipped if intent.allowed_tokens is None** (T26) |
| 7 | MaxAccountsPerTx | `policy.rs:160-165` | OK |
| 8 | RequireSignerPresent | `policy.rs:167-170` | OK |

### T7 — CRITICAL — Intent freshness is never checked

**File:line:** `tee-worker/src/main.rs:242-297` (process_intent), `tee-worker/src/policy.rs:98-176` (evaluate_intent)

Neither `validate_intent_signature` nor `evaluate_intent` compares `intent.expiry` or `intent.timestamp` against the current clock. The signature payload (`signing_payload`) includes `timestamp` and `expiry`, so the SDK's signature is bound to those values, but the worker never enforces them.

**Impact:** A signed intent with `expiry = u64::MAX` is valid forever. Even an intent with a normal short expiry is accepted long after expiry — only the on-chain verifier (per `AUDIT_ZK.md` finding #18) might catch it, and that audit notes the on-chain verifier *also* doesn't check expiry against `Clock`.

**Fix:** In `process_intent`, before calling the policy engine, add:

```rust
let now = chrono::Utc::now().timestamp() as u64; // Or, ideally, a TEE-trusted clock.
if intent.expiry > 0 && now > intent.expiry {
    state.metrics.record_policy_rejection();
    anyhow::bail!("intent expired");
}
if intent.timestamp > now + 300 {
    anyhow::bail!("intent timestamp is more than 5 minutes in the future");
}
```

The "TEE-trusted clock" caveat is important: a fully trustworthy clock requires a signed time service (e.g. Roughtime, AWS Time Sync attested via Nitro), because the host clock is tampered. Track as a follow-up.

### T8 — CRITICAL — Daily volume bypassable via host clock

**File:line:** `tee-worker/src/policy.rs:132`

```rust
let date_key = Utc::now().format("%Y-%m-%d").to_string();
```

`Utc::now()` is `CLOCK_REALTIME` from the host kernel — not authenticated by the TEE. A host with `CAP_SYS_TIME` (or one that ships a malicious `gettimeofday` shim) can advance the clock to flip the date and reset the daily budget.

**Fix (short-term):** Persist the *last seen date* alongside the volume; refuse to start a new day until at least 23 h have elapsed in `CLOCK_MONOTONIC` since the last seen day rolled over. `CLOCK_MONOTONIC` is also host-controlled but is harder to skew arbitrarily because `clock_settime(CLOCK_MONOTONIC, ...)` returns EINVAL.

**Fix (long-term):** Bind to a TEE-attested time service. Each policy evaluation should consume a fresh signed timestamp from a Roughtime / NTS server whose signature key is committed in `policy.toml`.

### T9 — HIGH — TimeWindow rule uses host clock

Same root cause as T8. Same fix.

### T11 — HIGH — Volume committed before proof success

**File:line:** `tee-worker/src/policy.rs:170-176` (commit happens at the end of `evaluate_intent`), then `main.rs:251-259` (engine releases lock and the persistence call), then `main.rs:271-284` (proof generation)

`evaluate_intent` ends with `self.daily_volume_tracker.insert(date_key, proposed)`. After that, `main.rs:258` persists the volume. *Then* the prover is invoked. If the prover fails — for any reason — the budget has already been consumed.

**Impact:** A misconfigured Bonsai endpoint or a transient ELF-parse error can drain the daily budget without ever producing a usable bundle. Not catastrophic, but a denial-of-service surface that the operator may not detect because the metric `intents_policy_rejected` doesn't go up — only `proofs_failed` does.

**Fix:** Refactor `evaluate_intent` into two phases: `check_intent` (read-only) and `commit_intent` (mutating). Call `check_intent` before proving; only call `commit_intent` after `prover.generate_proof` returns `Ok`.

### T12 — HIGH — `load_volume` swallows all errors silently

**File:line:** `tee-worker/src/policy.rs:179-191`

```rust
fn load_volume(&mut self, path: &Path, provider: &dyn TeeProvider) {
    if let Ok(sealed_data) = std::fs::read(path) {
        if let Ok(unsealed) = provider.unseal(&sealed_data) {
            if let Ok(tracker) = serde_json::from_slice::<BTreeMap<String, u64>>(&unsealed) {
                ...
            }
        }
    }
}
```

Three nested `if let Ok` — every error path silently produces an empty tracker. Missing file is benign; **unseal failure** is not — that means the file exists but couldn't be decrypted (or, with the current dev-mode passthrough, that the JSON is corrupted). Silent-empty leaks budget.

**Fix:** Distinguish three states:
- file does not exist → start with empty tracker (first run);
- file exists but unseal fails → **panic** (tampered state, refuse to proceed);
- file exists and unseals but JSON parse fails → **panic** (corrupted state).

### T22 — MEDIUM — `saturating_add` on volume

**File:line:** `tee-worker/src/policy.rs:134`

```rust
let proposed = current.saturating_add(intent.constraints.max_lamports);
```

For policies with `max_daily_volume_lamports == u64::MAX`, the saturating semantics hide the overflow. Acceptable for the realistic case (tx values are nowhere near u64::MAX), but the safer pattern is `checked_add` and explicit reject on overflow.

### T26 — MEDIUM — Token mint rule skipped when intent omits tokens

**File:line:** `tee-worker/src/policy.rs:148-157`

```rust
if let Some(allowed) = &rules.allowed_token_mints {
    if let Some(requested_tokens) = &intent.constraints.allowed_tokens {
        ...
    }
}
```

If `policy.allowed_token_mints == Some([..])` but `intent.constraints.allowed_tokens == None`, the rule is silently skipped. An attacker who omits the field bypasses the allowlist entirely.

**Fix:**

```rust
if let Some(allowed) = &rules.allowed_token_mints {
    let Some(requested_tokens) = &intent.constraints.allowed_tokens else {
        return Err(PolicyViolationError);
    };
    ...
}
```

### T24, T25, T34, T36 — MEDIUM/LOW — see summary table

---

## J. Transaction builder

### T27 — MEDIUM (KNOWN-OVERLAP) — No shared canonical serializer

The fix to SECURITY_AUDIT Finding #1 introduced `canonical_target_instruction_bytes` in `transaction_builder.rs:141-160`. The on-chain verifier **must** use byte-identical serialization. Today both sides reimplement.

**Fix:** Move `canonical_target_instruction_bytes` to a shared crate (`glyph-common` already exists — `tee-worker/src/policy.rs:11-13` imports `canonical_serialize_policy`, `hash_policy`, `Policy`, `TimeWindow` from it). Add `canonical_target_instruction_bytes` to `glyph-common` and have both worker and verifier call the same function.

### T28 — MEDIUM — No length-prefix on `data`

**File:line:** `tee-worker/src/transaction_builder.rs:141-160`

```rust
full_ix_bytes.extend_from_slice(target_program.as_ref());
for meta in &intent.action.accounts {
    full_ix_bytes.extend_from_slice(pk.as_ref());
    full_ix_bytes.push(meta.is_signer as u8);
    full_ix_bytes.push(meta.is_writable as u8);
}
full_ix_bytes.extend_from_slice(&target_data);
```

There is no `num_accounts: u16` count and no `data_len: u32` prefix. The format is **only unambiguous** because `target_program` is fixed 32 bytes and each account meta is fixed 34 bytes. If a future field is added (e.g. an account `is_invoked` flag, an extension byte), the parser cannot recover boundaries without breaking compatibility.

**Fix:** Adopt a fixed framing — `borsh::serialize` over a struct with explicit `num_accounts: u16` and `data: Vec<u8>` (which borsh prefixes with a `u32` length). This also makes the verifier-side parser straight `borsh::deserialize`.

---

## K. Replay / freshness

### T7 — see above (intent expiry)

### T17 — HIGH — Worker does not track nonce uniqueness

**File:line:** `tee-worker/src/main.rs:242-297` (process_intent)

The worker happily produces multiple proof bundles for the same `(agent_pubkey, nonce)` pair. The only deduplication is on-chain via `NonceAccount`. A compromised worker (or a worker fronted by a malicious load-balancer) can produce N bundles for the same intent and submit them to N different RPC endpoints; only one will land but the redundant bundles are signed-up artifacts that can confuse downstream auditing.

**Fix:** Maintain an in-TEE LRU of recently-seen `(agent_pubkey, nonce)` and reject duplicates with a 1024-entry cap (or a sealed bloom filter). Persist via the same volume-tracker mechanism.

### Epoch / freshness

The worker neither reads nor writes a `policy_epoch`. The on-chain side enforces epoch freshness (per AUDIT_ZK Finding #20-21), but the worker has no way to know that its locally-loaded policy is the current epoch. A stale worker can prove against a stale policy that's already been rotated on-chain.

**Fix:** During boot, the worker should read the on-chain `AgentRegistry::policy_commitment` for its agent pubkey and refuse to start if it doesn't match `hash_policy(canonical_policy)`. This bridges the worker's local policy to the on-chain state.

---

## L. Network exposure

### T18, T19 — HIGH — Plain-TCP, unauth, no TLS, no rate limit

**File:line:** `tee-worker/src/main.rs:136-167`, `tee-worker/src/main.rs:181-241`

`TcpListener::bind(&config.listen_addr)` accepts everything that connects. `read_to_end` is bounded to 1 MiB (the WS-3 / Finding #3 fix), so OOM is mitigated. But:

- **No TLS** — the SDK's intent (which contains a 32-byte agent pubkey, a nonce, and a base64 instruction payload) traverses cleartext if `listen_addr` ever points to a non-localhost IP. Per the WS-3 design intent, the worker is meant to be local-only, but `listen_addr` is operator-configurable and trivially set to `0.0.0.0`.
- **No per-IP rate limit** — unbounded parallel TCP connections, each up to 1 MiB. With CPU-bound proof generation taking 5–120 s (per `prover.rs:69-72`), a few dozen connections can saturate the proving thread pool.
- **No client authentication** — anyone who reaches the listening socket can submit an intent. The intent's Ed25519 signature establishes that the *intent* came from the agent, but does not establish that the *connection* came from a legitimate signer.

**Fix:**

1. Front the worker with mTLS (rustls + a hardcoded client CA). Reject any connection without a valid client cert.
2. Add a per-source-IP token bucket: e.g. 10 intents / minute / IP.
3. Enforce `listen_addr.starts_with("127.")` or `listen_addr == "[::1]:..."` in `Production` mode.
4. Move from raw TCP+JSON to a documented framing (length-prefixed) so partial reads are not a DoS surface.

### T39 — LOW — Metrics server doesn't drain headers

**File:line:** `tee-worker/src/metrics.rs:152-156`

`reader.read_line(&mut request_line)` reads only the request line. Headers stay in the buffer. Harmless for one-shot scrapers; technically wrong HTTP. Replace with a proper HTTP server (e.g. `hyper` on a separate runtime) when wiring T20.

---

## M. Audit log emission

### T20 — HIGH — No tamper-evident audit trail

Tobin South §3 ("Auditable delegation trail") requires each privileged component to emit a small attestation. The TEE worker emits:

- `tracing` log lines (mutable host log; not signed, not chained, not exported).
- `WorkerMetrics` counters (`metrics.rs:39-79`) — non-cryptographic.

There is no:

- per-intent signed audit record;
- chained hash log (Trillian-style log root);
- Merkle-tree export to an off-chain log;
- on-chain emission of a small commitment per accepted intent.

**Fix:**

1. Add an append-only, sealed audit log file (`audit.log.sealed`) that the worker writes to before responding to the SDK. Each entry: `(timestamp, agent_pubkey, intent_hash, policy_commitment, prev_entry_hash)`. Sign the entry with the worker's TEE key.
2. Periodically commit the log root on-chain (via a separate instruction) so the tail is anchored.
3. Expose a read-only `/audit` HTTP endpoint that streams entries with their signatures.

### T37 — LOW — No metrics for attestation / sealing

Add `glyph_attestations_total{result}`, `glyph_seal_ops_total{result}`, `glyph_unseal_ops_total{result}` counters once the providers are wired (T1).

---

## Cross-reference to docs/SECURITY_AUDIT.md

| Prior finding | Status in current code | Notes |
| --- | --- | --- |
| **#1 — Intent Hijacking via Incomplete Tx Hash** | PATCHED ✓ | `canonical_target_instruction_bytes` covers `program_id || metas || data`. T27 raises the residual *consolidation* gap (no shared crate); T28 raises the *length-prefix* gap (still ambiguous on data boundary if struct evolves). |
| **#2 — Attestation Bypass in Policy Updates** | PATCHED on-chain only | The on-chain `update_policy` now calls `verify_attestation_commitment`. The TEE worker side that *produces* the attestation evidence to feed that on-chain check **does not exist** (T2). The on-chain check therefore relies on whatever the SDK presents — and the SDK cannot get a real attestation from this worker. |
| **#3 — DoS via Unbounded TCP Streams** | PATCHED ✓ | `take(max_size + 1)` is in place at `main.rs:184-186`; `WorkerMetrics::record_too_large` is wired. Residual gaps are T18/T19 (TLS, mTLS, rate limit) and T39 (metrics HTTP layer). |

The audit recommendation in §"Recommendations for Future Work" — *"A robust, on-chain SPV or dedicated light client for TEE attestation verification (e.g., Intel TDX or AWS Nitro Enclaves) must be implemented before mainnet deployment"* — is the **on-chain twin** of T1. Both sides need to land.

---

## Recommended remediation order

The following ordering minimises rework — each step builds the substrate the next step depends on.

| Step | Fix | Findings closed |
| --- | --- | --- |
| 1 | Move `canonical_target_instruction_bytes` to `glyph-common`; verifier and worker share | T27, T28 (partial) |
| 2 | Implement intent freshness check (`expiry`, `timestamp`) and worker-side nonce LRU | T7, T17 |
| 3 | Implement `is_real_enclave` enforcement gate in `Production` mode | T4, T13, T29, T33 |
| 4 | Implement Nitro production path (NSM + KMS) end-to-end with COSE verify | T1 (Nitro slice), T5 (Nitro slice), T14 |
| 5 | Wire `provider.attest()` into worker boot; attach evidence to bundle | T2, T6, T20 |
| 6 | Implement SGX DCAP path | T1 (SGX), T15 |
| 7 | Implement SEV-SNP path | T1 (SEV), T16 |
| 8 | Bind worker keypair under sealing | T21 |
| 9 | Refactor `evaluate_intent` into check + commit | T11 |
| 10 | TEE-attested clock (Roughtime) | T8, T9, T34 |
| 11 | mTLS + rate limit | T18, T19 |
| 12 | Sealed append-only audit log + on-chain root commit | T20, T37 |
| 13 | Strengthen `GLYPH_MODE`, `GLYPH_TEE_VENDOR` parsing; reject typos | T13, T30 |
| 14 | Tighten policy rule edge cases (token-mint default, bound checks, error discriminator) | T22, T24, T25, T26, T36 |

---

## Conclusion

The TEE worker is **structurally sound** — the trait surface (`TeeProvider::{seal, unseal, attest, verify_attestation}`) is correctly shaped; the policy evaluator covers all eight rules; the transaction builder produces a canonical hash that matches the on-chain verifier (per Finding #1's patch); the runtime-mode guard for the prover side is enforced.

It is **not production-ready** because the *vendor adapters* are intentional placeholders (acknowledged in WS-3 of the migration blueprint) and — more critically — because:

1. The worker's own pipeline does not call `attest`/`verify_attestation` even where they exist (T2);
2. The dev path is reachable in `Production` mode whenever the device file is missing (T4);
3. Sealing is plaintext passthrough in dev mode (T3) and absent in production mode (T1);
4. Intent freshness, daily-volume budget, and time-window rules all rely on the **untrusted host clock** (T7, T8, T9);
5. There is **no audit trail** — a hard requirement of the thesis architecture (T20).

These five findings together mean a deployment that successfully passes today's `Production` mode checks can still: (a) accept replayed intents indefinitely; (b) bypass the daily-volume cap by skewing the host clock; (c) load a tampered policy file undetected; (d) operate without producing any verifiable evidence that it ran inside a real TEE.

Recommended path forward: execute the 14-step remediation order above. Steps 1-5 (canonical serializer + freshness + `is_real_enclave` gate + Nitro end-to-end + attestation wiring) are the smallest set that closes all CRITICAL findings; SGX and SEV can follow on a slower track if Nitro is the production target. T20 (audit log) is the only HIGH that is invisible to the on-chain side and so is easy to forget — schedule it explicitly.
